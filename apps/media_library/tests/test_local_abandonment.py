from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch, Mock
import hashlib
import json

from django.test import SimpleTestCase
from apps.media_library import storage_archive as archive
from apps.media_library.services import ProtectedAssetError


class LocalAbandonmentTests(SimpleTestCase):
    def setUp(self):
        self.data = {"original.mp4": b"exact original", "thumb.jpg": b"exact thumbnail"}
        self.client = Mock()
        self.client.meta.service_model.operation_model.return_value.input_shape.members = {"IfMatch": None}
        self.client.list_multipart_uploads.return_value = {}
        self.client.get_bucket_versioning.return_value = {}
        self.client.generate_presigned_url.side_effect = lambda *a, **k: "http://storage.test/" + k["Params"]["Key"]
        self.storage = SimpleNamespace(bucket_name="media", connection=SimpleNamespace(meta=SimpleNamespace(client=self.client)), open=lambda key, mode: BytesIO(self.data[key]), _normalize_name=lambda key: key)
        self.asset = SimpleNamespace(pk=next(iter(archive.DREAD_ABANDONMENT_IDS)), workspace_id=archive.DREAD_ABANDONMENT_WORKSPACE, file=SimpleNamespace(name="original.mp4", storage=self.storage), thumbnail=SimpleNamespace(name="thumb.jpg", storage=self.storage), processed_variants={})
        self.auth = {"operation_id": "dread-local-abandonment-20261023", "mode": "LOCAL_ABANDONMENT", "workspace_id": archive.DREAD_ABANDONMENT_WORKSPACE, "asset_ids": list(archive.DREAD_ABANDONMENT_IDS), "archive_prerequisite_waived": True, "drive_effects": False, "expires_at": (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(), "assets": {str(self.asset.pk): {"keys": list(self.data)}}, "consumer_probe": {"checked_at": datetime.now(timezone.utc).isoformat(), "open_refs": [], "inaccessible_processes": 0, "keys_sha256": hashlib.sha256(json.dumps(sorted(self.data)).encode()).hexdigest()}}
        self.auth["assets"][str(self.asset.pk)]["objects"] = {key: {"etag": '"generation1"', "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "storage_key": key} for key, data in self.data.items()}
        self.saved = []
        self.deleted = []
        self.timeout_after_delete = False

    @contextmanager
    def guard(self, *args):
        yield self.asset

    @contextmanager
    def seal(self, *args):
        yield "private-owner"

    def head(self, storage, key):
        return {"Bucket": "media", "Key": key}, ({"etag": '"generation1"', "size": len(self.data[key])} if key in self.data else None)

    def persist(self, asset, record):
        self.saved.append(deepcopy(record))
        asset.processed_variants["_local_abandonment"] = deepcopy(record)

    def delete(self, request, **kwargs):
        key = request.full_url.rsplit("/", 1)[1]
        self.assertEqual(self.saved[-1]["keys"][key]["state"], "UNKNOWN")
        self.assertEqual(request.get_header("If-match"), '"generation1"')
        self.deleted.append(key)
        self.data.pop(key)
        if self.timeout_after_delete:
            raise TimeoutError("outcome unknown")
        return self.guard()

    def run_operation(self, execute=False):
        with patch.object(archive, "connection", SimpleNamespace(in_atomic_block=False, vendor="sqlite")), patch.object(archive, "_asset", return_value=self.asset), patch.object(archive, "_locked", self.guard), patch.object(archive, "_dependency_commit", self.guard), patch.object(archive, "_abandonment_allowed", side_effect=lambda a, b: archive._abandonment_authorization(a, b)), patch.object(archive, "_abandonment_head", side_effect=self.head), patch.object(archive, "_persist_abandonment", side_effect=self.persist), patch.object(archive, "_write_admission", self.seal), patch.object(archive, "urlopen", side_effect=self.delete), patch.object(archive, "RcloneRemote", side_effect=AssertionError("Drive forbidden")):
            return archive.abandon_dread_local_asset(self.asset.pk, self.auth, execute=execute)

    def test_scope_and_consumer_probe_fail_closed(self):
        for change in [{"workspace_id": archive.WORKSPACE_ID}, {"asset_ids": []}, {"drive_effects": True}, {"consumer_probe": {}}]:
            auth = dict(self.auth, **change)
            with self.assertRaises((ProtectedAssetError, KeyError)):
                archive._abandonment_authorization(self.asset, auth)
        self.asset.workspace_id = archive.WORKSPACE_ID
        with self.assertRaises(ProtectedAssetError):
            archive._abandonment_authorization(self.asset, self.auth)

    def test_dry_run_hashes_but_never_deletes_or_persists(self):
        result = self.run_operation()
        self.assertEqual(len(result["keys"]), 2)
        self.assertEqual(self.deleted, [])
        self.assertEqual(self.saved, [])
        self.assertEqual(len(self.data), 2)

    def test_retirement_and_repeat_keep_tombstone_without_duplicate_delete(self):
        result = self.run_operation(execute=True)
        self.assertEqual(result["state"], "ABANDONED")
        self.assertEqual(set(self.deleted), {"original.mp4", "thumb.jpg"})
        self.assertEqual(self.run_operation(execute=True)["state"], "ABANDONED")
        self.assertEqual(len(self.deleted), 2)

    def test_unknown_effect_reconciles_absence_without_retry(self):
        self.timeout_after_delete = True
        with self.assertRaises(TimeoutError):
            self.run_operation(execute=True)
        self.assertEqual(self.saved[-1]["state"], "UNKNOWN")
        self.timeout_after_delete = False
        self.assertEqual(self.run_operation(execute=True)["state"], "ABANDONED")
        self.assertEqual(len(self.deleted), 2)

    def test_missing_initial_object_never_becomes_authorized_absence(self):
        self.data.pop("original.mp4")
        with self.assertRaises(archive.ArchiveUnknown):
            self.run_operation(execute=True)
        self.assertEqual(self.deleted, [])

    def test_changed_generation_preserves_unknown_and_does_not_delete(self):
        calls = 0
        original = self.head
        def changed(storage, key):
            nonlocal calls
            calls += 1
            args, head = original(storage, key)
            if calls == 3:
                head["etag"] = '"generation2"'
            return args, head
        with patch.object(self, "head", side_effect=changed):
            with self.assertRaises(archive.ArchiveUnknown):
                self.run_operation(execute=True)
        self.assertEqual(self.deleted, [])
        self.assertEqual(self.saved[-1]["state"], "UNKNOWN")

    def test_unsupported_conditional_backend_fails_closed(self):
        self.client.meta.service_model.operation_model.return_value.input_shape.members = {}
        with self.assertRaises(archive.ArchiveUnknown):
            self.run_operation(execute=True)
        self.assertEqual(self.deleted, [])

    def test_native_delete_cannot_remove_tombstoned_history(self):
        from apps.media_library.services import delete_asset
        self.asset.processed_variants["_local_abandonment"] = {"state": "ABANDONED"}
        with self.assertRaises(ProtectedAssetError):
            delete_asset(self.asset)

    def test_versioned_backend_fails_before_deletion(self):
        self.client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        with self.assertRaises(archive.ArchiveUnknown):
            self.run_operation(execute=True)
        self.assertEqual(self.deleted, [])
