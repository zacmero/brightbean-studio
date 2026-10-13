import hashlib
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.media_library.models import MediaAsset
from apps.media_library.storage_archive import ArchiveUnknown, WORKSPACE_ID, archive_asset, hydrate_asset, retire_asset
from apps.media_library.services import ProtectedAssetError, delete_asset
from apps.organizations.models import Organization
from apps.workspaces.models import Workspace
from apps.composer.models import Post, PostMedia, PlatformPost
from apps.social_accounts.models import SocialAccount


class Remote:
    binding = {"remote": "prod-attack:", "root_folder_id": "1W8QzKWScz2s6cCOLTl3hdexiaSwPjyMC"}

    def __init__(self, directory):
        self.path = Path(directory) / "remote-original"
        self.uploads = 0
        self.ambiguous = False

    def stat(self, key):
        return {"id": "verified-drive-id", "size": self.path.stat().st_size} if self.path.exists() else None

    def upload(self, source, key):
        self.uploads += 1
        shutil.copyfile(source, self.path)
        if self.ambiguous:
            raise ArchiveUnknown("upload response lost")

    def download(self, key, target):
        shutil.copyfile(self.path, target)


class ArchiveTests(TransactionTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings_override = override_settings(MEDIA_ROOT=self.tmp.name, STORAGE_ARCHIVE_STATE_DIR=self.tmp.name + "/state", STORAGES={"default": {"BACKEND": "django.core.files.storage.FileSystemStorage"}, "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}})
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        org = Organization.objects.create(name="Archive test")
        self.workspace = Workspace.objects.create(id=WORKSPACE_ID, organization=org, name="Allowed")
        self.account = SocialAccount.objects.create(workspace=self.workspace, platform="instagram", account_platform_id="test", account_name="Test")
        self.post = Post.objects.create(workspace=self.workspace)
        self.platform = PlatformPost.objects.create(post=self.post, social_account=self.account, status="published", platform_post_id="confirmed-native")
        self.data = b"real original bytes" * 200
        self.asset = MediaAsset.objects.create(workspace=self.workspace, filename="original.mp4", media_type="video", mime_type="video/mp4", file_size=len(self.data), processing_status="completed", processed_variants={"existing": {"key": "preserved"}})
        self.asset.file.save("original.mp4", ContentFile(self.data))
        PostMedia.objects.create(post=self.post, media_asset=self.asset)
        self.receipts = [{"post_id": str(self.post.pk), "confirmed_at": timezone.now().isoformat(), "permalink": "https://www.instagram.com/p/confirmed/"}]
        self.remote = Remote(self.tmp.name)

    def test_roundtrip_preserves_row_key_and_variants(self):
        key = self.asset.file.name
        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        self.assertFalse(self.asset.file.storage.exists(key))
        restored = hydrate_asset(self.asset.pk, backend=self.remote)
        self.assertEqual(restored.file.name, key)
        with restored.file.open("rb") as original:
            self.assertEqual(original.read(), self.data)
        self.assertEqual(restored.processed_variants["existing"], {"key": "preserved"})
        self.assertEqual(restored.processed_variants["_archive"]["sha256"], hashlib.sha256(self.data).hexdigest())
        with self.assertRaises(ProtectedAssetError):
            delete_asset(restored)
        self.assertTrue(MediaAsset.objects.filter(pk=self.asset.pk).exists())

    def test_unknown_upload_reconciles_without_duplicate(self):
        self.remote.ambiguous = True
        with self.assertRaises(ArchiveUnknown):
            archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.asset.refresh_from_db()
        self.assertEqual(self.asset.processed_variants["_archive"]["state"], "UNKNOWN")
        self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))
        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        self.assertEqual(self.remote.uploads, 1)
        hydrate_asset(self.asset.pk, backend=self.remote)

    def test_all_nonterminal_statuses_block_retirement(self):
        for status in ["draft", "scheduled", "publishing", "failed", "UNKNOWN"]:
            self.platform.status = status
            self.platform.save(update_fields=["status"])
            with self.subTest(status=status), self.assertRaises(Exception):
                archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
            self.assertEqual(self.remote.uploads, 0)
            self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_corrupt_remote_never_retires(self):
        archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.remote.path.write_bytes(b"x" * len(self.data))
        with self.assertRaises(ArchiveUnknown):
            retire_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_unconfirmed_and_wrong_workspace_are_protected(self):
        with self.assertRaises(Exception):
            archive_asset(self.asset.pk, [], backend=self.remote)
        self.asset.workspace = Workspace.objects.create(organization=self.workspace.organization, name="Other")
        self.asset.save(update_fields=["workspace"])
        with self.assertRaises(Exception):
            archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.assertEqual(self.remote.uploads, 0)

    def test_json_cover_reference_blocks(self):
        draft = Post.objects.create(workspace=self.workspace)
        PlatformPost.objects.create(post=draft, social_account=self.account, status="UNKNOWN", platform_extra={"thumbnail_asset_id": str(self.asset.pk)})
        with self.assertRaises(Exception):
            archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.assertEqual(self.remote.uploads, 0)

    def test_repeat_hydration_and_remote_identity_change(self):
        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        hydrate_asset(self.asset.pk, backend=self.remote)
        hydrate_asset(self.asset.pk, backend=self.remote)
        with self.asset.file.open("rb") as original:
            self.assertEqual(hashlib.sha256(original.read()).hexdigest(), hashlib.sha256(self.data).hexdigest())
        with patch.object(self.remote, "stat", return_value={"id": "replaced-id", "size": len(self.data)}):
            with self.assertRaises(ArchiveUnknown):
                retire_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_pending_cover_even_with_confirmed_post_blocks(self):
        self.platform.status = "pending_review"
        self.platform.platform_extra = {"nested": {"cover_image_asset_id": str(self.asset.pk)}}
        self.platform.save(update_fields=["status", "platform_extra"])
        PostMedia.objects.filter(media_asset=self.asset).delete()
        with self.assertRaises(ProtectedAssetError):
            archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.assertEqual(self.remote.uploads, 0)

    def test_reference_created_during_verification_blocks_retirement(self):
        original = self.remote.download
        def download(key, target):
            original(key, target)
            self.platform.status = "UNKNOWN"
            self.platform.save(update_fields=["status"])
        with patch.object(self.remote, "download", side_effect=download):
            with self.assertRaises(ProtectedAssetError):
                archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_virtual_root_identity_uses_parent_listing(self):
        import json
        import os
        from types import SimpleNamespace
        from apps.media_library.storage_archive import RcloneRemote, DRIVE_ROOT_ID
        config_dir = Path(self.tmp.name) / "private"
        config_dir.mkdir(mode=0o700)
        config = config_dir / "rclone.conf"
        config.write_text("[prod-attack]\ntype=drive\nroot_folder_id=" + DRIVE_ROOT_ID + "\nclient_id=test\nclient_secret=test\n")
        os.chmod(config, 0o600)
        root = SimpleNamespace(returncode=0, stdout=json.dumps({"IsDir": True}))
        parent = SimpleNamespace(returncode=0, stdout=json.dumps([{"Name": "prod-attack", "ID": DRIVE_ROOT_ID, "IsDir": True}]))
        with override_settings(STORAGE_ARCHIVE_RCLONE_CONFIG=str(config)), patch.object(RcloneRemote, "_run_raw", side_effect=[root, parent]) as run:
            self.assertEqual(RcloneRemote().binding["root_folder_id"], DRIVE_ROOT_ID)
            self.assertIn("--drive-root-folder-id", run.call_args.args)
        wrong = SimpleNamespace(returncode=0, stdout=json.dumps([{"Name": "prod-attack", "ID": "wrong-folder", "IsDir": True}]))
        with override_settings(STORAGE_ARCHIVE_RCLONE_CONFIG=str(config)), patch.object(RcloneRemote, "_run_raw", side_effect=[root, wrong]):
            with self.assertRaises(ArchiveUnknown):
                RcloneRemote().binding

    def test_publisher_hydrates_original_and_thumbnail_before_dispatch(self):
        from unittest.mock import Mock
        from apps.publisher.engine import PublishEngine
        from providers.types import PostType
        self.platform.platform_extra = {"thumbnail_asset_id": str(self.asset.pk)}
        self.platform.save(update_fields=["platform_extra"])
        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        provider = Mock()
        provider.supported_post_types = [PostType.VIDEO]
        observed = []
        class CheckedDispatch(Exception):
            pass
        def publish(token, content):
            observed.append(Path(content.media_files[0]).read_bytes())
            observed.append(Path(content.extra["thumbnail_file"]).read_bytes())
            raise CheckedDispatch()
        provider.publish_post.side_effect = publish
        def hydrate(asset):
            return hydrate_asset(asset, backend=self.remote)
        with patch("apps.publisher.engine.get_provider", return_value=provider), patch("apps.media_library.storage_archive.hydrate_asset", side_effect=hydrate) as hydration:
            with self.assertRaises(CheckedDispatch):
                PublishEngine()._dispatch_to_provider(self.platform)
            self.assertEqual(hydration.call_count, 2)
        self.assertEqual(observed, [self.data, self.data])

    def test_hot_original_survives_drive_outage_without_clearing_unknown(self):
        class UnavailableRemote:
            @property
            def binding(self):
                raise ArchiveUnknown("Drive unavailable")

        self.remote.ambiguous = True
        with self.assertRaises(ArchiveUnknown):
            archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        restored = hydrate_asset(self.asset.pk, backend=UnavailableRemote())
        with restored.file.open("rb") as original:
            self.assertEqual(original.read(), self.data)
        self.assertEqual(restored.processed_variants["_archive"]["state"], "UNKNOWN")
        self.assertEqual(restored.processed_variants["_archive"]["archive_state"], "UNKNOWN")
        self.assertEqual(restored.processed_variants["_archive"]["resident_state"], "PRESENT")

        # Even a verified remote copy does not resolve an UNKNOWN retirement
        # outcome merely because the original can be read locally.
        archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        restored.refresh_from_db()
        record = restored.processed_variants["_archive"]
        record.update(state="UNKNOWN", phase="retire", resident_state="UNKNOWN")
        restored.save(update_fields=["processed_variants"])
        hot = hydrate_asset(restored.pk, backend=UnavailableRemote())
        self.assertEqual(hot.processed_variants["_archive"]["state"], "UNKNOWN")
        self.assertEqual(hot.processed_variants["_archive"]["phase"], "retire")
        self.assertEqual(hot.processed_variants["_archive"]["archive_state"], "VERIFIED")

    def test_missing_original_is_held_during_drive_outage(self):
        class UnavailableRemote:
            @property
            def binding(self):
                raise ArchiveUnknown("Drive unavailable")

        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        key = self.asset.file.name
        with self.assertRaises(ArchiveUnknown):
            hydrate_asset(self.asset.pk, backend=UnavailableRemote())
        self.asset.refresh_from_db()
        self.assertEqual(self.asset.file.name, key)
        self.assertFalse(self.asset.file.storage.exists(key))
        self.assertEqual(self.asset.processed_variants["_archive"]["state"], "UNKNOWN")
        self.assertTrue(MediaAsset.objects.filter(pk=self.asset.pk).exists())

    def test_completed_retirement_does_not_starve_next_candidate(self):
        import json
        from io import StringIO
        from django.core.management import call_command
        from apps.media_library.storage_archive import eligible_originals

        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        next_asset = MediaAsset.objects.create(id="ffffffff-ffff-ffff-ffff-ffffffffffff", workspace=self.workspace, filename="next.mp4", media_type="video", mime_type="video/mp4", file_size=len(self.data), processing_status="completed")
        next_asset.file.save("next.mp4", ContentFile(self.data))
        next_asset.refresh_from_db()
        PostMedia.objects.create(post=self.post, media_asset=next_asset, position=1)
        self.assertEqual([asset.pk for asset in eligible_originals(self.receipts)], [next_asset.pk])
        receipts_file = Path(self.tmp.name) / "confirmations.json"
        receipts_file.write_text(json.dumps(self.receipts))
        output = StringIO()
        call_command("archive_originals", confirmations=str(receipts_file), limit=1, stdout=output)
        selected = json.loads(output.getvalue().splitlines()[0])
        self.assertEqual(selected["asset_id"], str(next_asset.pk))
        self.assertEqual(selected["action"], "candidate")

    def test_hydrated_or_reappeared_original_becomes_candidate_again(self):
        from apps.media_library.storage_archive import eligible_originals

        archive_asset(self.asset.pk, self.receipts, retire_original=True, backend=self.remote)
        self.assertEqual(list(eligible_originals(self.receipts)), [])
        # A blob can reappear while metadata still says ABSENT. Do not starve it.
        Path(self.asset.file.path).write_bytes(self.data)
        self.assertEqual([asset.pk for asset in eligible_originals(self.receipts)], [self.asset.pk])
        Path(self.asset.file.path).unlink()
        hydrate_asset(self.asset.pk, backend=self.remote)
        self.assertEqual([asset.pk for asset in eligible_originals(self.receipts)], [self.asset.pk])

    def test_hot_original_still_checks_local_binding_and_bytes(self):
        class UnavailableRemote:
            @property
            def binding(self):
                raise AssertionError("hot path must not query Drive")

        archive_asset(self.asset.pk, self.receipts, backend=self.remote)
        self.asset.refresh_from_db()
        record = self.asset.processed_variants["_archive"]
        record["binding"]["root_folder_id"] = "wrong-root"
        self.asset.save(update_fields=["processed_variants"])
        with self.assertRaises(ArchiveUnknown):
            hydrate_asset(self.asset.pk, backend=UnavailableRemote())
        record["binding"]["root_folder_id"] = "1W8QzKWScz2s6cCOLTl3hdexiaSwPjyMC"
        self.asset.save(update_fields=["processed_variants"])
        Path(self.asset.file.path).write_bytes(b"x" * len(self.data))
        with self.assertRaises(ArchiveUnknown):
            hydrate_asset(self.asset.pk, backend=UnavailableRemote())
        self.assertEqual(Path(self.asset.file.path).read_bytes(), b"x" * len(self.data))



class RetentionBoundaryTests(ArchiveTests):
    def test_metadata_poll_does_not_restore_original_but_explicit_hydrate_does(self):
        from unittest.mock import MagicMock
        from apps.api.routers.media import retrieve, hydrate
        archive_asset(self.asset.pk,self.receipts,retire_original=True,backend=self.remote)
        request=MagicMock()
        with patch("apps.api.routers.media.enforce_http_rate_limits"), patch("apps.api.routers.media.log_audit_entry"), patch("apps.api.routers.media._visible_assets_qs",return_value=MediaAsset.objects.all()):
            with patch("apps.media_library.storage_archive.hydrate_asset",side_effect=AssertionError("metadata must not hydrate")):
                retrieve(request,self.asset.pk)
                retrieve(request,self.asset.pk)
            self.assertFalse(self.asset.file.storage.exists(self.asset.file.name))
            with patch("apps.media_library.storage_archive.RcloneRemote",return_value=self.remote):
                hydrate(request,self.asset.pk)
            self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_same_asset_version_alias_remains_protected(self):
        from apps.media_library.models import MediaAssetVersion
        MediaAssetVersion.objects.create(media_asset=self.asset,version_number=1,file=self.asset.file.name)
        with self.assertRaises(ProtectedAssetError):
            archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertEqual(self.remote.uploads,0)

    def test_retirement_rejects_outer_transaction(self):
        from django.db import transaction
        archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        with transaction.atomic(), self.assertRaises(ArchiveUnknown):
            retire_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertTrue(self.asset.file.storage.exists(self.asset.file.name))

    def test_hydration_does_not_overwrite_raced_in_original(self):
        archive_asset(self.asset.pk,self.receipts,retire_original=True,backend=self.remote)
        original_download=self.remote.download
        def race(key,destination):
            Path(self.asset.file.path).write_bytes(b"different writer")
            original_download(key,destination)
        with patch.object(self.remote,"download",side_effect=race), self.assertRaises(ArchiveUnknown):
            hydrate_asset(self.asset.pk,backend=self.remote)
        self.assertEqual(Path(self.asset.file.path).read_bytes(),b"different writer")

    def test_retirement_holds_reference_table_write_guard(self):
        from django.db import connection
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL writer lock")
        original_delete=self.asset.file.storage.delete
        def guarded(key):
            with connection.cursor() as cursor:
                cursor.execute("SELECT c.relname FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE l.pid=pg_backend_pid() AND l.mode='ShareRowExclusiveLock'")
                names={row[0] for row in cursor.fetchall()}
            self.assertTrue({PostMedia._meta.db_table,PlatformPost._meta.db_table}.issubset(names))
            independent = connection.copy(alias="intent-proof")
            try:
                with independent.cursor() as cursor:
                    cursor.execute("SELECT processed_variants->'_archive'->>'state' FROM " + connection.ops.quote_name(MediaAsset._meta.db_table) + " WHERE id=%s", [str(self.asset.pk)])
                    self.assertEqual(cursor.fetchone()[0],"UNKNOWN")
            finally:
                independent.close()
            original_delete(key)
        with patch.object(self.asset.file.storage,"delete",side_effect=guarded):
            archive_asset(self.asset.pk,self.receipts,retire_original=True,backend=self.remote)

    def test_cross_workspace_thumbnail_and_cover_are_rejected(self):
        from apps.publisher.engine import PublishEngine
        from providers.types import PostType
        from unittest.mock import MagicMock
        other=Workspace.objects.create(organization=self.workspace.organization,name="Other")
        outside=MediaAsset.objects.create(workspace=other,filename="outside.jpg",media_type="image",processing_status="completed")
        provider=MagicMock();provider.supported_post_types=[PostType.VIDEO]
        for field in ("thumbnail_asset_id","cover_image_asset_id"):
            self.platform.platform_extra={field:str(outside.pk)}
            self.platform.save(update_fields=["platform_extra"])
            with patch("apps.publisher.engine.get_provider",return_value=provider), self.assertRaises(ValueError):
                PublishEngine()._dispatch_to_provider(self.platform)
        provider.publish_post.assert_not_called()


class IndependentScopeTests(ArchiveTests):
    def scoped(self):
        import json
        from apps.media_library.storage_archive import CF_ROOT_ID, CF_NAMESPACES
        workspace_id = "49915185-0fe4-4eb6-a4d4-20b07211ede6"
        workspace = Workspace.objects.create(id=workspace_id, organization=self.workspace.organization, name="Holy")
        for row in (self.asset, self.post, self.account):
            row.workspace = workspace
            row.save(update_fields=["workspace"])
        evidence = Path(self.tmp.name) / "owner.json"
        evidence.write_text('{"owner":"Holy","approved":true}')
        scope = {"workspace_id":workspace_id,"operator_authorized":True,
                 "remote":"content-factory:","root_folder_id":CF_ROOT_ID,"namespace":CF_NAMESPACES[workspace_id],
                 "config":"/private/cf/rclone.conf","owner_evidence":str(evidence),
                 "owner_evidence_sha256":hashlib.sha256(evidence.read_bytes()).hexdigest(),
                 "checked_at":timezone.now().isoformat(),"eligible_asset_ids":[str(self.asset.pk)],
                 "held_asset_ids":[],"held_content_hashes":[]}
        authority = Path(self.tmp.name) / "authorities.json"
        authority.write_text(json.dumps({workspace_id:scope}))
        self.remote.binding = {"remote":"content-factory:","root_folder_id":CF_ROOT_ID}
        return authority, scope

    def test_independent_namespace_row_preserving_retire_and_hydrate(self):
        authority, scope = self.scoped()
        with override_settings(STORAGE_ARCHIVE_SCOPE_CONFIG=str(authority)):
            record = archive_asset(self.asset.pk,self.receipts,retire_original=True,backend=self.remote)
            self.assertTrue(record["remote_path"].startswith("content-factory:"+scope["namespace"]+"/"))
            self.assertTrue(MediaAsset.objects.filter(pk=self.asset.pk).exists())
            restored = hydrate_asset(self.asset.pk,backend=self.remote)
            with restored.file.open("rb") as stream:
                self.assertEqual(stream.read(),self.data)

    def test_pa_authority_cannot_authorize_cf(self):
        import json
        authority, scope = self.scoped()
        scope["root_folder_id"] = "1W8QzKWScz2s6cCOLTl3hdexiaSwPjyMC"
        authority.write_text(json.dumps({scope["workspace_id"]:scope}))
        with override_settings(STORAGE_ARCHIVE_SCOPE_CONFIG=str(authority)), self.assertRaises(ValueError):
            archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertEqual(self.remote.uploads,0)

    def test_hold_blocks_equivalent_copy_before_upload(self):
        import json
        authority, scope = self.scoped()
        scope["held_content_hashes"]=[hashlib.md5(self.data,usedforsecurity=False).hexdigest()]
        authority.write_text(json.dumps({scope["workspace_id"]:scope}))
        with override_settings(STORAGE_ARCHIVE_SCOPE_CONFIG=str(authority)), self.assertRaises(ProtectedAssetError):
            archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertEqual(self.remote.uploads,0)

    def test_owner_evidence_change_fails_closed(self):
        authority, scope = self.scoped()
        Path(scope["owner_evidence"]).write_text('{"new_pending_dependency":true}')
        with override_settings(STORAGE_ARCHIVE_SCOPE_CONFIG=str(authority)), self.assertRaises(ArchiveUnknown):
            archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertEqual(self.remote.uploads,0)

    def test_expired_provider_receipt_is_not_authority(self):
        authority, scope = self.scoped()
        self.settings_override_cf = override_settings(STORAGE_ARCHIVE_SCOPE_CONFIG=str(authority))
        self.settings_override_cf.enable()
        self.addCleanup(self.settings_override_cf.disable)
        self.receipts[0]["confirmed_at"]="2020-01-01T00:00:00+00:00"
        with self.assertRaises(ProtectedAssetError):
            archive_asset(self.asset.pk,self.receipts,backend=self.remote)
        self.assertEqual(self.remote.uploads,0)
