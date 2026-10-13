"""Allowlisted BrightBean originals: verified Drive copies and same-key hydration.

No discovery, automatic cleanup, row deletion, or remote deletion lives here.
"""
from __future__ import annotations

import configparser
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
import uuid
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import connection, transaction

from .models import MediaAsset
from .services import ProtectedAssetError, asset_has_non_post_references, asset_referencing_posts

WORKSPACE_ID = "99d7934b-9a92-442c-9414-80bc088a36b5"
DRIVE_ROOT_ID = "1W8QzKWScz2s6cCOLTl3hdexiaSwPjyMC"
REMOTE = "prod-attack:"
DEFAULT_CONFIG = "/home/ubuntu/projects/prod-attack/.runtime-secrets/storage-archive/rclone.conf"
DEFAULT_STATE = "/home/ubuntu/projects/prod-attack/var/storage-archive/brightbean"
CF_ROOT_ID = "1ALgEsE_M9N5wk3WQkjrdfkScVS6OuIqH"
CF_NAMESPACES = {
    "f7c11493-0569-4d66-b9dc-84b5ca3dc2fe": "provider-originals/relaxing-paradise/f7c11493-0569-4d66-b9dc-84b5ca3dc2fe",
    "49915185-0fe4-4eb6-a4d4-20b07211ede6": "provider-originals/holy-miracle/49915185-0fe4-4eb6-a4d4-20b07211ede6",
}


class ArchiveUnknown(RuntimeError):
    """An unresolved transfer or identity mismatch must be reconciled before retry."""


def _setting(name, default):
    return getattr(settings, name, os.environ.get(name, default))


def _now():
    return datetime.now(timezone.utc).isoformat()


def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _authority(workspace_id):
    workspace_id = str(workspace_id)
    if workspace_id == WORKSPACE_ID:
        return {"workspace_id": WORKSPACE_ID, "remote": REMOTE, "root_folder_id": DRIVE_ROOT_ID,
                "namespace": f"brightbean/{WORKSPACE_ID}",
                "config": _setting("STORAGE_ARCHIVE_RCLONE_CONFIG", DEFAULT_CONFIG)}
    if workspace_id not in CF_NAMESPACES:
        raise ProtectedAssetError([{"id": workspace_id, "caption": "Outside authorized workspace"}])
    path = Path(_setting("STORAGE_ARCHIVE_SCOPE_CONFIG", str(Path(DEFAULT_STATE) / "workspace-authorities.json")))
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("explicit independent workspace authority required")
    scope = json.loads(path.read_text()).get(workspace_id)
    if (not isinstance(scope, dict) or scope.get("workspace_id") != workspace_id
            or scope.get("operator_authorized") is not True
            or scope.get("remote") != "content-factory:"
            or scope.get("root_folder_id") != CF_ROOT_ID
            or scope.get("namespace") != CF_NAMESPACES[workspace_id]
            or not Path(str(scope.get("config", ""))).is_absolute()):
        raise ValueError("independent workspace archive binding mismatch")
    return scope


def _owner_evidence(asset, scope):
    if str(asset.workspace_id) == WORKSPACE_ID:
        return
    evidence = Path(scope["owner_evidence"])
    if not evidence.is_absolute() or evidence.is_symlink() or _digest(evidence) != scope["owner_evidence_sha256"]:
        raise ArchiveUnknown("owner dependency evidence changed")
    checked = datetime.fromisoformat(scope["checked_at"].replace("Z", "+00:00"))
    if checked.tzinfo is None:
        raise ValueError("owner evidence timestamp must be timezone-aware")
    age = (datetime.now(timezone.utc) - checked).total_seconds()
    if not 0 <= age <= 86400:
        raise ProtectedAssetError([{"id": str(asset.pk), "caption": "Owner dependency evidence expired"}])
    if str(asset.pk) not in scope.get("eligible_asset_ids", []) or str(asset.pk) in scope.get("held_asset_ids", []):
        raise ProtectedAssetError([{"id": str(asset.pk), "caption": "Owner dependency or clipping hold"}])


def _held_content(path, scope):
    sha256 = _digest(path)
    protected = scope.get("held_content_hashes", [])
    if sha256 in protected:
        raise ProtectedAssetError()
    if any(len(value) == 32 for value in protected):
        digest = hashlib.md5(usedforsecurity=False)
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() in protected:
            raise ProtectedAssetError()


class RcloneRemote:
    """Same stat/upload/download contract as prod_attack.storage_archive.RcloneRemote."""

    def __init__(self, scope=None):
        self.scope = scope or _authority(WORKSPACE_ID)

    @property
    def binding(self):
        config = Path(self.scope["config"])
        if (not config.is_absolute() or config.is_symlink() or config.parent.is_symlink()
                or stat.S_IMODE(config.stat().st_mode) != 0o600
                or stat.S_IMODE(config.parent.stat().st_mode) & 0o077):
            raise ValueError("isolated private rclone config required")
        parsed = configparser.ConfigParser(interpolation=None)
        parsed.read(config)
        section = parsed[self.scope["remote"].rstrip(":")]
        root_id = self.scope["root_folder_id"]
        remote = self.scope["remote"]
        if (section.get("type") != "drive" or section.get("root_folder_id") != root_id
                or not section.get("client_id") or not section.get("client_secret")):
            raise ValueError("verified independent workspace Drive root required")
        if (self.scope.get("client_id_sha256")
                and hashlib.sha256(section["client_id"].encode()).hexdigest() != self.scope["client_id_sha256"]):
            raise ValueError("workspace OAuth client identity changed")
        if not getattr(self, "_root_verified", False):
            result = self._run_raw("lsjson", remote, "--stat")
            if result.returncode:
                raise ArchiveUnknown("archive root reconciliation failed")
            folder = json.loads(result.stdout)
            if isinstance(folder, list):
                if len(folder) != 1:
                    raise ArchiveUnknown("archive root identity ambiguous")
                folder = folder[0]
            if not folder.get("IsDir"):
                raise ArchiveUnknown("archive root is not a directory")
            if folder.get("ID"):
                if folder["ID"] != root_id:
                    raise ArchiveUnknown("archive root identity changed")
            else:
                parent = self._run_raw("lsjson", remote, "--drive-root-folder-id", "root", "--dirs-only", "--max-depth", "1")
                if parent.returncode:
                    raise ArchiveUnknown("archive parent reconciliation failed")
                matches = [entry for entry in json.loads(parent.stdout) if entry.get("ID") == root_id]
                if len(matches) != 1:
                    raise ArchiveUnknown("archive virtual root identity changed")
            self._root_verified = True
        return {"remote": remote, "root_folder_id": root_id}

    def _run(self, *args):
        self.binding
        return self._run_raw(*args)

    def _run_raw(self, *args):
        config = self.scope["config"]
        try:
            return subprocess.run(
                ["rclone", "--config", str(config), "--tpslimit", "2", "--tpslimit-burst", "1",
                 "--transfers", "1", "--checkers", "1", "--retries", "1", "--low-level-retries", "1", *args],
                capture_output=True, text=True, timeout=900,
            )
        except subprocess.TimeoutExpired as error:
            raise ArchiveUnknown("rclone outcome unresolved") from error

    def stat(self, remote):
        result = self._run("lsjson", remote, "--stat")
        if result.returncode in (3, 4):
            return None
        if result.returncode:
            raise ArchiveUnknown("remote identity read failed")
        entry = json.loads(result.stdout)
        if isinstance(entry, list):
            if len(entry) != 1:
                raise ArchiveUnknown("ambiguous remote identity")
            entry = entry[0]
        if entry.get("IsDir") or not entry.get("ID"):
            raise ArchiveUnknown("remote file ID missing")
        return {"id": str(entry["ID"]), "size": int(entry["Size"])}

    def upload(self, source, remote):
        if self._run("copyto", str(source), remote, "--immutable", "--no-traverse").returncode:
            raise ArchiveUnknown("archive upload outcome unresolved")

    def download(self, remote, destination):
        if self._run("copyto", remote, str(destination), "--immutable", "--no-traverse").returncode:
            raise ArchiveUnknown("archive download outcome unresolved")


def _asset(value):
    pk = value.pk if isinstance(value, MediaAsset) else uuid.UUID(str(value))
    return MediaAsset.objects.get(pk=pk)


def _scope(asset):
    scope = _authority(asset.workspace_id)
    key = asset.file.name
    if not key or PurePosixPath(key).is_absolute() or ".." in PurePosixPath(key).parts:
        raise ValueError("original storage key must be a safe relative key")
    return scope


def _confirmed_ids(receipts, require_fresh=False):
    if isinstance(receipts, (str, Path)):
        receipts = json.loads(Path(receipts).read_text())
    if not isinstance(receipts, list):
        raise ValueError("root-supplied receipt list required")
    ids = set()
    for receipt in receipts:
        pk = str(uuid.UUID(str(receipt["post_id"])))
        timestamp = datetime.fromisoformat(str(receipt.get("official_confirmed_at") or receipt["confirmed_at"]).replace("Z", "+00:00"))
        if timestamp.tzinfo is None or not str(receipt.get("permalink", "")).startswith("https://"):
            raise ValueError("provider-visible timestamp and permalink required")
        if require_fresh and not 0 <= (datetime.now(timezone.utc) - timestamp).total_seconds() <= 86400:
            continue
        ids.add(pk)
    return ids


def _retention_allowed(asset, receipts):
    scope = _scope(asset)
    _owner_evidence(asset, scope)
    if asset.processing_status != "completed":
        raise ProtectedAssetError()
    allowed = _confirmed_ids(receipts, require_fresh=str(asset.workspace_id) != WORKSPACE_ID)
    posts = asset_referencing_posts(asset)
    if not posts or asset_has_non_post_references(asset):
        raise ProtectedAssetError()
    for post in posts:
        children = list(post.platform_posts.all())
        if (post.workspace_id != asset.workspace_id or str(post.pk) not in allowed or not children
                or any(child.status != "published" or not child.platform_post_id or child.publish_error for child in children)):
            raise ProtectedAssetError([{"id": str(post.pk), "caption": "Not entirely terminal and externally confirmed"}])
    storage = asset.file.storage
    if hasattr(storage, "connection") and hasattr(storage, "bucket_name"):
        from storages.utils import clean_name
        key = storage._normalize_name(clean_name(asset.file.name))
        uploads = storage.connection.meta.client.list_multipart_uploads(Bucket=storage.bucket_name, Prefix=key)
        if uploads.get("IsTruncated") or any(item["Key"] == key for item in uploads.get("Uploads", [])):
            raise ProtectedAssetError([{"id": str(asset.pk), "caption": "Active or unresolved multipart upload"}])


@contextmanager
def _locked(asset):
    directory = Path(_setting("STORAGE_ARCHIVE_STATE_DIR", DEFAULT_STATE))
    if not directory.is_absolute():
        raise ValueError("absolute shared archive staging directory required")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (directory / (str(asset.pk) + ".lock")).open("a+b") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield directory


def _persist(asset, record):
    # Commit intent before each external effect, preserving unrelated cover variants.
    with transaction.atomic():
        current = MediaAsset.objects.select_for_update().get(pk=asset.pk)
        if current.file.name != asset.file.name or current.workspace_id != asset.workspace_id:
            raise ArchiveUnknown("asset identity changed")
        variants = dict(current.processed_variants or {})
        variants["_archive"] = dict(record)
        current.processed_variants = variants
        current.save(update_fields=["processed_variants", "updated_at"])
        asset.processed_variants = variants


def _record(asset, remote=None):
    scope = _scope(asset)
    record = (asset.processed_variants or {}).get("_archive")
    if (not isinstance(record, dict) or record.get("asset_id") != str(asset.pk)
            or record.get("workspace_id") != str(asset.workspace_id) or record.get("storage_key") != asset.file.name
            or record.get("binding") != {"remote": scope["remote"], "root_folder_id": scope["root_folder_id"]}
            or not str(record.get("remote_path", "")).startswith(f"{scope['remote']}{scope['namespace']}/{asset.pk}/")
            or len(str(record.get("sha256", ""))) != 64 or int(record.get("byte_size", 0)) <= 0):
        raise ArchiveUnknown("archive metadata binding mismatch")
    sha = str(record["sha256"])
    path = str(record["remote_path"])
    leaf = path.rsplit("/", 1)[-1]
    if (any(char not in "0123456789abcdef" for char in sha)
            or ".." in PurePosixPath(path.split(":", 1)[-1]).parts
            or not (leaf == sha or leaf.startswith(sha + "."))
            or record.get("operation_id") != f"brightbean:archive:{asset.pk}:{sha}"):
        raise ArchiveUnknown("archive content identity mismatch")
    if remote is not None and record["binding"] != remote.binding:
        raise ArchiveUnknown("live archive binding mismatch")
    return dict(record)


def _verified_download(asset, record, remote, directory):
    identity = remote.stat(record["remote_path"])
    if (identity is None or identity["size"] != record["byte_size"]
            or record.get("remote_id") and record["remote_id"] != identity["id"]):
        raise ArchiveUnknown("remote absent, changed ID, or changed size")
    record["remote_id"] = identity["id"]
    _persist(asset, record)
    destination = Path(directory) / "verified-original"
    destination.unlink(missing_ok=True)  # disposable staging, never provider content
    remote.download(record["remote_path"], destination)
    if (destination.stat().st_size != record["byte_size"] or _digest(destination) != record["sha256"]
            or remote.stat(record["remote_path"]) != identity):
        raise ArchiveUnknown("remote roundtrip hash/size/identity verification failed")
    return destination


def _unknown(asset, record, error):
    record.update(state="UNKNOWN", last_error=type(error).__name__, updated_at=_now())
    _persist(asset, record)


@contextmanager
def _dependency_commit(asset):
    """Block every ordinary reference writer during final check and object removal."""
    from apps.composer.models import Post, PostMedia, PlatformPost, PostVersion, Idea, IdeaMedia, PostTemplate
    from .models import MediaAssetVersion, PendingUpload

    with transaction.atomic():
        if connection.vendor == "postgresql":
            tables = sorted(model._meta.db_table for model in (
                MediaAsset, MediaAssetVersion, PendingUpload, Post, PostMedia,
                PlatformPost, PostVersion, Idea, IdeaMedia, PostTemplate,
            ))
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout = '5s'")
                cursor.execute("LOCK TABLE " + ", ".join(connection.ops.quote_name(name) for name in tables) + " IN SHARE ROW EXCLUSIVE MODE")
        yield MediaAsset.objects.select_for_update().get(pk=asset.pk)


@contextmanager
def _write_admission(storage, key):
    directory = Path(_setting("STORAGE_ARCHIVE_STATE_DIR", DEFAULT_STATE))
    with (directory / "write-admission.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        policy = json.loads((directory / "write-admission.json").read_text())
        if (policy.get("server_write_guard_verified") is not True
                or policy.get("endpoint_host") != urlsplit(storage.connection.meta.client.meta.endpoint_url).netloc
                or storage.bucket_name + "/" + key not in policy.get("sealed_keys", [])):
            raise ArchiveUnknown("verified exact-original write admission required")
        token_path = Path(policy["owner_token_file"])
        if stat.S_IMODE(token_path.stat().st_mode) != 0o600:
            raise ArchiveUnknown("private original-retirement identity required")
        yield token_path.read_text().strip()


def _retire_locked(asset, receipts, remote, directory):
    if connection.in_atomic_block:
        raise ArchiveUnknown("retirement requires a durable pre-effect commit outside caller transactions")
    _retention_allowed(asset, receipts)
    record = _record(asset, remote)
    if record.get("archive_state") != "VERIFIED":
        raise ArchiveUnknown("verified archive required before retirement")
    try:
        restored = _verified_download(asset, record, remote, directory)
        _held_content(restored, _scope(asset))
        storage = asset.file.storage
        original_etag = None
        if asset.file.storage.exists(asset.file.name) and hasattr(storage, "connection") and hasattr(storage, "bucket_name"):
            from storages.utils import clean_name
            storage_args = {"Bucket": storage.bucket_name,
                            "Key": storage._normalize_name(clean_name(asset.file.name))}
            original_etag = storage.connection.meta.client.head_object(**storage_args)["ETag"]
        if asset.file.storage.exists(asset.file.name):
            source = Path(directory) / "resident-original"
            with asset.file.open("rb") as src, source.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            if source.stat().st_size != record["byte_size"] or _digest(source) != record["sha256"]:
                raise ArchiveUnknown("resident original changed")
        record.update(state="UNKNOWN", phase="retire", resident_state="UNKNOWN", original_etag=original_etag)
        _persist(asset, record)
        with _dependency_commit(asset) as current:
            if current.file.name != record["storage_key"] or current.workspace_id != asset.workspace_id:
                raise ArchiveUnknown("original identity changed before retirement")
            _retention_allowed(current, receipts)
            try:
                if original_etag:
                    with _write_admission(storage, storage_args["Key"]) as token:
                        # MinIO ignores DeleteObject IfMatch; the verified gateway seals writes.
                        url = storage.connection.meta.client.generate_presigned_url("delete_object", Params=storage_args, ExpiresIn=60)
                        request = Request(url, method="DELETE", headers={"X-Storage-Archive-Owner": token, "If-Match": original_etag})
                        with urlopen(request, timeout=60):
                            pass
                else:
                    current.file.storage.delete(current.file.name)
            except Exception:
                if current.file.storage.exists(current.file.name):
                    raise
            if current.file.storage.exists(current.file.name):
                raise ArchiveUnknown("original retirement not provider-confirmed")
            record.update(state="VERIFIED", phase=None, resident_state="ABSENT", retired_at=_now())
            _persist(current, record)
        return record
    except Exception as error:
        _unknown(asset, record, error)
        raise


def archive_asset(asset_id, confirmed_posts, *, retire_original=False, backend=None):
    """Copy one eligible original; retirement is explicit and never deletes its row."""
    asset = _asset(asset_id)
    _retention_allowed(asset, confirmed_posts)
    remote = backend or RcloneRemote(_scope(asset))
    with _locked(asset) as state_dir, tempfile.TemporaryDirectory(dir=state_dir) as tmp:
        asset = _asset(asset.pk)
        _retention_allowed(asset, confirmed_posts)
        existing = "_archive" in (asset.processed_variants or {})
        if existing:
            record = _record(asset, remote)
        else:
            if shutil.disk_usage(state_dir).free < 2 * asset.file_size + 64 * 1024 * 1024:
                raise ArchiveUnknown("insufficient archive staging space")
            source = Path(tmp) / "source-original"
            with asset.file.open("rb") as src, source.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            size, sha = source.stat().st_size, _digest(source)
            scope = _scope(asset)
            _held_content(source, scope)
            if size <= 0 or asset.file_size not in (0, size):
                raise ArchiveUnknown("original size differs from asset metadata")
            suffix = PurePosixPath(asset.file.name).suffix.lower()
            if suffix not in {".mp4", ".mov", ".webm", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".wav", ".mp3", ".m4a", ".ogg"}:
                raise ValueError("media originals only")
            record = {"version": 1, "operation_id": f"brightbean:archive:{asset.pk}:{sha}",
                      "asset_id": str(asset.pk), "workspace_id": str(asset.workspace_id), "storage_key": asset.file.name,
                      "sha256": sha, "byte_size": size, "binding": remote.binding,
                      "remote_path": f"{scope['remote']}{scope['namespace']}/{asset.pk}/{sha}{suffix}",
                      "remote_id": None, "state": "UNKNOWN", "archive_state": "UNKNOWN",
                      "resident_state": "PRESENT", "phase": "archive", "created_at": _now()}
            _persist(asset, record)
        try:
            identity = remote.stat(record["remote_path"])
            if identity is None:
                if existing:
                    raise ArchiveUnknown("prior upload unresolved and remote absent; no blind upload retry")
                remote.upload(source, record["remote_path"])
            _verified_download(asset, record, remote, tmp)
            record.update(state="VERIFIED", archive_state="VERIFIED", phase=None, verified_at=_now())
            _persist(asset, record)
            if retire_original:
                return _retire_locked(asset, confirmed_posts, remote, tmp)
            return record
        except Exception as error:
            _unknown(asset, record, error)
            raise


def retire_asset(asset_id, confirmed_posts, *, backend=None):
    asset = _asset(asset_id)
    _retention_allowed(asset, confirmed_posts)
    with _locked(asset) as directory, tempfile.TemporaryDirectory(dir=directory) as tmp:
        return _retire_locked(_asset(asset.pk), confirmed_posts, backend or RcloneRemote(_scope(asset)), tmp)


def _write_same_key(asset, source):
    storage, key = asset.file.storage, asset.file.name
    if isinstance(storage, FileSystemStorage):
        target = Path(storage.path(key))
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
            staging = Path(tmp.name)
            try:
                with Path(source).open("rb") as src:
                    shutil.copyfileobj(src, tmp, 1024 * 1024)
                tmp.flush()
                os.fsync(tmp.fileno())
                try:
                    os.link(staging, target)
                except FileExistsError:
                    pass  # independently reconcile the raced-in original below
            finally:
                staging.unlink(missing_ok=True)
    elif hasattr(storage, "connection") and hasattr(storage, "bucket_name"):
        from storages.utils import clean_name

        from botocore.exceptions import ClientError

        client = storage.connection.meta.client
        args = {"Bucket": storage.bucket_name, "Key": storage._normalize_name(clean_name(key))}
        upload_id = None
        try:
            with Path(source).open("rb") as src:
                if Path(source).stat().st_size <= 5 * 1024 ** 3:
                    client.put_object(**args, Body=src, ContentType=asset.mime_type or "application/octet-stream", IfNoneMatch="*")
                else:
                    upload_id = client.create_multipart_upload(**args, ContentType=asset.mime_type or "application/octet-stream")["UploadId"]
                    parts = []
                    for number, chunk in enumerate(iter(lambda: src.read(64 * 1024 ** 2), b""), 1):
                        part = client.upload_part(**args, UploadId=upload_id, PartNumber=number, Body=chunk)
                        parts.append({"PartNumber": number, "ETag": part["ETag"]})
                    client.complete_multipart_upload(**args, UploadId=upload_id, MultipartUpload={"Parts": parts}, IfNoneMatch="*")
                    upload_id = None
        except ClientError as error:
            if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 412:
                raise
        finally:
            if upload_id:
                client.abort_multipart_upload(**args, UploadId=upload_id)
    else:
        raise ArchiveUnknown("storage backend cannot guarantee exact-key hydration")


def hydrate_asset(asset_or_id, *, backend=None):
    """Verify and restore the original key before any publishing URL/upload is built."""
    asset = _asset(asset_or_id)
    if "_archive" not in (asset.processed_variants or {}):
        return asset
    _scope(asset)
    remote = backend or RcloneRemote(_scope(asset))
    with _locked(asset) as directory, tempfile.TemporaryDirectory(dir=directory) as tmp:
        asset = _asset(asset.pk)
        record = _record(asset)
        try:
            resident = asset.file.storage.exists(asset.file.name)
            if resident:
                local = Path(tmp) / "resident-original"
                with asset.file.open("rb") as src, local.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                if local.stat().st_size != record["byte_size"] or _digest(local) != record["sha256"]:
                    raise ArchiveUnknown("resident key has different content; never overwrite")
            else:
                record = _record(asset, remote)
                if record.get("archive_state") != "VERIFIED":
                    raise ArchiveUnknown("archive must be reconciled before hydration")
                if shutil.disk_usage(directory).free < 2 * record["byte_size"] + 64 * 1024 * 1024:
                    raise ArchiveUnknown("insufficient hydration staging space")
                local = _verified_download(asset, record, remote, tmp)
                record.update(state="UNKNOWN", phase="hydrate", resident_state="UNKNOWN")
                _persist(asset, record)
                _write_same_key(asset, local)
                # Independently read storage bytes; acceptance is not hydration proof.
                check = Path(tmp) / "hydrated-check"
                with asset.file.open("rb") as src, check.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                if check.stat().st_size != record["byte_size"] or _digest(check) != record["sha256"]:
                    raise ArchiveUnknown("hydrated original hash/size differs")
            record.update(resident_state="PRESENT", hydrated_at=_now())
            if not resident and record.get("archive_state") == "VERIFIED":
                record.update(state="VERIFIED", phase=None)
            _persist(asset, record)
            return asset
        except Exception as error:
            _unknown(asset, record, error)
            raise


def eligible_originals(confirmed_posts, minimum_bytes=1, workspace_id=WORKSPACE_ID):
    """Read-only scoped selection; every candidate is checked again before effects."""
    _authority(workspace_id)
    for asset in MediaAsset.objects.filter(workspace_id=workspace_id, file_size__gte=minimum_bytes).order_by("-file_size"):
        try:
            _retention_allowed(asset, confirmed_posts)
        except (ValueError, ArchiveUnknown, ProtectedAssetError):
            continue
        if "_archive" in (asset.processed_variants or {}):
            try:
                record = _record(asset)
            except (ValueError, ArchiveUnknown, TypeError):
                continue
            if (record.get("state") == "VERIFIED" and record.get("archive_state") == "VERIFIED"
                    and record.get("resident_state") == "ABSENT" and record.get("remote_id")
                    and record.get("retired_at") and not asset.file.storage.exists(asset.file.name)):
                continue
        yield asset
