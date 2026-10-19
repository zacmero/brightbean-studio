import json
from pathlib import Path
import stat
import subprocess
import tempfile
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from apps.media_library.storage_archive import ArchiveUnknown, RcloneRemote


class ArchiveDiagnosticsTests(SimpleTestCase):
    def test_failed_process_keeps_private_stderr_and_original_result(self):
        result = subprocess.CompletedProcess([], 1, "", "private provider diagnostic")
        with tempfile.TemporaryDirectory() as directory, override_settings(STORAGE_ARCHIVE_STATE_DIR=directory):
            remote = RcloneRemote({"config": "/unused/private-config"})
            with patch("apps.media_library.storage_archive.subprocess.run", return_value=result):
                self.assertIs(remote._run_raw("copyto", "source", "destination"), result)
            folder = Path(directory) / "diagnostics"
            receipt, = folder.iterdir()
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertEqual(json.loads(receipt.read_text())["stderr"], result.stderr)

    def test_timeout_stays_unknown_and_captures_partial_stderr(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(STORAGE_ARCHIVE_STATE_DIR=directory):
            remote = RcloneRemote({"config": "/unused/private-config"})
            with patch("apps.media_library.storage_archive.subprocess.run", side_effect=subprocess.TimeoutExpired("rclone", 900, stderr=b"partial diagnostic")):
                with self.assertRaisesMessage(ArchiveUnknown, "rclone outcome unresolved"):
                    remote._run_raw("copyto", "source", "destination")
            receipt, = (Path(directory) / "diagnostics").iterdir()
            self.assertEqual(json.loads(receipt.read_text())["stderr"], "partial diagnostic")

    def test_diagnostic_disk_error_does_not_change_provider_outcome(self):
        result = subprocess.CompletedProcess([], 1, "", "private diagnostic")
        remote = RcloneRemote({"config": "/unused/private-config"})
        with patch("apps.media_library.storage_archive.subprocess.run", return_value=result), patch("apps.media_library.storage_archive.Path.mkdir", side_effect=OSError("full")):
            self.assertIs(remote._run_raw("copyto", "source", "destination"), result)
