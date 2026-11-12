"""Exercise fixed numerical consumers after real disposable install rollback."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from tests import test_install_projection as fixture
from tests import test_installed_numeric_compatibility as numeric


MV_SHIM = r'''
capture_stage() {
    [ ! -e "$CWO_TEST_TARGET" ] || return 91
    [ -d "$1" ] && [ -d "$2" ] || return 92
    cp -R -- "$1" "$CWO_TEST_WITNESS" || return $?
    printf '%s\n' "$1" "$2" > "$CWO_TEST_EVENT"
}
if [ "$#" -ne 3 ] || [ "$1" != "--" ]; then
    exec "$REAL" "$@"
fi
source=$2
destination=$3
case "$CWO_TEST_INTERRUPT" in
    activation)
        [ "$destination" = "$CWO_TEST_TARGET" ] || exec "$REAL" "$@"
        case "$source" in
            "$CWO_TEST_SKILLS"/."$CWO_TEST_SKILL".stage.*) ;;
            *) exec "$REAL" "$@";;
        esac
        set -- "$CWO_TEST_BACKUPS"/"$CWO_TEST_SKILL".prev.*
        [ "$#" -eq 1 ] || exit 95
        capture_stage "$source" "$1" || exit $?
        exit 1;;
    term)
        [ "$source" = "$CWO_TEST_TARGET" ] || exec "$REAL" "$@"
        case "$destination" in
            "$CWO_TEST_BACKUPS"/"$CWO_TEST_SKILL".prev.*) ;;
            *) exec "$REAL" "$@";;
        esac
        "$REAL" "$@" || exit $?
        set -- "$CWO_TEST_SKILLS"/."$CWO_TEST_SKILL".stage.*
        [ "$#" -eq 1 ] || exit 95
        capture_stage "$1" "$destination" || exit $?
        kill -TERM "$PPID" || exit $?
        exit 0;;
    *) exit 94;;
esac
'''


class InstalledNumericRollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.golden_stat = numeric.GOLDEN.stat()
        self.addCleanup(self._assert_golden_unchanged)
        golden_bytes = numeric.GOLDEN.read_bytes()
        self.assertEqual(
            hashlib.sha256(golden_bytes).hexdigest(), numeric.GOLDEN_SHA256,
        )
        self.consumer = numeric.InstalledNumericCompatibilityTests(
            "test_replacement_source_gone_and_missing_numeric_dependency"
        )
        self.consumer.golden_bytes = golden_bytes
        # Register before either composed setup can allocate and then fail.
        self.addCleanup(self._cleanup_consumer)
        self.consumer.setUp()
        self.install = self.consumer.install
        self.consumer.positive()
        self._prepare_replacement()

    def _cleanup_consumer(self) -> None:
        # Also cover failure before the inner setup registers its own cleanup.
        temporary = getattr(getattr(self.consumer, "install", None), "_tmp", None)
        try:
            self.consumer.doCleanups()
        finally:
            if temporary is not None:
                temporary.cleanup()

    def _assert_golden_unchanged(self) -> None:
        current = numeric.GOLDEN.stat()
        for field in (
            "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns",
        ):
            with self.subTest(fixture_metadata=field):
                self.assertEqual(getattr(current, field), getattr(self.golden_stat, field))

    def _prepare_replacement(self) -> None:
        source = self.consumer.source
        target = self.install.target
        self.old_source = fixture.snapshot(source)
        self.old_target = fixture.snapshot(target)
        self.old_manifest = fixture.checker.build_manifest(source)
        self.assertEqual(self.old_manifest, self.consumer.expected)
        self.assertEqual(fixture.checker.build_manifest(target), self.old_manifest)
        security = source / "SECURITY.md"
        self.old_security = security.read_bytes()
        self.assertEqual((target / "SECURITY.md").read_bytes(), self.old_security)
        security.write_bytes(self.old_security + b"\nDisposable rollback test replacement marker.\n")
        self.new_manifest = fixture.checker.build_manifest(source)
        self.assertNotEqual(
            self.new_manifest["content_sha256"], self.old_manifest["content_sha256"],
        )
        self.assertEqual(
            fixture.checker.compare_manifests(self.old_manifest, self.new_manifest)["changed_files"],
            ["SECURITY.md"],
        )
        self.new_source = fixture.snapshot(source)
        self.assertEqual(set(self.old_source), set(self.new_source))
        self.assertEqual(
            {path for path in self.old_source if self.old_source[path] != self.new_source[path]},
            {"SECURITY.md"},
        )
        self.witness = self.install.tmp / "staged-witness"
        self.event = self.install.tmp / "interruption-paths"

    def _interrupt(self, mode: str) -> subprocess.CompletedProcess[str]:
        shim = self.install.shims / "mv"
        self.addCleanup(shim.unlink, missing_ok=True)
        self.assertFalse(self.witness.exists())
        self.install.write_shim("mv", MV_SHIM)
        env = {
            **self.consumer.env,
            "CWO_TEST_INTERRUPT": mode,
            "CWO_TEST_TARGET": str(self.install.target),
            "CWO_TEST_SKILLS": str(self.install.skills),
            "CWO_TEST_BACKUPS": str(self.install.backups),
            "CWO_TEST_SKILL": fixture.SKILL,
            "CWO_TEST_WITNESS": str(self.witness),
            "CWO_TEST_EVENT": str(self.event),
        }
        try:
            return subprocess.run(
                ["bash", str(self.consumer.source / "scripts/install.sh"),
                 "--skills-dir", str(self.install.skills), "--yes"],
                cwd=self.install.tmp, env=env, capture_output=True, text=True,
                check=False, timeout=180,
            )
        finally:
            shim.unlink(missing_ok=True)

    def _assert_rollback(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertIn(
            f"Restored the previous install at {self.install.target}",
            result.stderr.splitlines(),
        )
        self.assertEqual(fixture.snapshot(self.install.target), self.old_target)
        self.assertEqual(self.install.leftovers(), [])
        self.assertEqual(fixture.snapshot(self.consumer.source), self.new_source)
        stage, backup = (Path(line) for line in self.event.read_text(encoding="utf-8").splitlines())
        self.assertEqual(stage.parent, self.install.skills)
        self.assertTrue(stage.name.startswith(f".{fixture.SKILL}.stage."))
        self.assertEqual(backup.parent, self.install.backups)
        self.assertTrue(backup.name.startswith(f"{fixture.SKILL}.prev."))
        self.assertEqual(fixture.checker.build_manifest(self.witness), self.new_manifest)
        record = json.loads((self.witness / numeric.RECORD).read_text(encoding="utf-8"))
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["status"], "current")
        self.assertEqual(record["source_dir"], str(self.consumer.source.resolve()))
        for field in ("source_content_sha256", "installed_content_sha256"):
            self.assertEqual(record[field], self.new_manifest["content_sha256"])
        self.assertEqual(record["projection"], self.new_manifest["projection"])
        self.assertEqual(record["installed_file_count"], self.new_manifest["file_count"])
        self.assertEqual((self.install.target / "SECURITY.md").read_bytes(), self.old_security)
        self.assertNotEqual(
            (self.install.target / "SECURITY.md").read_bytes(),
            (self.consumer.source / "SECURITY.md").read_bytes(),
        )
        shutil.rmtree(self.witness)

    def test_activation_failure_restores_numeric_consumers_without_source(self) -> None:
        result = self._interrupt("activation")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"error: could not activate staged install at {self.install.target}",
            result.stderr.splitlines(),
        )
        self._assert_rollback(result)
        self.consumer.remove_source()
        self.consumer.positive()
        self.consumer.missing(
            numeric.MODULE, "ModuleNotFoundError", "No module named 'cwo_core.native_progress'",
        )

    def test_term_after_backup_restores_numeric_consumers_without_source(self) -> None:
        result = self._interrupt("term")
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self._assert_rollback(result)
        self.consumer.remove_source()
        self.consumer.positive()
        self.consumer.missing(
            numeric.POLICY, "SystemExit",
            "missing policy file: policy/native-worker-execution.yaml",
        )


if __name__ == "__main__":
    unittest.main()
