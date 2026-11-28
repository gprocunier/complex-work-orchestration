"""Offline checks for parsing and settling contained worker patches."""

from hashlib import sha256
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cwo_core.native_pool_transaction import NativePoolTransactionError
from cwo_core.worker_patch import (
    MAX_WORKER_DIFF_BYTES,
    MAX_WORKER_PATCH_BYTES,
    WorkerPatchError,
    apply_worker_patch,
)
import registered_pool_ordinary_runtime as ordinary_runtime


TARGET = "pkg/source.py"
DIRECT = f"--- {TARGET}\n+++ {TARGET}\n"
PREFIXED = f"--- a/{TARGET}\n+++ b/{TARGET}\n"
ENVELOPE = f"diff --git a/{TARGET} b/{TARGET}\n"
UPDATE = "@@ -1 +1 @@\n-before\n+after\n"


class WorkerPatchTests(unittest.TestCase):
    def apply(self, diff, before=b"before\n", *, target=TARGET, maximum_bytes=MAX_WORKER_PATCH_BYTES):
        return apply_worker_patch(diff, target, before, maximum_bytes=maximum_bytes)

    def test_accepts_both_header_forms_and_ordinary_git_envelopes(self):
        for headers in (
            DIRECT, PREFIXED, ENVELOPE + PREFIXED,
            ENVELOPE + "index 3ba2903..f032b04 100644\n" + PREFIXED,
            ENVELOPE + f"index {'a' * 64}..{'b' * 64} 100755\n" + PREFIXED,
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.apply(headers + UPDATE), b"after\n")

    def test_applies_ordered_hunks_with_context_and_original_gaps(self):
        before = b"first\nkeep\nuntouched\nnext\nfinal\n"
        diff = DIRECT + (
            "@@ -1,2 +1,3 @@ section\n-first\n+new first\n+added\n keep\n"
            "@@ -4,2 +5 @@\n-next\n final\n"
        )
        self.assertEqual(self.apply(diff, before), b"new first\nadded\nkeep\nuntouched\nfinal\n")

    def test_rejects_hunks_that_leave_the_file_unchanged(self):
        for hunks in (
            "@@ -1 +1 @@\n-before\n+before\n",
            "@@ -1 +0,0 @@\n-before\n@@ -1,0 +1 @@\n+before\n",
        ):
            with self.subTest(hunks=hunks), self.assertRaisesRegex(WorkerPatchError, "leaves the file unchanged"):
                self.apply(DIRECT + hunks)

    def test_zero_length_ranges_allow_insertion_and_an_empty_postimage(self):
        self.assertEqual(self.apply(DIRECT + "@@ -0,0 +1 @@\n+new\n", b""), b"new\n")
        self.assertEqual(self.apply(DIRECT + "@@ -1,0 +2 @@\n+new\n"), b"before\nnew\n")
        self.assertEqual(self.apply(DIRECT + "@@ -1 +0,0 @@\n-before\n"), b"")

    def test_exact_utf8_endings_include_crlf_and_missing_final_newline(self):
        diff = DIRECT + "@@ -1,2 +1,2 @@\n café\r\n-fin\n\\ No newline at end of file\n+été\n"
        self.assertEqual(self.apply(diff, "café\r\nfin".encode()), "café\r\nété\n".encode())
        diff = DIRECT + UPDATE + "\\ No newline at end of file\n"
        self.assertEqual(self.apply(diff), b"after")

    def test_rejects_other_paths_ambiguous_header_forms_and_noncanonical_targets(self):
        for headers in (
            "--- nearby.py\n+++ nearby.py\n",
            f"--- a/{TARGET}\n+++ nearby.py\n",
            f"--- {TARGET}\n+++ b/{TARGET}\n",
            f"diff --git a/{TARGET} b/nearby.py\n" + PREFIXED,
            ENVELOPE + DIRECT,
        ):
            with self.subTest(headers=headers), self.assertRaises(WorkerPatchError):
                self.apply(headers + UPDATE)
        for target in ("", "/source.py", "./source.py", "pkg//source.py", "pkg/../source.py", "source.py\n"):
            with self.subTest(target=target), self.assertRaises(WorkerPatchError):
                self.apply(f"--- {target}\n+++ {target}\n" + UPDATE, target=target)

    def test_rejects_operations_outside_an_existing_regular_file_update(self):
        for metadata in (
            "old mode 100644\nnew mode 100755\n",
            "rename from pkg/source.py\nrename to pkg/another.py\n",
            "new file mode 100644\n",
            "deleted file mode 100644\n",
            "GIT binary patch\n",
            "index 0000000..f032b04 100644\n",
            "index 3ba2903..0000000 100644\n",
            "index 3ba2903..f032b04 120000\n",
        ):
            with self.subTest(metadata=metadata), self.assertRaises(WorkerPatchError):
                self.apply(ENVELOPE + metadata + PREFIXED + UPDATE)
        for diff in (
            f"--- /dev/null\n+++ b/{TARGET}\n" + UPDATE,
            f"--- a/{TARGET}\n+++ /dev/null\n" + UPDATE,
            PREFIXED + UPDATE + ENVELOPE + PREFIXED + UPDATE,
        ):
            with self.subTest(diff=diff), self.assertRaises(WorkerPatchError):
                self.apply(diff)

    def test_rejects_stale_text_bad_counts_and_overlapping_or_misplaced_ranges(self):
        before = b"before\nkeep\nlast\n"
        for hunks in (
            "@@ -1,2 +1,2 @@\n-before\n+after\n stale context\n",
            UPDATE.replace("-before", "-stale"),
            UPDATE.replace("-1 +1", "-1,2 +1"),
            UPDATE.replace("-1 +1", "-1 +1,2"),
            UPDATE.replace("-1 +1", "-0 +1"),
            UPDATE.replace("-1 +1", "-1 +2"),
            UPDATE.replace("-1 +1", "-4 +4"),
            UPDATE + "@@ -1 +2 @@\n-before\n+second\n",
            UPDATE + "@@ -2 +1 @@\n-keep\n+second\n",
            "@@ -1 +1 @@\n before\n",
            "@@ -0,0 +0,0 @@\n",
            "",
        ):
            with self.subTest(hunks=hunks), self.assertRaises(WorkerPatchError):
                self.apply(DIRECT + hunks, before)

    def test_rejects_invalid_text_or_misplaced_newline_markers(self):
        for diff, before in (
            (DIRECT + UPDATE, b"\xff"),
            (DIRECT + UPDATE, b"before\x00\n"),
            (DIRECT + UPDATE.replace("after", "\ud800"), b"before\n"),
            (DIRECT + UPDATE.replace("after", "\x00"), b"before\n"),
            (DIRECT + UPDATE.rstrip("\n"), b"before\n"),
            (DIRECT + UPDATE + "\\ No newline at end of file\n", b"before\nnext\n"),
            (DIRECT + UPDATE.replace("+after\n", "+\n\\ No newline at end of file\n"), b"before\n"),
        ):
            with self.subTest(diff=diff, before=before), self.assertRaises(WorkerPatchError):
                self.apply(diff, before)

    def test_enforces_byte_bounds_for_diff_preimage_and_postimage(self):
        insertion = DIRECT + "@@ -0,0 +1 @@\n+"
        edit = insertion + "x" * (MAX_WORKER_DIFF_BYTES - len(insertion) - 1) + "\n"
        self.assertEqual(len(edit.encode()), MAX_WORKER_DIFF_BYTES)
        self.assertTrue(self.apply(edit, b"").endswith(b"\n"))
        with self.assertRaisesRegex(WorkerPatchError, "byte limit"):
            self.apply(edit[:-1] + "x\n", b"")
        with self.assertRaisesRegex(WorkerPatchError, "byte limit"):
            self.apply(insertion + "é" * (MAX_WORKER_DIFF_BYTES // 2) + "\n", b"")
        with self.assertRaisesRegex(WorkerPatchError, "byte limit"):
            self.apply(DIRECT + UPDATE, b"x" * (MAX_WORKER_PATCH_BYTES + 1))
        append = DIRECT + "@@ -1,0 +2 @@\n+y\n"
        before = b"x" * (MAX_WORKER_PATCH_BYTES - 3) + b"\n"
        self.assertEqual(self.apply(append, before), before + b"y\n")
        with self.assertRaisesRegex(WorkerPatchError, "patched file exceeds"):
            self.apply(append, b"x" + before)
        with self.assertRaisesRegex(WorkerPatchError, "byte limit"):
            self.apply(DIRECT + UPDATE, maximum_bytes=16)


class OrdinaryPatchSettlementTests(unittest.TestCase):
    def test_requires_a_changed_output_that_matches_the_writer_receipt(self):
        before = b"before\n"
        child = SimpleNamespace(worker_id="worker-1", worktree=Path("/worker"), write_path=TARGET,
                                productive_spool=Path("/spool"), patch_preimage_sha256=sha256(before).hexdigest())
        receipt = {"path": child.write_path, "call_id": "call-1", "patch_preimage_sha256": child.patch_preimage_sha256,
                   "request_sha256": "a" * 64, "diff_sha256": "b" * 64, "content_sha256": child.patch_preimage_sha256}
        host = {"worker_id": child.worker_id, "worktree": str(child.worktree), "spool": str(child.productive_spool),
                "observations": [{"stage": "writer-output", "observation": receipt}]}
        workers = {child.worker_id: {"host": host}}
        with patch.object(ordinary_runtime, "read_pool_patch_file", return_value=before) as read_output:
            with self.assertRaisesRegex(NativePoolTransactionError, "ordinary-patch-output-unchanged"):
                ordinary_runtime._read_productive_output(child, workers)
            read_output.assert_not_called()

        after = b"after\n"
        receipt["content_sha256"] = sha256(after).hexdigest()
        with patch.object(ordinary_runtime, "read_pool_patch_file", return_value=after) as read_output:
            self.assertTrue(ordinary_runtime._read_productive_output(child, workers))
            read_output.assert_called_once_with(child.worktree, child.write_path)
