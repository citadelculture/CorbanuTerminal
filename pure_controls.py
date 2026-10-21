#!/usr/bin/env python3
"""Offline controls only: no network, product tooling, builds or native tests."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import bazel
from controller import admitted, digest, write
from worker import check_scope, link_records, safe_extract, snapshot_generated


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def link_fixture(self, target="/never-open-this-fixture"):
        name = "fixture/link"
        p = self.root / name
        p.parent.mkdir()
        p.symlink_to(target)
        record = {"path": name, "mode": "120000", "blob": "a" * 40, "targetSha256": hashlib.sha256(target.encode()).hexdigest(), "targetBytes": len(target.encode())}
        row = ("120000 blob " + "a" * 40 + "\t" + name + "\0").encode()
        return p, record, row

    def test_known_external_link_never_opened_or_resolved(self):
        p, expected, row = self.link_fixture()
        with patch.object(Path, "open", side_effect=AssertionError("open forbidden")), patch.object(Path, "resolve", side_effect=AssertionError("resolve forbidden")):
            self.assertEqual(link_records(self.root, row, [expected]), [expected])

    def test_changed_link_target_is_rejected(self):
        p, expected, row = self.link_fixture()
        p.unlink()
        p.symlink_to("/other-inert-target")
        with self.assertRaisesRegex(RuntimeError, "symlink_identity_mismatch"):
            link_records(self.root, row, [expected])

    def test_link_materialized_as_regular_file_is_rejected(self):
        p, expected, row = self.link_fixture()
        p.unlink()
        p.write_text("/never-open-this-fixture")
        with self.assertRaisesRegex(RuntimeError, "symlink_replaced_by_file"):
            link_records(self.root, row, [expected])

    def test_unknown_or_missing_link_is_rejected(self):
        p, expected, row = self.link_fixture()
        with self.assertRaisesRegex(RuntimeError, "unexpected_tracked_symlink"):
            link_records(self.root, row, [])
        with self.assertRaisesRegex(RuntimeError, "inventory_mismatch"):
            link_records(self.root, b"", [expected])

    def archive(self, name, kind=None, linkname=""):
        path = self.root / "tool.tar"
        with tarfile.open(path, "w") as t:
            member = tarfile.TarInfo(name)
            if kind:
                member.type = kind
                member.linkname = linkname
                t.addfile(member)
            else:
                member.size = 2
                t.addfile(member, io.BytesIO(b"ok"))
        return path

    def test_archive_regular_file_is_preserved(self):
        safe_extract(self.archive("tool/bin/just"), self.root / "out")
        self.assertEqual((self.root / "out/tool/bin/just").read_bytes(), b"ok")

    def test_archive_parent_escape_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "path_escape"):
            safe_extract(self.archive("../outside"), self.root / "out")

    def test_archive_external_symlink_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "absolute_link"):
            safe_extract(self.archive("link", tarfile.SYMTYPE, "/outside"), self.root / "out")

    def test_archive_escaping_hardlink_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "link_escape"):
            safe_extract(self.archive("link", tarfile.LNKTYPE, "../outside"), self.root / "out")

    def test_generated_snapshot_rejects_symlink(self):
        source = self.root / "source"
        source.mkdir()
        (source / "MODULE.bazel.lock").symlink_to("/never-open")
        with self.assertRaisesRegex(RuntimeError, "unsafe_generated_file"):
            snapshot_generated(source, self.root, "result")

    def test_generated_snapshots_preserve_exact_bytes(self):
        source = self.root / "source"
        (source / "codex-rs").mkdir(parents=True)
        for name in ("MODULE.bazel.lock", "codex-rs/Cargo.lock"):
            (source / name).write_bytes(b"public generated output\n")
        records = snapshot_generated(source, self.root, "captured")
        for name in records:
            self.assertEqual((source / name).read_bytes(), (self.root / "captured" / name).read_bytes())

    def test_generated_snapshot_rejects_symlink_parent(self):
        source = self.root / "source"
        source.mkdir()
        (source / "MODULE.bazel.lock").write_bytes(b"public")
        (source / "codex-rs").symlink_to("/never-open-directory")
        with self.assertRaisesRegex(RuntimeError, "subject_parent_not_directory"):
            snapshot_generated(source, self.root, "captured")

    def test_only_expected_changed_files_are_accepted(self):
        check_scope(["MODULE.bazel.lock"], ["MODULE.bazel.lock"])
        with self.assertRaisesRegex(RuntimeError, "unexpected_tracked_source_delta"):
            check_scope(["other.rs"], ["MODULE.bazel.lock"])

    def test_bazel_shim_rejects_build_remote_and_wrong_cache(self):
        for args in (["build", "//..."], ["mod", "deps", "--lockfile_mode=update", "--config=buildbuddy-generic"], ["--output_user_root=/other", "mod", "deps", "--lockfile_mode=error"]):
            with self.assertRaises(RuntimeError):
                bazel.command(args, self.root)

    def test_bazel_shim_uses_owned_batch_and_exact_lock_mode(self):
        for mode in ("update", "error"):
            command = bazel.command(["mod", "deps", "--lockfile_mode=" + mode], self.root)
            self.assertIn("--batch", command)
            self.assertIn("--output_user_root=" + str(self.root / "bazel-state"), command)
            self.assertEqual(command.count("--lockfile_mode=" + mode), 1)
            self.assertNotIn("--config=ci", command)

    def test_unapproved_and_hash_mismatched_admission_rejected(self):
        write(self.root / "packet-manifest.json", {"files": []})
        with self.assertRaisesRegex(RuntimeError, "method_not_admitted"):
            admitted(self.root, {"approved": False}, {"files": []})
        with self.assertRaisesRegex(RuntimeError, "manifest_mismatch"):
            admitted(self.root, {"approved": True, "reviewReceiptSha256": "a" * 64, "packetManifestSha256": "b" * 64}, {"files": []})
        admitted(self.root, {"approved": True, "reviewReceiptSha256": "a" * 64, "packetManifestSha256": digest(self.root / "packet-manifest.json")}, {"files": []})


if __name__ == "__main__":
    unittest.main(verbosity=2)
