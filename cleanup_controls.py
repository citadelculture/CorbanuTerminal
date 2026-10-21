#!/usr/bin/env python3
"""Offline synthetic owned-directory cleanup regression controls only."""
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch
import controller as c


class CleanupControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pr951-cleanup-control-')
        self.parent = Path(self.tmp.name)
        self.root = self.parent / 'pr951-format-12345'
        self.root.mkdir()
        st = self.root.stat()
        self.identity = [st.st_dev, st.st_ino]
        self.progress = {}

    def tearDown(self):
        # Only synthetic test directories; restore read/write to allow fixture teardown.
        for root, dirs, files in os.walk(self.parent, followlinks=False):
            p = Path(root)
            if not p.is_symlink():
                p.chmod(stat.S_IMODE(p.stat().st_mode) | 0o700)
        self.tmp.cleanup()

    def run_cleanup(self, **kwargs):
        return c.remove_owned_state(self.root, self.progress, self.identity, **kwargs)

    def test_old_cleanup_fails_read_only_directory_new_cleanup_removes_it(self):
        self.assertNotEqual(os.geteuid(), 0)
        cache = self.root / 'synthetic-public-tool-cache'
        cache.mkdir()
        (cache / 'payload').write_text('public synthetic bytes')
        cache.chmod(0o555)
        with self.assertRaises(PermissionError):
            shutil.rmtree(self.root)
        self.run_cleanup()
        self.assertFalse(self.root.exists())
        self.assertTrue(self.progress['completed'])
        self.assertEqual(self.progress['directoriesRepaired'], 1)
        self.assertEqual(self.progress['repairedDirectorySample'][0]['path'], 'synthetic-public-tool-cache')

    def test_external_symlink_target_and_hardlinked_file_permissions_unchanged(self):
        outside = self.parent / 'outside'
        outside.mkdir()
        file = outside / 'public-fixture'
        file.write_text('remain');file.chmod(0o444)
        before = file.stat()
        (self.root / 'link-outside').symlink_to(outside, target_is_directory=True)
        os.link(file, self.root / 'hardlink')
        self.run_cleanup()
        after = file.stat()
        self.assertEqual(file.read_text(), 'remain')
        self.assertEqual((before.st_dev, before.st_ino, before.st_mode), (after.st_dev, after.st_ino, after.st_mode))
        self.assertTrue(outside.is_dir())
        self.assertEqual(self.progress['filePermissionsChanged'], 0)
        self.assertEqual(self.progress['symlinksFollowed'], 0)

    def test_root_symlink_rejected_without_touching_target(self):
        self.root.rmdir()
        outside = self.parent / 'outside';outside.mkdir();(outside / 'keep').write_text('keep')
        self.root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):self.run_cleanup()
        self.assertEqual((outside / 'keep').read_text(), 'keep')

    def test_wrong_root_name_refused(self):
        wrong = self.parent / 'foreign-source';wrong.mkdir();(wrong / 'keep').write_text('keep')
        with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_root_name'):
            c.remove_owned_state(wrong, {}, self.identity)
        self.assertTrue((wrong / 'keep').exists())

    def test_wrong_original_inode_refused(self):
        (self.root / 'keep').write_text('keep')
        self.identity[1] += 1
        with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_root_identity'):self.run_cleanup()
        self.assertTrue((self.root / 'keep').exists())

    def test_foreign_owner_refused_before_chmod(self):
        (self.root / 'keep').write_text('keep')
        with patch.object(c.os, 'geteuid', return_value=os.geteuid()+1), patch.object(c.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_foreign_directory'):self.run_cleanup()
            chmod.assert_not_called()
        self.assertTrue((self.root / 'keep').exists())

    def test_deadline_and_entry_bounds_retain_incomplete_progress(self):
        (self.root / 'keep').write_text('keep')
        with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_deadline'):self.run_cleanup(seconds=0)
        with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_entry_bound'):self.run_cleanup(max_entries=1)
        self.assertFalse(self.progress['completed'])
        self.assertTrue((self.root / 'keep').exists())

    def test_permission_repair_failure_is_retained_not_completion(self):
        cache=self.root/'cache';cache.mkdir();(cache/'keep').write_text('keep');cache.chmod(0o555)
        with patch.object(c.os, 'fchmod', side_effect=PermissionError('synthetic refusal')):
            with self.assertRaises(PermissionError):self.run_cleanup()
        self.assertFalse(self.progress['completed'])
        self.assertEqual(self.progress['activeRelativePath'], 'cache')
        self.assertTrue((cache/'keep').exists())

    def test_special_entry_refused(self):
        os.mkfifo(self.root/'synthetic-fifo')
        with self.assertRaisesRegex(RuntimeError, 'owned_cleanup_special_entry'):self.run_cleanup()
        self.assertFalse(self.progress['completed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
