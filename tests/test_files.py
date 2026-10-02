import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from handshake_evidence_review.files import InputUnavailable, snapshot
from fixtures import pcap


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
        )
        self.base = Path(self.temp.name)
        self.target = self.base / "PRIVATE_CAPTURE"
        self.data = pcap()
        self.target.write_bytes(self.data)

    def tearDown(self):
        self.temp.cleanup()

    def test_regular_snapshot_and_byte_bound(self):
        self.assertEqual(snapshot(str(self.target), 1024), self.data)
        with self.assertRaises(InputUnavailable):
            snapshot(str(self.target), 1)

    def test_leaf_ancestor_symlinks_dotdot_and_nonregular(self):
        leaf = self.base / "link"
        leaf.symlink_to(self.target)
        ancestor = self.base / "alias"
        ancestor.symlink_to(self.base, target_is_directory=True)
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        for path in (
            leaf,
            ancestor / self.target.name,
            self.base / ".." / self.base.name / self.target.name,
            fifo,
            self.base,
            self.base / "absent",
        ):
            with self.assertRaises(InputUnavailable):
                snapshot(str(path), 1024)

    def test_missing_each_platform_flag_and_dirfd(self):
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            value = getattr(os, flag)
            delattr(os, flag)
            try:
                with self.assertRaises(InputUnavailable) as error:
                    snapshot(str(self.target), 1024)
                self.assertEqual(error.exception.code, "snapshot_platform_unsupported")
            finally:
                setattr(os, flag, value)
        with patch("handshake_evidence_review.files.os.supports_dir_fd", set()):
            with self.assertRaises(InputUnavailable) as error:
                snapshot(str(self.target), 1024)
            self.assertEqual(error.exception.code, "snapshot_platform_unsupported")

    def test_changed_descriptor_snapshot_rejected(self):
        original = os.read
        first = [True]

        def changed(fd, n):
            raw = original(fd, n)
            if first[0]:
                first[0] = False
                self.target.write_bytes(self.data + b"x")
            return raw

        with patch("handshake_evidence_review.files.os.read", side_effect=changed):
            with self.assertRaises(InputUnavailable) as error:
                snapshot(str(self.target), 1024)
            self.assertEqual(error.exception.code, "input_changed_during_snapshot")

    def test_invalid_path_and_limits(self):
        for path in ("", None, "PRIVATE\0", "/private/tmp/../PRIVATE"):
            with self.assertRaises(InputUnavailable):
                snapshot(path, 1024)
        for budget in (True, 0, 2**40):
            with self.assertRaises(InputUnavailable):
                snapshot(str(self.target), budget)


if __name__ == "__main__":
    unittest.main()
