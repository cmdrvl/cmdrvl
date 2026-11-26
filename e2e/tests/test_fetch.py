"""The downloader must refuse anything it cannot check. No network and no spine binaries."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from e2e import fetch

ASSET = "tool-v1-x86_64-unknown-linux-gnu.tar.gz"


def archive(*names: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in names:
            body = b"#!/bin/sh\necho tool 1\n"
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


class FetchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.out = Path(directory.name)
        (self.out / "bin").mkdir()
        (self.out / "archives").mkdir()
        self.data = archive("dir/tool")
        self.digest = hashlib.sha256(self.data).hexdigest()
        for name, value in (("platform.system", "Linux"), ("platform.machine", "x86_64")):
            patcher = mock.patch(f"e2e.fetch.{name}", return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fetch(self, published: str, pinned: dict | None = None):
        sums = f"{published}  ./dist/{ASSET}\n".encode()
        with mock.patch.object(fetch, "download", lambda url: sums if url.endswith("SHA256SUMS") else self.data), \
                mock.patch.object(fetch, "latest_tag", return_value="v1"):
            return fetch.fetch_one("tool", "tool", self.out, pinned)

    def assert_refused(self, message: str, published: str, pinned: dict | None = None):
        with self.assertRaisesRegex(fetch.FetchError, message):
            self.fetch(published, pinned)
        self.assertEqual(list((self.out / "bin").iterdir()), [], "a refused download must not be installed")

    def test_matching_checksum_installs_and_records_the_version(self):
        entry = self.fetch(self.digest)
        self.assertEqual((entry["tag"], entry["sha256"], entry["version_output"]), ("v1", self.digest, "tool 1"))

    def test_checksum_mismatch_is_refused(self):
        self.assert_refused("does not match SHA256SUMS", "0" * 64)

    def test_pin_with_a_changed_checksum_is_refused(self):
        self.assert_refused("changed since it was pinned", self.digest, {"tag": "v1", "sha256": {ASSET: "1" * 64}})

    def test_pin_without_a_checksum_for_this_asset_is_refused(self):
        self.assert_refused("records no checksum", self.digest, {"tag": "v1", "sha256": {}})

    def test_asset_missing_from_checksums_is_refused(self):
        with self.assertRaisesRegex(fetch.FetchError, "no .tar.gz asset"):
            fetch.pick_asset("tool", ["tool-v1-aarch64-apple-darwin.tar.gz"])

    def test_archive_must_hold_exactly_one_binary(self):
        self.data = archive("a/tool", "b/tool")
        self.assert_refused("expected one file named tool", hashlib.sha256(self.data).hexdigest())

    def test_committed_pin_covers_every_tool_on_the_ci_platform(self):
        pinned = json.loads((Path(fetch.__file__).parent / "tools.pinned.json").read_text())["tools"]
        self.assertEqual(sorted(pinned), sorted(fetch.TOOLS))
        for binary, entry in pinned.items():
            with self.subTest(binary):
                self.assertIn(fetch.pick_asset(binary, list(entry["sha256"])), entry["sha256"])


if __name__ == "__main__":
    unittest.main()
