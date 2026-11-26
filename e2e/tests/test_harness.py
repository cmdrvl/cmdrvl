"""The suite's own checks must be able to fail. These need no spine binaries."""

from __future__ import annotations

import base64
import json
import unittest
import urllib.parse

from e2e import harness, leaks
from e2e.harness import E2ETestCase, source

TEXT = source.CANARY_BORROWER
NUMBER = str(source.CANARY_AMOUNT_OLD)


class DetectorTests(unittest.TestCase):
    def views(self, data: bytes, canary: str) -> set[str]:
        return {view for found, view in leaks.find(data, (canary,)) if found == canary}

    def test_each_encoding_is_seen(self):
        planted = {
            "plain": TEXT.upper().encode(),
            "percent": urllib.parse.quote(TEXT).encode(),
            "json-escape": "".join(f"\\u{ord(c):04x}" for c in TEXT).encode(),
            "base64": base64.b64encode(b"prefix " + TEXT.encode() + b" suffix"),
            "hex": TEXT.encode().hex().encode(),
        }
        for view, data in planted.items():
            with self.subTest(view=view):
                self.assertIn(view, self.views(b'{"x": "' + data + b'"}', TEXT))

    def test_base64_is_seen_at_every_alignment(self):
        for padding in range(4):
            with self.subTest(padding=padding):
                data = b"a" * padding + base64.b64encode(TEXT.encode())
                self.assertIn("base64", self.views(data, TEXT))

    def test_numeric_rewrites_are_seen(self):
        for form in ("918273645.19", "918,273,645.19", "918_273_645", "91827364519", "9.1827364519e8", "$918273645"):
            with self.subTest(form=form):
                self.assertTrue(leaks.find(f"value={form};".encode(), (NUMBER,)))

    def test_unrelated_output_is_clean(self):
        data = b'{"hash":"blake3:9bdc1f382fd6800f96f5bbdae8372af695f112e08b2ec10fa27c11036b15841a","total":90909840.46}'
        self.assertEqual(leaks.find(data, source.CANARIES), [])

    def test_every_canary_is_found_when_planted(self):
        for canary in source.CANARIES:
            with self.subTest(canary=canary):
                self.assertTrue(leaks.find(f"noise {canary} noise".encode(), source.CANARIES))


class AssertionTests(E2ETestCase):
    def test_leak_fails(self):
        with self.assertRaisesRegex(AssertionError, "canary visible"):
            self.assert_redacted("planted", TEXT.encode(), TEXT.encode())

    def test_dead_control_fails_even_when_output_is_clean(self):
        with self.assertRaisesRegex(AssertionError, "positive control did not fire"):
            self.assert_redacted("planted", b"clean", b"also clean")

    def test_empty_capture_fails(self):
        with self.assertRaisesRegex(AssertionError, "nothing was captured"):
            self.assert_redacted("planted", b"", TEXT.encode())

    def test_changed_known_failure_fails_and_is_not_recorded(self):
        identifier = next(iter(harness.KNOWN_FAILURES))
        before = list(harness.OBSERVED_KNOWN.get(identifier, []))
        with self.assertRaisesRegex(AssertionError, "KNOWN FAILURE CHANGED"):
            self.known(identifier, False, "behaves correctly now")
        self.assertEqual(harness.OBSERVED_KNOWN.get(identifier, []), before)

    def test_unregistered_known_failure_is_an_error(self):
        with self.assertRaises(KeyError):
            self.known("not-filed", True, None)

    def test_registry_entries_name_a_bead(self):
        for identifier, entry in harness.KNOWN_FAILURES.items():
            with self.subTest(identifier):
                self.assertRegex(entry["repo"], r"^cmdrvl/[a-z0-9-]+$")
                self.assertRegex(entry["bead"], r"^bd-[a-z0-9]+$")
                self.assertTrue(entry["summary"])


class FixtureTests(unittest.TestCase):
    def test_committed_csv_matches_the_source_rows(self):
        for name, rows in (("old", source.OLD_ROWS), ("new", source.new_rows())):
            with self.subTest(name):
                self.assertEqual((harness.FIXTURES / f"{name}.csv").read_bytes(), source.messy_csv(rows))

    def test_source_rows_exercise_what_the_pipelines_assert(self):
        expected = harness.expected_changes()
        self.assertEqual(expected["numeric_cells_changed"], 2)
        self.assertEqual(expected["categorical_transitions"], 1)
        self.assertEqual(expected["over_ceiling"], [source.CANARY_LOAN_ID])
        self.assertEqual(len(expected["blank_notes"]), 2)


if __name__ == "__main__":
    unittest.main()
