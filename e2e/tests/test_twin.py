"""Twin plane proof: fixture rows into a released `twinning --port 0`, checked and sealed."""

from __future__ import annotations

import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path

from e2e import leaks, pgclient
from e2e.harness import CREATED, E2ETestCase, Workspace, expected_changes, source, tree_bytes

TABLE = "public.loans"


def listening_ports(pid: int) -> list[int]:
    """Ports one process listens on, asked of the operating system."""
    if platform.system() == "Linux":
        inodes = set()
        for handle in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(handle)
            except OSError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        ports = []
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            for line in Path(table).read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and fields[9] in inodes:
                    ports.append(int(fields[1].rsplit(":", 1)[1], 16))
        return ports
    done = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN", "-Fn"],
                          capture_output=True, text=True)
    return [int(line.rsplit(":", 1)[1]) for line in done.stdout.splitlines() if line.startswith("n")]


def constraint(name: str, rule: str) -> str:
    return f"""constraint_set_id: e2e.twin.{name}
bindings:
  {TABLE}:
    key_fields:
      - loan_id
rules:
  - id: {name.upper()}
    severity: error
    binding: {TABLE}
{rule}
"""


CONSTRAINTS = {
    "keys": constraint("keys", "    op: not_null\n    columns:\n      - loan_id\n      - balance"),
    "notes": constraint("notes", "    op: not_null\n    columns:\n      - notes"),
    "ceiling": constraint("ceiling", "    op: predicate\n    expr:\n      lt:\n        - column: balance\n        - 100000"),
    # Compares text with a number, which verify refuses to evaluate.
    "refused": constraint("refused", "    op: predicate\n    expr:\n      gt:\n        - column: borrower\n        - 5"),
}


class TwinPipeline(E2ETestCase):
    def setUp(self):
        self.ws = Workspace("twin")
        self.expected = expected_changes()
        columns = ", ".join(
            "loan_id TEXT PRIMARY KEY" if name == "loan_id" else
            "balance NUMERIC" if name == "balance" else f"{name} TEXT" for name in source.COLUMNS)
        self.ws.write("schema.sql", f"CREATE TABLE {TABLE} ({columns});\n")
        for name, text in CONSTRAINTS.items():
            self.ws.write(f"{name}.yaml", text)
            # The seam under test: what `verify compile` writes is what twinning must load.
            self.expect(self.ws.run("verify", "compile", f"{name}.yaml", "--out", f"{name}.verify.json"), 0)

    def load_twin(self, name: str, explicit: bool = False, rows: list | None = None) -> dict:
        """Serve a twin on an ephemeral port, load rows, try a duplicate key, stop it.

        `explicit` is a positive control: it prints raw values on purpose, under its own
        file names and witness ledger. `rows` defaults to all the new rows.
        """
        rows = source.new_rows() if rows is None else rows
        label = f"{name}-explicit" if explicit else name
        out_path, err_path = self.ws.root / f"{label}.stdout", self.ws.root / f"{label}.stderr"
        with out_path.open("wb") as out, err_path.open("wb") as err:
            twin = subprocess.Popen(
                [str(self.ws.bin / "twinning"), "postgres", "--schema", "schema.sql", "--verify", f"{name}.verify.json",
                 "--port", "0", "--serve", "--report", f"{label}.report.json", "--snapshot", f"{label}.snapshot.twin",
                 "--json", *(["--explicit"] if explicit else [])],
                cwd=self.ws.root, env=self.ws.env(control=explicit), stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 30
            while not (ports := listening_ports(twin.pid)):
                self.assertIsNone(twin.poll(), f"twinning exited: {out_path.read_bytes()!r} {err_path.read_bytes()!r}")
                self.assertLess(time.monotonic(), deadline, "twinning never listened")
                time.sleep(0.05)
            self.assertEqual(len(ports), 1, ports)
            client = pgclient.Connection("127.0.0.1", ports[0])
            client.query("BEGIN")
            for values in rows:
                client.insert(TABLE, list(source.COLUMNS),
                              [None if value is None else source.cell_text(value) for value in values])
            client.query("COMMIT")
            with self.assertRaisesRegex(pgclient.PgError, "C23505") as duplicate:
                client.insert(TABLE, ["loan_id"], [source.CANARY_LOAN_ID])
            client.close()
            while_serving = out_path.read_bytes() + err_path.read_bytes()
            twin.send_signal(signal.SIGINT)
            code = twin.wait(timeout=30)
        finally:
            if twin.poll() is None:
                twin.kill()
                twin.wait()
        report = json.loads(out_path.read_bytes())
        self.assertEqual(report["port"], ports[0], "the report must name the port the system assigned")
        self.assertEqual(report["tables"][TABLE]["rows"], len(rows))
        report_file = self.ws.read(f"{label}.report.json")
        self.assertEqual(json.loads(report_file), report, "--report and --json must say the same")
        return {"code": code, "report": report, "stdout": out_path.read_bytes(), "stderr": err_path.read_bytes(),
                "report_file": report_file, "label": label, "verify_artifact": f"{name}.verify.json",
                "while_serving": while_serving, "duplicate_error": str(duplicate.exception).encode()}

    def seal_and_verify(self, run: dict) -> bytes:
        evidence = f"evidence/{run['label']}"
        self.expect(self.ws.run("pack", "seal", f"{run['label']}.report.json", run["verify_artifact"],
                                "--out", evidence, "--created", CREATED), 0)
        verified = self.expect(self.ws.run("pack", "verify", evidence, "--json"), 0)
        self.assertEqual(verified.json()["outcome"], "OK")
        self.assertEqual(self.ws.read(f"{evidence}/{run['label']}.report.json"), run["report_file"],
                         "the sealed member must be the report as written")
        return tree_bytes(self.ws.root / evidence)

    def surfaces(self, run: dict) -> dict[str, bytes]:
        """Every place the embedded verify report leaves the twin, and what pack keeps of it."""
        return {"stdout": run["stdout"], "report file": run["report_file"], "sealed pack": self.seal_and_verify(run)}

    def assert_report_surfaces_redacted(self, case: str, default: dict, explicit: dict,
                                        hidden: tuple[str, ...]) -> None:
        """No canary on any default surface. The control is the same surface of an --explicit
        run, which must show every canary in `hidden`: each is something the default run held
        and had to keep off that surface."""
        default_surfaces, explicit_surfaces = self.surfaces(default), self.surfaces(explicit)
        for surface, text in default_surfaces.items():
            with self.subTest(surface=surface):
                shown = {canary for canary, _ in leaks.find(explicit_surfaces[surface], source.CANARIES)}
                self.assertEqual(set(hidden) - shown, set(), f"{surface}: --explicit did not show these")
                self.assert_redacted(f"twin {surface}, {case}", text, explicit_surfaces[surface])

    def assert_diagnostics_redacted(self, case: str, run: dict) -> None:
        """stderr and the duplicate-key error carry no verify report, so --explicit cannot be
        their control. A snapshot, which is the committed data, shows only that the detector
        sees these canaries. The witness ledger is checked the same way."""
        snapshot = self.ws.read(f"{run['label']}.snapshot.twin")
        self.assert_redacted(f"twin stderr and duplicate-key error ({case})",
                             run["stderr"] + b"\n" + run["duplicate_error"], snapshot)
        self.assert_redacted(f"witness ledger (twin, {case})", self.ws.read("witness.jsonl"), snapshot)

    def test_port_zero_twin_with_passing_and_failing_constraints(self):
        passing = self.load_twin("keys")
        self.known("twinning-port-zero-no-readiness", passing["while_serving"] == b"", passing["while_serving"][:300])
        self.assertEqual(passing["code"], 0)
        self.assertEqual(passing["report"]["verify"]["outcome"], "PASS")
        passing_pack = self.seal_and_verify(passing)

        # The rows with blank notes, from the source rows. By default each key is replaced by
        # an ordinal ref, numbered in the order reported; --explicit keeps the raw key.
        blank = self.expected["blank_notes"]
        failing, raw = self.load_twin("notes"), self.load_twin("notes", explicit=True)
        for run, keys in ((failing, [f"redacted:ref:k{n}" for n in range(1, len(blank) + 1)]), (raw, blank)):
            self.assertEqual(run["code"], 1)
            self.assertEqual(run["report"]["verify"]["outcome"], "FAIL")
            result = run["report"]["verify"]["results"][0]
            self.assertEqual(result["violation_count"], len(blank))
            self.assertEqual([a["key"]["loan_id"] for a in result["affected"]], keys)
        failing_pack = self.seal_and_verify(failing)
        raw_surfaces = self.surfaces(raw)
        failing_surfaces = {"stdout": failing["stdout"], "report file": failing["report_file"], "sealed pack": failing_pack}
        # These keys are not canaries, and short enough to turn up inside a hash, so each is
        # looked for as a whole JSON string.
        for surface, text in failing_surfaces.items():
            for key in blank:
                self.assertIn(json.dumps(key).encode(), raw_surfaces[surface], f"{surface}: control")
                self.assertNotIn(json.dumps(key).encode(), text, f"{surface}: raw key in default output")

        # Control: a snapshot is the committed data itself, so it must contain canaries.
        snapshot = self.ws.read("keys.snapshot.twin")
        for name, run, evidence in (("passing", passing, passing_pack), ("failing on blank notes", failing, failing_pack)):
            self.assert_redacted(
                f"twin report, stderr, duplicate-key error and sealed pack ({name})",
                run["stdout"] + run["stderr"] + run["duplicate_error"] + evidence, snapshot)
        self.assert_redacted("witness ledger (twin)", self.ws.read("witness.jsonl"), snapshot)

    def test_embedded_verify_redacts_a_failing_row(self):
        run, raw = self.load_twin("ceiling"), self.load_twin("ceiling", explicit=True)
        # Only the canary row is over the ceiling.
        self.assertEqual(self.expected["over_ceiling"], [source.CANARY_LOAN_ID])
        for each, key, value in ((run, "redacted:ref:k1", "redacted:ref:v1"),
                                 (raw, source.CANARY_LOAN_ID, float(source.CANARY_AMOUNT_NEW))):
            self.assertEqual(each["code"], 1)
            result = each["report"]["verify"]["results"][0]
            self.assertEqual(result["violation_count"], len(self.expected["over_ceiling"]))
            self.assertEqual(result["affected"], [
                {"binding": TABLE, "field": "balance", "key": {"loan_id": key}, "value": value}])
        self.assert_report_surfaces_redacted("failing check on the canary row", run, raw,
                                             (source.CANARY_LOAN_ID, str(source.CANARY_AMOUNT_NEW)))
        self.assert_diagnostics_redacted("failing check", run)

    def test_embedded_verify_redacts_a_refused_check(self):
        # A refusal names the row it stopped at, the first by key. With only the canary row
        # loaded, that is the canary row.
        only_canary = [row for row in source.new_rows() if row[0] == source.CANARY_LOAN_ID]
        self.assertEqual(len(only_canary), 1)
        run = self.load_twin("refused", rows=only_canary)
        raw = self.load_twin("refused", explicit=True, rows=only_canary)
        for each, key in ((run, "redacted:ref:k1"), (raw, source.CANARY_LOAN_ID)):
            report = each["report"]
            self.assertEqual((each["code"], report["outcome"], report["verify"]["outcome"]), (2, "REFUSAL", "REFUSAL"))
            self.assertEqual(report["verify"]["results"], [])
            refusal = report["verify"]["refusal"]
            self.assertEqual(refusal["code"], "E_BAD_EXPR")
            self.assertEqual(refusal["detail"]["field"], "borrower")
            self.assertEqual(refusal["detail"]["key"], {"loan_id": key})
        self.assert_report_surfaces_redacted("refused check on the canary row", run, raw, (source.CANARY_LOAN_ID,))
        self.assert_diagnostics_redacted("refused check", run)
