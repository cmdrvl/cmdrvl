"""Twin plane proof: fixture rows into a released `twinning --port 0`, checked and sealed."""

from __future__ import annotations

import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path

from e2e import pgclient
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

    def load_twin(self, name: str) -> dict:
        """Serve a twin on an ephemeral port, load the new rows, try a duplicate key, stop it."""
        out_path, err_path = self.ws.root / f"{name}.stdout", self.ws.root / f"{name}.stderr"
        with out_path.open("wb") as out, err_path.open("wb") as err:
            twin = subprocess.Popen(
                [str(self.ws.bin / "twinning"), "postgres", "--schema", "schema.sql", "--verify", f"{name}.verify.json",
                 "--port", "0", "--serve", "--report", f"{name}.report.json", "--snapshot", f"{name}.snapshot.twin",
                 "--json"], cwd=self.ws.root, env=self.ws.env(), stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 30
            while not (ports := listening_ports(twin.pid)):
                self.assertIsNone(twin.poll(), f"twinning exited: {out_path.read_bytes()!r} {err_path.read_bytes()!r}")
                self.assertLess(time.monotonic(), deadline, "twinning never listened")
                time.sleep(0.05)
            self.assertEqual(len(ports), 1, ports)
            client = pgclient.Connection("127.0.0.1", ports[0])
            client.query("BEGIN")
            for values in source.new_rows():
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
        self.assertEqual(report["tables"][TABLE]["rows"], self.expected["rows"])
        return {"code": code, "report": report, "stdout": out_path.read_bytes(), "stderr": err_path.read_bytes(),
                "while_serving": while_serving, "duplicate_error": str(duplicate.exception).encode()}

    def seal_and_verify(self, name: str) -> bytes:
        self.expect(self.ws.run("pack", "seal", f"{name}.report.json", f"{name}.verify.json",
                                "--out", f"evidence/{name}", "--created", CREATED), 0)
        verified = self.expect(self.ws.run("pack", "verify", f"evidence/{name}", "--json"), 0)
        self.assertEqual(verified.json()["outcome"], "OK")
        return tree_bytes(self.ws.root / "evidence" / name)

    def test_port_zero_twin_with_passing_and_failing_constraints(self):
        passing = self.load_twin("keys")
        self.known("twinning-port-zero-no-readiness", passing["while_serving"] == b"", passing["while_serving"][:300])
        self.assertEqual(passing["code"], 0)
        self.assertEqual(passing["report"]["verify"]["outcome"], "PASS")
        passing_pack = self.seal_and_verify("keys")

        failing = self.load_twin("notes")
        self.assertEqual(failing["code"], 1)
        result = failing["report"]["verify"]["results"][0]
        self.assertEqual(result["violation_count"], len(self.expected["blank_notes"]))
        self.assertEqual(sorted(a["key"]["loan_id"] for a in result["affected"]), self.expected["blank_notes"])
        failing_pack = self.seal_and_verify("notes")

        # Control: a snapshot is the committed data itself, so it must contain canaries.
        snapshot = self.ws.read("keys.snapshot.twin")
        for name, run, evidence in (("passing", passing, passing_pack), ("failing on blank notes", failing, failing_pack)):
            self.assert_redacted(
                f"twin report, stderr, duplicate-key error and sealed pack ({name})",
                run["stdout"] + run["stderr"] + run["duplicate_error"] + evidence, snapshot)
        self.assert_redacted("witness ledger (twin)", self.ws.read("witness.jsonl"), snapshot)

    def test_embedded_verify_redaction_on_the_canary_row(self):
        run = self.load_twin("ceiling")
        self.assertEqual(run["code"], 1)
        result = run["report"]["verify"]["results"][0]
        self.assertEqual(result["violation_count"], len(self.expected["over_ceiling"]))
        affected = result.pop("affected")
        want = [{"binding": TABLE, "field": "balance", "key": {"loan_id": source.CANARY_LOAN_ID},
                 "value": float(source.CANARY_AMOUNT_NEW)}]
        evidence = self.seal_and_verify("ceiling")
        # Required: redacted refs, as standalone verify prints (test_09 of the tabular pipeline).
        self.known("twinning-embedded-verify-raw-values",
                   affected == want and source.CANARY_LOAN_ID.encode() in evidence, affected)
        # Apart from `affected`, the report must be clean.
        self.assert_redacted("twin report except verify affected rows",
                             json.dumps(run["report"]).encode() + run["stderr"], run["stdout"])
