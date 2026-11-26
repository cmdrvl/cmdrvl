"""Boundary plane proof: released veil and airlock, on synthetic data and loopback only.

boundary-detectors is a library with no binary of its own. It is exercised here
only through the releases of airlock (gate screening) and veil.
"""

from __future__ import annotations

import base64
import http.client
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from e2e.harness import E2ETestCase, Workspace, source, tree_bytes

RULES = """constraint_set_id: e2e.boundary
bindings:
  input:
    key_fields:
      - loan_id
rules:
  - id: BALANCE_CEILING
    severity: error
    binding: input
    op: predicate
    expr:
      lt:
        - column: balance
        - 100000
"""
PAIR = "protected/old.csv protected/new.csv --key loan_id"


class VeilGuard(E2ETestCase):
    ws: Workspace

    @classmethod
    def setUpClass(cls):
        ws = cls.ws = Workspace("veil")
        for name in ("old.csv", "new.csv"):
            ws.write(f"protected/{name}", ws.read(f"data/{name}"))
        ws.write(".veil.toml", '[sensitivity]\nprotected = ["protected/**"]\n')
        ws.write(f"named/{source.CANARY_LOAN_ID}.csv", ws.read("data/old.csv"))
        ws.write("variant/dropped-column.csv",
                 ws.read("data/old.csv").replace(source.CANARY_HEADER.encode(), b"other_column"))
        ws.write("rules.yaml", RULES)
        ws.write("gold.jsonl", json.dumps(
            {"entity": "00018", "field": "balance", "expected": "1", "compare_as": "number"}) + "\n")
        compiled = ws.run("verify", "compile", "rules.yaml", "--out", "rules.verify.json")
        assert compiled.code == 0, compiled.blob

    def decide(self, tool: str, tool_input: dict) -> str:
        """veil's PreToolUse answer for one tool call: 'deny', 'allow', or '' for no decision."""
        payload = {"session_id": "e2e", "cwd": str(self.ws.root), "hook_event_name": "PreToolUse",
                   "tool_name": tool, "tool_input": tool_input}
        run = self.expect(self.ws.run("veil", stdin=json.dumps(payload).encode(),
                                      extra_env={"VEIL_HARNESS": "plain"}), 0)
        if not run.stdout.strip():
            return ""
        return run.json()["hookSpecificOutput"]["permissionDecision"]

    def test_raw_reads_of_protected_files_are_denied(self):
        """Also the control for every 'not denied' answer below: this hook does deny."""
        for command in ("cat protected/new.csv", "head -3 protected/new.csv"):
            with self.subTest(command=command):
                self.assertEqual(self.decide("Bash", {"command": command}), "deny")
        self.assertEqual(self.decide("Read", {"file_path": str(self.ws.root / "protected/new.csv")}), "deny")

    def test_authorized_tools_run_on_protected_files_without_leaking(self):
        ws = self.ws
        named_scan = ws.run("vacuum", "named", control=True)
        named_hash = ws.run("hashbytes", "--algorithm", "blake3", stdin=named_scan.stdout, control=True)
        named_print = ws.run("fingerprint", "--fp", "csv.v0", stdin=named_hash.stdout, control=True)
        named_lock = ws.run("lock", "--dataset-id", "e2e.named", stdin=named_print.stdout, control=True)

        scan = ws.run("vacuum", "protected")
        hashed = ws.run("hashbytes", "--algorithm", "blake3", stdin=scan.stdout)
        printed = ws.run("fingerprint", "--fp", "csv.v0", stdin=hashed.stdout)
        locked = ws.run("lock", "--dataset-id", "e2e.protected", stdin=printed.stdout)
        chain = "vacuum protected | hashbytes --algorithm blake3 | fingerprint --fp csv.v0 | lock --dataset-id e2e.protected"
        self.assertNotEqual(self.decide("Bash", {"command": chain}), "deny")
        for name, run, control in (("vacuum", scan, named_scan), ("hashbytes", hashed, named_hash),
                                   ("fingerprint", printed, named_print), ("lock", locked, named_lock)):
            with self.subTest(tool=name):
                self.expect(run, 0)
                self.assert_redacted(f"veil-authorized {name}", run.blob, control.blob)

        # (command veil is asked about, expected exit, control command that does print a canary)
        dropped = "shape protected/old.csv variant/dropped-column.csv --key loan_id --delimiter comma --json"
        cases = (
            (dropped, 0, f"{dropped} --explicit"),
            (f"shape {PAIR} --delimiter comma --json", 0, f"{dropped} --explicit"),
            (f"rvl {PAIR} --json", 1, f"rvl {PAIR} --json --explicit"),
            (f"rvl {PAIR} --non-numeric --json", 1, f"rvl {PAIR} --json --explicit"),
            ("profile stats protected/new.csv --json", 0, "profile stats protected/new.csv --json --explicit"),
            ("fingerprint peek protected/new.csv", 0, None),
            ("verify run rules.verify.json --bind input=protected/new.csv --json", 1,
             "verify run rules.verify.json --bind input=protected/new.csv --json --explicit"),
            ("benchmark protected/new.csv --assertions gold.jsonl --key loan_id --json", 1,
             f"rvl {PAIR} --json --explicit"),
        )
        for command, code, control_command in cases:
            with self.subTest(command=command):
                self.assertNotEqual(self.decide("Bash", {"command": command}), "deny")
                run = self.expect(ws.run(*command.split()), code)
                if control_command is None:
                    control = named_print.blob
                else:
                    control = ws.run(*control_command.split(), control=True).blob
                self.assert_redacted(f"veil-authorized: {command}", run.blob, control)
        # Control for the ledger, which records input paths: a run on a canary-named file.
        named = f"named/{source.CANARY_LOAN_ID}.csv"
        ws.run("shape", named, named, "--key", "loan_id", "--delimiter", "comma", "--json", control=True)
        self.assert_redacted("witness ledger (veil-authorized tools)", ws.witness.read_bytes(),
                             ws.control_witness.read_bytes())

    def test_explicit_on_protected_files(self):
        commands = (
            f"rvl {PAIR} --explicit",
            f"rvl {PAIR} --explicit=true",
            f"shape --explicit {PAIR}",
            "profile stats protected/new.csv --explicit",
            "verify run rules.verify.json --bind input=protected/new.csv --explicit",
        )
        decisions = {command: self.decide("Bash", {"command": command}) for command in commands}
        # Required behaviour is "deny" for each. The recorded failure is that none is denied.
        self.known("veil-allows-explicit-on-protected",
                   all(answer != "deny" for answer in decisions.values()), decisions)


class Upstream:
    """A loopback stand-in for a model provider that records every byte it receives."""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        self.client_has_first_event = threading.Event()
        self.second_event_waits: list[bool] = []
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                upstream.received.append(self.path.encode() + b"\n" + body)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for index, event in enumerate((b"data: one\n\n", b"data: two\n\n")):
                    if index:
                        upstream.second_event_waits.append(upstream.client_has_first_event.wait(10))
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Gate:
    """A released `airlock gate --mode policy-proxy` in front of an Upstream."""

    def __init__(self, ws: Workspace, name: str, policy: str, upstream: Upstream, control: bool = False) -> None:
        ws.write(f"{name}/policy.yaml", policy)
        self.directory = ws.root / name
        self.requests = 0
        self.stderr_path = self.directory / "stderr.txt"
        self.stdout_path = self.directory / "stdout.txt"
        with self.stdout_path.open("wb") as out, self.stderr_path.open("wb") as err:
            self.process = subprocess.Popen(
                [str(ws.bin / "airlock"), "gate", "--mode", "policy-proxy", "--policy", f"{name}/policy.yaml",
                 "--upstream", f"http://127.0.0.1:{upstream.server.server_port}", "--listen", "127.0.0.1:0",
                 "--out-dir", f"{name}/receipts"],
                cwd=ws.root, env=ws.env(control), stdout=out, stderr=err)
        deadline = time.monotonic() + 30
        marker = "airlock gate listening on 127.0.0.1:"
        while True:
            lines = [line for line in self.stderr_path.read_text().splitlines(keepends=True) if line.endswith("\n")]
            found = [line for line in lines if line.startswith(marker)]
            if found:
                self.port = int(found[0][len(marker):].strip())
                return
            if self.process.poll() is not None or time.monotonic() > deadline:
                self.process.kill()
                raise AssertionError(f"gate did not start: {self.stderr_path.read_text()!r}")
            time.sleep(0.05)

    def post(self, body: bytes, on_first_bytes: threading.Event | None = None) -> tuple[int, bytes]:
        self.requests += 1
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            connection.request("POST", "/v1/messages", body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            head = b""
            if on_first_bytes is not None and response.status == 200:
                head = response.read1(len(b"data: one\n\n"))
                on_first_bytes.set()
            return response.status, head + response.read()
        finally:
            connection.close()

    def receipts(self) -> bytes:
        """The gate writes a receipt after answering, so wait for one per request."""
        directory = self.directory / "receipts"
        deadline = time.monotonic() + 20
        while True:
            files = [path for path in directory.rglob("*.json") if path.stat().st_size]
            if len(files) >= self.requests:
                return tree_bytes(directory)
            if time.monotonic() > deadline:
                raise AssertionError(f"{len(files)} receipts for {self.requests} requests")
            time.sleep(0.05)

    def stdio(self) -> bytes:
        return self.stdout_path.read_bytes() + self.stderr_path.read_bytes()

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


def policy(policy_id: str, forbidden_keys=(), patterns=(), detectors=()) -> str:
    # JSON is valid YAML, which avoids hand-quoting the patterns.
    return json.dumps({
        "policy_id": policy_id, "version": "airlock.v0",
        "allowed_keys": [{"key_path": "messages"}],
        "forbidden_keys": list(forbidden_keys),
        "forbidden_patterns": [{"pattern": p, "description": "synthetic canary"} for p in patterns],
        "derived_text_paths": [],
        "claim_levels": ["BOUNDARY_FAILED", "RAW_DOCUMENT_ABSENT", "STRICT_TELEMETRY_ONLY"],
        "detectors": list(detectors),
    })


def message(content) -> bytes:
    return json.dumps({"messages": [{"role": "user", "content": content}]}).encode()


def blocked_requests() -> dict[str, bytes]:
    tape = (Path(__file__).resolve().parents[1] / "fixtures" / "new.csv").read_text(encoding="utf-8-sig")
    return {
        "borrower": message(source.CANARY_BORROWER),
        "loan id": message(source.CANARY_LOAN_ID),
        "email": message(source.CANARY_EMAIL),
        "base64": message(base64.b64encode(source.CANARY_NOTE.encode()).decode()),
        "hex": message(source.CANARY_NOTE.encode().hex()),
        "whole messy csv": message(tape),
        # messages[1].content as an object, the shape named in the bead's background.
        "object content": json.dumps({"messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": {"borrower": source.CANARY_BORROWER}}]}).encode(),
        "forbidden key": json.dumps({"messages": [{"role": "user", "content": "ok"}], "raw_rows": []}).encode(),
        "detector: US SSN": message("SSN 123-45-6789"),
        "unparseable body": b"{not json " + source.CANARY_NOTE.encode(),
    }


class AirlockGate(E2ETestCase):
    def setUp(self):
        self.ws = Workspace("gate")
        self.upstream = Upstream()
        self.addCleanup(self.upstream.close)

    def gate(self, name: str, text: str, upstream: Upstream | None = None, control: bool = False) -> Gate:
        gate = Gate(self.ws, name, text, upstream or self.upstream, control)
        self.addCleanup(gate.close)
        return gate

    def strict(self, policy_id: str = "e2e-egress", forbidden_keys=("raw_rows",)) -> str:
        return policy(policy_id, forbidden_keys, (r"ZQX[-A-Za-z0-9.]+", r"zqx\.canary\.[0-9]+@example\.invalid"),
                      ("secrets", "pii", "tabular"))

    def test_clean_turn_streams_through(self):
        gate = self.gate("clean", self.strict())
        request = json.dumps({"stream": True, "messages": [{"role": "user", "content": "Summarize this status."}]})
        status, body = gate.post(request.encode(), on_first_bytes=self.upstream.client_has_first_event)
        self.assertEqual((status, body), (200, b"data: one\n\ndata: two\n\n"))
        # The upstream held the second event until the client had the first, so nothing buffered the stream.
        self.assertEqual(self.upstream.second_event_waits, [True])
        self.assertEqual(len(self.upstream.received), 1)

    def test_blocked_turns_never_reach_upstream_and_are_not_echoed(self):
        gate = self.gate("strict", self.strict())
        refusals = []
        for name, request in blocked_requests().items():
            with self.subTest(request=name):
                status, body = gate.post(request)
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body)["code"], "BOUNDARY_FAILED")
                refusals.append(body)
        self.assertEqual(self.upstream.received, [], "a blocked request reached the upstream")

        # Control for the upstream capture: with an empty policy the same bytes arrive and are seen.
        open_upstream = Upstream()
        self.addCleanup(open_upstream.close)
        open_upstream.client_has_first_event.set()
        permissive = self.gate("permissive", policy("e2e-permissive"), open_upstream, control=True)
        status, _ = permissive.post(message(source.CANARY_BORROWER))
        self.assertEqual(status, 200)
        # Then a clean turn through the strict gate shows what its upstream sees by default.
        self.upstream.client_has_first_event.set()
        self.assertEqual(gate.post(message("clean follow-up"))[0], 200)
        self.assert_redacted("airlock gate upstream bytes", b"".join(self.upstream.received),
                             b"".join(open_upstream.received))

        # Control for refusals and receipts: they name the policy and the blocked key path.
        echoing = self.gate("echoing", self.strict(f"e2e-{source.CANARY_LOAN_ID}", (source.CANARY_HEADER,)),
                            control=True)
        status, echoed = echoing.post(json.dumps({"messages": [], source.CANARY_HEADER: 1}).encode())
        self.assertEqual(status, 403)
        self.assert_redacted("airlock gate refusal bodies", b"\n".join(refusals), echoed)
        # The gate's stdio and ledger have no field for request text; they share the receipts' control.
        self.assert_redacted("airlock gate receipts, stdio and witness ledger",
                             gate.receipts() + gate.stdio() + self.ws.witness.read_bytes(), echoing.receipts())
