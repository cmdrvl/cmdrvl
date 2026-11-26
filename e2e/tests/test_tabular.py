"""Tabular spine proof: the released tools chained over messy CSV, XLSX and Parquet."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from e2e.harness import (
    CELL_CANARIES, CREATED, FIXTURES, FORMATS, E2ETestCase, Workspace, expected_changes, source, tree_bytes)

ALGORITHMS = ("blake3", "sha256")
NAMES = sorted(f"{side}.{fmt}" for side in ("old", "new") for fmt in FORMATS)

RULES = """constraint_set_id: e2e.loans
bindings:
  input:
    key_fields:
      - loan_id
rules:
  - id: REQUIRED
    severity: error
    binding: input
    op: not_null
    columns:
      - loan_id
      - balance
"""
CEILING = """constraint_set_id: e2e.ceiling
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


class TabularPipeline(E2ETestCase):
    ws: Workspace

    @classmethod
    def setUpClass(cls):
        ws = cls.ws = Workspace("tabular")
        cls.expected = expected_changes()
        cls.chain = {}
        cls.scan = ws.run("vacuum", "data")
        for algorithm in ALGORITHMS:
            hashed = ws.run("hashbytes", "--algorithm", algorithm, stdin=cls.scan.stdout)
            printed = ws.run("fingerprint", "--fp", "csv.v0", "--fp", "xlsx.v0", stdin=hashed.stdout)
            locked = ws.run("lock", "--dataset-id", "e2e.loans", "--created", CREATED,
                            "--out", f"{algorithm}.lock.json", stdin=printed.stdout)
            cls.chain[algorithm] = (hashed, printed, locked)
        cls.draft = ws.run("profile", "draft", "init", "data/old.csv", "--out", "draft.yaml", "--key", "loan_id")
        cls.freeze = ws.run("profile", "freeze", "draft.yaml", "--family", "e2e.loans", "--version", "0", "--out", "frozen.yaml")
        ws.write("rules.yaml", RULES)
        ws.write("ceiling.yaml", CEILING)
        cls.compiled = [ws.run("verify", "compile", f"{name}.yaml", "--out", f"{name}.verify.json") for name in ("rules", "ceiling")]

        # Positive-control inputs: the same data under names, headers and values that are canaries.
        new_csv = ws.read("data/new.csv")
        old_csv = ws.read("data/old.csv")
        ws.write(f"named/{source.CANARY_LOAN_ID}.csv", old_csv)
        status_row = b"827364554.73,7.125,2029-06-30,current"
        assert status_row in new_csv
        ws.write("variant/canary-status.csv", new_csv.replace(status_row, status_row[:-7] + source.CANARY_NOTE.encode()))
        ws.write("variant/dropped-column.csv", old_csv.replace(source.CANARY_HEADER.encode(), b"other_column"))
        ws.write("variant/canary-key-header.csv", old_csv.replace(b"loan_id,", f"{source.CANARY_HEADER}_k,".encode()))

    # Stages -----------------------------------------------------------------

    def test_01_vacuum_hash_fingerprint_lock(self):
        self.expect(self.scan, 0)
        records = [json.loads(line) for line in self.scan.stdout.splitlines()]
        self.assertEqual(sorted(r["relative_path"] for r in records), NAMES)
        for algorithm, (hashed, printed, locked) in self.chain.items():
            with self.subTest(algorithm=algorithm):
                self.expect(hashed, 0)
                # Exit 1 is fingerprint's "some records did not match": the two Parquet files below.
                self.expect(printed, 1)
                self.expect(locked, 0)
                lock = json.loads(self.ws.read(f"{algorithm}.lock.json"))
                self.assertEqual(lock["version"], "lock.v0")
                members = {Path(m["path"]).name: m for m in lock["members"]}
                self.assertEqual(sorted(members), NAMES)
                for name, member in members.items():
                    self.assertRegex(member["bytes_hash"], rf"^{algorithm}:[0-9a-f]{{64}}$", name)
                    if algorithm == "sha256":
                        # Independent of every spine tool.
                        digest = hashlib.sha256(self.ws.read(f"data/{name}")).hexdigest()
                        self.assertEqual(member["bytes_hash"], f"sha256:{digest}", name)
        matched = {}
        for line in self.chain["blake3"][1].stdout.splitlines():
            record = json.loads(line)
            found = record.get("fingerprint") or {}
            matched[record["relative_path"]] = (found.get("fingerprint_id"), found.get("matched"))
        for side in ("old", "new"):
            self.assertEqual(matched[f"{side}.csv"], ("csv.v0", True))
            self.assertEqual(matched[f"{side}.xlsx"], ("xlsx.v0", True))
            # fingerprint ships no Parquet definition; the member must still pass through to lock.
            self.assertEqual(matched[f"{side}.parquet"], (None, None))

    def test_02_lock_verify(self):
        for algorithm in ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                run = self.expect(self.ws.run("lock", "verify", f"{algorithm}.lock.json", "--root", "data", "--json"), 0)
                self.assertEqual(run.json()["outcome"], "VERIFY_OK")

    def test_03_profile(self):
        self.expect(self.draft, 0)
        self.expect(self.freeze, 0)
        for name in ("draft.yaml", "frozen.yaml"):
            self.assert_redacted(f"profile {name}: no cell values", self.ws.read(name),
                                 self.ws.read("data/old.csv"), CELL_CANARIES)
        for fmt in FORMATS:
            data = f"data/old.{fmt}"
            with self.subTest(fmt=fmt):
                stats = self.expect(self.ws.run("profile", "stats", data, "--json"), 0)
                raw = self.expect(self.ws.run("profile", "stats", data, "--json", "--explicit", control=True), 0)
                self.assert_redacted(f"profile stats {fmt}", stats.blob, raw.blob)
                keys = self.expect(self.ws.run("profile", "suggest-key", data, "--json"), 0)
                named = self.expect(self.ws.run("profile", "suggest-key", "variant/canary-key-header.csv", "--json",
                                                "--explicit", control=True), 0)
                self.assert_redacted(f"profile suggest-key {fmt}", keys.blob, named.blob)
                self._check_inspect(fmt, data)

    def _check_inspect(self, fmt: str, data: str) -> None:
        run = self.expect(self.ws.run("profile", "inspect", data, "--json"), 0)
        raw = self.expect(self.ws.run("profile", "inspect", data, "--json", "--explicit", control=True), 0)
        report = run.json()
        columns = report.get("result", report)["columns"]
        self.assertEqual(len(columns), self.expected["columns"])
        balance = columns[source.COLUMNS.index("balance")]
        numeric = balance.get("numeric") or {}
        self.known("profile-inspect-numeric-extremes",
                   numeric.get("max") == float(source.CANARY_AMOUNT_OLD), numeric)
        # Apart from that numeric summary, the report must be clean.
        del balance["numeric"]
        self.assert_redacted(f"profile inspect {fmt}, except the balance numeric summary",
                             json.dumps(report).encode() + run.stderr, raw.blob)

    def test_04_fingerprint_peek_and_match(self):
        named = self.expect(self.ws.run("fingerprint", "--fp", "csv.v0", control=True, stdin=self.ws.run(
            "hashbytes", "--algorithm", "blake3", stdin=self.ws.run("vacuum", "named", control=True).stdout,
            control=True).stdout), 0)
        for fmt in ("csv", "xlsx"):
            with self.subTest(fmt=fmt):
                match = self.expect(self.ws.run("fingerprint", "match", f"data/old.{fmt}", "--fp", f"{fmt}.v0"), 0)
                self.assert_redacted(f"fingerprint match {fmt}", match.blob, named.blob)
                peek = self.expect(self.ws.run("fingerprint", "peek", f"data/old.{fmt}"), 0)
                self.assert_redacted(f"fingerprint peek {fmt}", peek.blob, named.blob)

    def test_05_path_carrying_tools_do_not_carry_cells(self):
        scan = self.ws.run("vacuum", "named", control=True)
        hashed = self.ws.run("hashbytes", "--algorithm", "blake3", stdin=scan.stdout, control=True)
        printed = self.ws.run("fingerprint", "--fp", "csv.v0", stdin=hashed.stdout, control=True)
        locked = self.ws.run("lock", "--dataset-id", "e2e.named", "--created", CREATED, stdin=printed.stdout, control=True)
        self.assert_redacted("vacuum", self.scan.blob, scan.blob)
        for algorithm, (default_hash, default_print, default_lock) in self.chain.items():
            self.assert_redacted(f"hashbytes {algorithm}", default_hash.blob, hashed.blob)
            self.assert_redacted(f"fingerprint stream {algorithm}", default_print.blob, printed.blob)
            self.assert_redacted(f"lock {algorithm}",
                                 default_lock.stderr + self.ws.read(f"{algorithm}.lock.json"), locked.blob)

    def test_06_shape_messy_csv_dialect(self):
        run = self.ws.run("shape", "data/old.csv", "data/new.csv", "--key", "loan_id", "--json")
        refusal = run.json().get("refusal") or {}
        observed = (run.code, refusal.get("code"), (refusal.get("detail") or {}).get("candidates"),
                    refusal.get("next_command", ""))
        self.known("shape-quoted-newline-dialect",
                   observed[:3] == (2, "E_DIALECT", ["0x09"]) and "--delimiter tab" in observed[3], observed)
        # rvl reads the same bytes without help.
        rvl = self.expect(self.ws.run("rvl", "data/old.csv", "data/new.csv", "--key", "loan_id", "--json"), 1)
        self.assertEqual(rvl.json()["outcome"], "REAL_CHANGE")

    def _shape_args(self, old: str, new: str, key: tuple = ("--key", "loan_id")) -> list[str]:
        # The pinned delimiter is the recorded way round shape-quoted-newline-dialect (test_06).
        delimiter = ["--delimiter", "comma"] if "csv" in (old.rsplit(".", 1)[-1], new.rsplit(".", 1)[-1]) else []
        return ["shape", old, new, *key, "--json", *delimiter]

    def test_07_shape_and_rvl_agree_with_source_across_format_pairs(self):
        want = self.expected
        for old_format in FORMATS:
            for new_format in FORMATS:
                old, new = f"data/old.{old_format}", f"data/new.{new_format}"
                with self.subTest(old=old_format, new=new_format):
                    shape = self.expect(self.ws.run(*self._shape_args(old, new)), 0).json()
                    self.assertEqual(shape["outcome"], "COMPATIBLE")
                    checks = shape["checks"]
                    self.assertEqual(checks["schema_overlap"]["columns_common"], want["columns"])
                    self.assertEqual(checks["row_granularity"]["rows_old"], want["rows"])
                    self.assertEqual(checks["row_granularity"]["rows_new"], want["rows"])
                    self.assertEqual(checks["row_granularity"]["key_overlap"], want["rows"])
                    self.assertEqual(checks["type_consistency"]["numeric_columns"], 2)
                    self.assertEqual(checks["type_consistency"]["type_shifts"], [])
                    rvl = self.expect(self.ws.run("rvl", old, new, "--key", "loan_id", "--json"), 1).json()
                    self.assertEqual(rvl["outcome"], "REAL_CHANGE")
                    self.assertEqual(rvl["counts"]["numeric_cells_changed"], want["numeric_cells_changed"])
                    self.assertAlmostEqual(rvl["metrics"]["total_change"], want["total_change"], places=4)
                    self.assertAlmostEqual(rvl["metrics"]["max_abs_delta"], want["max_abs_delta"], places=4)
                    words = self.expect(self.ws.run("rvl", old, new, "--key", "loan_id", "--non-numeric", "--json"), 1).json()
                    transitions = words["non_numeric"]["categorical_transitions"]
                    self.assertEqual([t["count"] for t in transitions], [1] * want["categorical_transitions"])

    def test_08_chain_per_format_with_locks_assess_and_pack(self):
        for fmt in FORMATS:
            for algorithm in ALGORITHMS:
                with self.subTest(fmt=fmt, algorithm=algorithm):
                    self._chain(fmt, algorithm)

    def _chain(self, fmt: str, algorithm: str) -> None:
        ws, tag = self.ws, f"{fmt}-{algorithm}"
        old, new, lock = f"data/old.{fmt}", f"data/new.{fmt}", f"{algorithm}.lock.json"
        profiled = ["--profile", "frozen.yaml", "--lock", lock]

        # The key comes from the frozen profile; passing --key too is refused (E_KEY_CONFLICT).
        shape = self.expect(ws.run(*self._shape_args(old, new, key=()), *profiled), 0)
        self.assertEqual(shape.json()["outcome"], "COMPATIBLE")
        verification = shape.json().get("input_verification")
        self.known("shape-lock-verification-null", verification is None, verification)
        if fmt != "csv":
            dialect = (shape.json().get("dialect") or {}).get("old")
            self.known("shape-non-csv-dialect", (dialect or {}).get("delimiter") == ",", dialect)

        rvl = self.expect(ws.run("rvl", old, new, "--json", *profiled), 1)
        self.assertEqual(rvl.json()["counts"]["numeric_cells_changed"], self.expected["numeric_cells_changed"])
        self.assertTrue(rvl.json().get("lock"), "rvl must record which lock it checked")
        rvl_words = self.expect(ws.run("rvl", old, new, "--non-numeric", "--json", *profiled), 1)
        self._check_profiled_non_numeric(old, new, lock, rvl_words.json()["non_numeric"])

        checked = self.expect(ws.run("verify", "run", "rules.verify.json", "--bind", f"input={new}",
                                     "--lock", lock, "--json"), 0)
        self.assertEqual(checked.json()["outcome"], "PASS")
        self.assertEqual(checked.json()["bindings"]["input"]["input_verification"]["status"], "VERIFIED")

        reports = []
        for name, run in (("shape", shape), ("rvl", rvl), ("rvl-non-numeric", rvl_words), ("verify", checked)):
            reports.append(ws.write(f"reports/{tag}/{name}.json", run.stdout))
        assessed = self.expect(ws.run("assess", reports[0], reports[1], reports[3],
                                      "--policy-id", "loan_tape.monthly.v1", "--json"), 0)
        self.assertEqual(assessed.json()["decision_band"], "PROCEED")
        reports.append(ws.write(f"reports/{tag}/assess.json", assessed.stdout))

        sealed = self.expect(ws.run("pack", "seal", *reports, lock, "--out", f"evidence/{tag}", "--created", CREATED), 0)
        verified = self.expect(ws.run("pack", "verify", f"evidence/{tag}", "--json"), 0)
        self.assertEqual(verified.json()["outcome"], "OK")
        rendered = []
        (ws.root / "render").mkdir(exist_ok=True)  # pack render does not create the parent directory
        for kind in ("md", "html"):
            self.expect(ws.run("pack", "render", f"evidence/{tag}", "--format", kind, "--out", f"render/{tag}.{kind}"), 0)
            rendered.append(ws.read(f"render/{tag}.{kind}"))

        # Controls for this format: what the same commands print when asked for raw values.
        pair = (old, new, "--key", "loan_id", "--json")
        raw_rvl = self.expect(ws.run("rvl", *pair, "--explicit", control=True), 1)
        self.assert_redacted(f"rvl {tag}", rvl.blob, raw_rvl.blob)
        variant = ("rvl", old, "variant/canary-status.csv", "--key", "loan_id", "--non-numeric", "--json")
        quiet = self.expect(ws.run(*variant), 1)
        loud = self.expect(ws.run(*variant, "--explicit", control=True), 1)
        self.assert_redacted(f"rvl --non-numeric {tag}", rvl_words.blob + quiet.blob, loud.blob)
        drop = ("shape", old, "variant/dropped-column.csv", "--key", "loan_id", "--json", "--delimiter", "comma")
        quiet = self.expect(ws.run(*drop), 0)
        loud = self.expect(ws.run(*drop, "--explicit", control=True), 0)
        self.assert_redacted(f"shape {tag}", shape.blob + quiet.blob, loud.blob)

        control_reports = [ws.write(f"control/{tag}/{source.CANARY_LOAN_ID}.{name}.json", ws.read(path))
                           for name, path in zip(("shape", "rvl", "verify"), (reports[0], reports[1], reports[3]))]
        control_assess = ws.run("assess", *control_reports, "--policy-id", "loan_tape.monthly.v1", "--json", control=True)
        self.assert_redacted(f"assess {tag}", assessed.blob, control_assess.blob)
        self.expect(ws.run("pack", "seal", *control_reports, "--out", f"control/{tag}/pack", "--created", CREATED,
                           control=True), 0)
        control_rendered = []
        for kind in ("md", "html"):
            self.expect(ws.run("pack", "render", f"control/{tag}/pack", "--format", kind,
                               "--out", f"control/{tag}/render.{kind}", control=True), 0)
            control_rendered.append(ws.read(f"control/{tag}/render.{kind}"))
        evidence = tree_bytes(ws.root / "evidence" / tag)
        control_evidence = tree_bytes(ws.root / "control" / tag / "pack")
        self.assert_redacted(f"pack evidence directory {tag}", evidence + sealed.blob + verified.blob, control_evidence)
        for kind, default, control in zip(("md", "html"), rendered, control_rendered):
            self.assert_redacted(f"pack render {kind} {tag}", default, control)

    def _check_profiled_non_numeric(self, old: str, new: str, lock: str, default: dict) -> None:
        """Correct output is one transition (status) and no text churn; test_07 gets that with --key."""
        raw = self.expect(self.ws.run("rvl", old, new, "--non-numeric", "--json", "--explicit",
                                      "--profile", "frozen.yaml", "--lock", lock, control=True), 1)
        words = raw.json()["non_numeric"]
        observed = (
            len(default["categorical_transitions"]),
            sorted(t["column"] for t in words["categorical_transitions"]),
            [(t["column"], t["changed_rows"]) for t in words["text_churn"]],
        )
        self.known("rvl-non-numeric-stock-profile",
                   observed == (2, ["u8:balance", "u8:balance"], [("u8:status", 1)]), observed)

    def test_09_failing_rule_stays_redacted(self):
        for fmt in FORMATS:
            command = ("verify", "run", "ceiling.verify.json", "--bind", f"input=data/new.{fmt}")
            with self.subTest(fmt=fmt):
                machine = self.expect(self.ws.run(*command, "--json"), 1)
                result = machine.json()["results"][0]
                self.assertEqual(result["violation_count"], len(self.expected["over_ceiling"]))
                human = self.expect(self.ws.run(*command), 1)
                raw = self.expect(self.ws.run(*command, "--json", "--explicit", control=True), 1)
                self.assertEqual([a["key"]["loan_id"] for a in raw.json()["results"][0]["affected"]],
                                 self.expected["over_ceiling"])
                self.assert_redacted(f"verify FAIL json {fmt}", machine.blob, raw.blob)
                self.assert_redacted(f"verify FAIL human {fmt}", human.blob, raw.blob)

    def test_10_benchmark_reads_both_lock_algorithms(self):
        gold = [
            {"entity": "00018", "field": "balance", "expected": "2750", "compare_as": "number"},
            {"entity": source.CANARY_LOAN_ID, "field": "borrower", "expected": "somebody else"},
            {"entity": source.CANARY_LOAN_ID, "field": "balance", "expected": "1", "compare_as": "number"},
        ]
        self.ws.write("gold.jsonl", "".join(json.dumps(item) + "\n" for item in gold))

        def without_caller_entities(run) -> bytes:
            # benchmark repeats each assertion's own `entity`, which the caller supplied in the
            # gold file. Only that field is removed, and it must equal what the caller wrote.
            report = run.json()
            self.assertEqual(sorted(f.pop("entity") for f in report["failures"]), [source.CANARY_LOAN_ID] * 2)
            return json.dumps(report).encode() + run.stderr

        for fmt in FORMATS:
            base = ("benchmark", f"data/new.{fmt}", "--assertions", "gold.jsonl", "--key", "loan_id")
            raw = self.expect(self.ws.run(*base, "--json", "--explicit", control=True), 1)
            for algorithm in ALGORITHMS:
                with self.subTest(fmt=fmt, algorithm=algorithm):
                    run = self.expect(self.ws.run(*base, "--lock", f"{algorithm}.lock.json", "--json"), 1)
                    report = run.json()
                    self.assertEqual(report["input_verification"]["verified_member"], f"new.{fmt}")
                    self.assertEqual((report["summary"]["passed"], report["summary"]["failed"]), (1, 2))
                    self.assert_redacted(f"benchmark {fmt} {algorithm}, except caller-supplied entity",
                                         without_caller_entities(run), without_caller_entities(raw))
            summary = self.expect(self.ws.run(*base, "--render", "summary"), 1)
            self.assert_redacted(f"benchmark summary {fmt}", summary.blob, raw.blob)

    def test_11_every_lock_consumer_refuses_drift(self):
        drift = self.ws.root / "drift"
        shutil.copytree(self.ws.root / "data", drift)
        self.ws.write("gold-drift.jsonl", json.dumps(
            {"entity": "00018", "field": "balance", "expected": "2750", "compare_as": "number"}) + "\n")
        for fmt in FORMATS:
            # A readable file of the same format that matches no locked member.
            (drift / f"new.{fmt}").write_bytes((FIXTURES / "drifted" / f"new.{fmt}").read_bytes())
            for algorithm in ALGORITHMS:
                lock = f"{algorithm}.lock.json"
                old, new = f"drift/old.{fmt}", f"drift/new.{fmt}"
                # The file reads without a lock, so a refusal below comes from the lock check.
                self.expect(self.ws.run("rvl", old, new, "--key", "loan_id", "--json"), 1)
                commands = {
                    "shape": [*self._shape_args(old, new), "--lock", lock],
                    "rvl": ["rvl", old, new, "--key", "loan_id", "--json", "--lock", lock],
                    "verify": ["verify", "run", "rules.verify.json", "--bind", f"input={new}", "--lock", lock, "--json"],
                    "benchmark": ["benchmark", new, "--assertions", "gold-drift.jsonl", "--key", "loan_id",
                                  "--lock", lock, "--json"],
                }
                with self.subTest(fmt=fmt, algorithm=algorithm, tool="lock verify"):
                    run = self.expect(self.ws.run("lock", "verify", lock, "--root", "drift", "--json"), 1)
                    self.assertEqual(run.json()["outcome"], "VERIFY_FAILED")
                for tool, command in commands.items():
                    with self.subTest(fmt=fmt, algorithm=algorithm, tool=tool):
                        run = self.expect(self.ws.run(*command), 2)
                        self.assertEqual(run.json()["refusal"]["code"], "E_INPUT_DRIFT")

    def test_12_pack_verify_detects_tampering(self):
        """Control for every `pack verify` exit 0 above: it can say no."""
        self.ws.write("tamper/report.json", self.chain["blake3"][0].stdout.splitlines()[0])
        self.expect(self.ws.run("pack", "seal", "tamper/report.json", "--out", "tamper/pack", "--created", CREATED), 0)
        self.expect(self.ws.run("pack", "verify", "tamper/pack", "--json"), 0)
        member = self.ws.root / "tamper/pack/report.json"
        member.write_bytes(member.read_bytes() + b" ")
        run = self.expect(self.ws.run("pack", "verify", "tamper/pack", "--json"), 1)
        self.assertEqual(run.json()["outcome"], "INVALID")

    def test_99_witness_ledger_is_clean(self):
        """Runs last: the ledger of every default-mode command in this pipeline."""
        # Control: the ledger records input paths, so a canary file name must show up in one.
        self.ws.run("shape", f"named/{source.CANARY_LOAN_ID}.csv", f"named/{source.CANARY_LOAN_ID}.csv",
                    "--key", "loan_id", "--delimiter", "comma", "--json", control=True)
        self.assert_redacted("witness ledger (tabular)", self.ws.witness.read_bytes(),
                             self.ws.control_witness.read_bytes())
