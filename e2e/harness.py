"""Shared plumbing: running released binaries, leakage assertions and known failures."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from e2e import leaks

E2E = Path(__file__).resolve().parent
FIXTURES = E2E / "fixtures"
sys.path.insert(0, str(FIXTURES))
import make_fixtures as source  # noqa: E402  (the rows the fixtures were written from)

CREATED = "2026-01-15T10:30:00Z"
FORMATS = ("csv", "xlsx", "parquet")
KNOWN_FAILURES = json.loads((E2E / "known_failures.json").read_text())["known_failures"]

# Filled while tests run; e2e/run.py reads both to write the report.
OBSERVED_KNOWN: dict[str, list[str]] = {}
LEAK_CHECKS: list[dict] = []


def tools_dir() -> Path:
    value = os.environ.get("E2E_TOOLS")
    if not value:
        raise RuntimeError("E2E_TOOLS must name the bin directory written by `python3 -m e2e.fetch`")
    return Path(value).resolve()


def work_root() -> Path:
    value = os.environ.get("E2E_WORK")
    if value:
        root = Path(value).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root
    return Path(tempfile.mkdtemp(prefix="cmdrvl-e2e-")).resolve()


@dataclass
class Run:
    argv: list[str]
    code: int
    stdout: bytes
    stderr: bytes

    @property
    def blob(self) -> bytes:
        return self.stdout + b"\n" + self.stderr

    def json(self) -> dict:
        try:
            return json.loads(self.stdout)
        except ValueError as error:
            raise AssertionError(
                f"{self.argv} exit {self.code}: stdout is not JSON: {self.stdout[:300]!r} stderr={self.stderr[:300]!r}"
            ) from error


class Workspace:
    """A throwaway directory with the fixtures, an empty HOME and its own witness ledger."""

    def __init__(self, name: str) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=work_root()))
        self.bin = tools_dir()
        for sub in ("home", "data"):
            (self.root / sub).mkdir()
        for path in sorted(FIXTURES.glob("[on]??.*")):
            (self.root / "data" / path.name).write_bytes(path.read_bytes())
        self.witness = self.root / "witness.jsonl"
        # Controls print raw values on purpose, so they get a separate ledger.
        self.control_witness = self.root / "witness-controls.jsonl"

    def env(self, control: bool = False, extra: dict | None = None) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "HOME": str(self.root / "home"),
            "EPISTEMIC_WITNESS": str(self.control_witness if control else self.witness),
            # Nothing here may reach the network; loopback traffic ignores these.
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
        }
        env.update(extra or {})
        return env

    def run(self, tool: str, *args, stdin: bytes | None = None, control: bool = False, extra_env: dict | None = None) -> Run:
        argv = [tool, *map(str, args)]
        done = subprocess.run(
            [str(self.bin / tool), *argv[1:]], cwd=self.root, env=self.env(control, extra_env),
            input=stdin, capture_output=True, timeout=180,
        )
        record = {
            "argv": argv, "exit": done.returncode, "control": control,
            "stdout": done.stdout.decode("utf-8", "replace"), "stderr": done.stderr.decode("utf-8", "replace"),
        }
        with (self.root / "transcript.jsonl").open("a", encoding="utf-8") as transcript:
            transcript.write(json.dumps(record) + "\n")
        return Run(argv, done.returncode, done.stdout, done.stderr)

    def read(self, name: str) -> bytes:
        return (self.root / name).read_bytes()

    def write(self, name: str, data: bytes | str) -> str:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return name


def tree_bytes(root: Path) -> bytes:
    """Names and contents of every file under root."""
    parts = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            parts.append(path.relative_to(root).as_posix().encode() + b"\n" + path.read_bytes())
    return b"\n".join(parts)


class E2ETestCase(unittest.TestCase):
    maxDiff = None

    def expect(self, run: Run, code: int) -> Run:
        self.assertEqual(run.code, code, f"{run.argv}\nstdout={run.stdout[:600]!r}\nstderr={run.stderr[:600]!r}")
        return run

    def assert_redacted(self, surface: str, default, control, canaries: tuple[str, ...] = source.CANARIES) -> None:
        """No canary in `default`, and the same detector must fire on `control`.

        `control` is output from the same kind of channel that does carry a canary
        (an --explicit run, a canary-named input, a permissive policy). Without a
        control that fires, a clean result proves nothing and the test fails.
        """
        control_hits = leaks.find(control, canaries)
        self.assertTrue(control_hits, f"{surface}: the positive control did not fire, so a clean result proves nothing")
        self.assertTrue(default.strip() if isinstance(default, bytes) else default, f"{surface}: nothing was captured")
        hits = leaks.find(default, canaries)
        self.assertEqual(hits, [], f"{surface}: canary visible in default output")
        LEAK_CHECKS.append({
            "surface": surface,
            "bytes_scanned": len(default),
            "control_fired_on": sorted({canary for canary, _ in control_hits}),
        })

    def known(self, identifier: str, still_wrong: bool, observed: object) -> None:
        """Assert that a filed seam failure still behaves exactly as recorded."""
        entry = KNOWN_FAILURES[identifier]
        where = f"{entry['repo']} {entry['bead']}"
        self.assertTrue(
            still_wrong,
            f"KNOWN FAILURE CHANGED: {identifier} ({where}) no longer behaves as recorded. "
            f"If it is fixed, remove it from e2e/known_failures.json and assert the correct behaviour. "
            f"Observed: {observed!r}",
        )
        OBSERVED_KNOWN.setdefault(identifier, []).append(self.id())


def expected_changes() -> dict:
    """What the tools should report, computed from the rows the fixtures were written from."""
    old = {row[0]: dict(zip(source.COLUMNS, row)) for row in source.OLD_ROWS}
    numeric, categorical = [], []
    for (key, column), value in source.CHANGES.items():
        if isinstance(value, Decimal):
            numeric.append(abs(value - old[key][column]))
        else:
            categorical.append((old[key][column], value))
    new = [dict(zip(source.COLUMNS, row)) for row in source.new_rows()]
    return {
        "rows": len(source.OLD_ROWS),
        "columns": len(source.COLUMNS),
        "numeric_cells_changed": len(numeric),
        "total_change": float(sum(numeric)),
        "max_abs_delta": float(max(numeric)),
        "categorical_transitions": len(categorical),
        "over_ceiling": [row["loan_id"] for row in new if row["balance"] > 100000],
        "blank_notes": [row["loan_id"] for row in new if row["notes"] is None],
    }


# Canaries that are cell values. CANARY_HEADER is a column name, which schema files may carry.
CELL_CANARIES = tuple(c for c in source.CANARIES if c != source.CANARY_HEADER)
