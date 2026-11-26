"""Run the suite against fetched binaries and write a report.

    python3 -m e2e.fetch --out /tmp/spine
    python3 -m e2e.run --tools /tmp/spine --report /tmp/e2e-report

The report holds versions, test names, known failures and the leak checks. It does
not hold tool output. A run fails on any failed, errored or skipped test, and on
any recorded known failure that no test exercised.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import unittest
from pathlib import Path


class Result(unittest.TextTestResult):
    ran_ids: list[str]

    def startTest(self, test):
        super().startTest(test)
        self.ran_ids.append(test.id())


def markdown(report: dict) -> str:
    lines = [f"## Spine E2E: {report['result']}", "",
             f"{report['tests']['run']} tests, {len(report['tests']['failed'])} failed, "
             f"{len(report['tests']['skipped'])} skipped, {len(report['leak_checks'])} leak checks "
             f"(each with a positive control that fired).", ""]
    if report["tests"]["failed"]:
        lines += ["### Failures", ""] + [f"- `{item['test']}`: {item['message']}" for item in report["tests"]["failed"]] + [""]
    lines += ["### Known failures (real seam defects, not passes)", "",
              "| id | owner | observed |", "|---|---|---|"]
    for item in report["known_failures"]:
        lines.append(f"| {item['id']} | {item['repo']} {item['bead']} | "
                     f"{'still present' if item['observed'] else 'NOT OBSERVED'} |")
    lines += ["", "### Binaries", "", "| tool | tag | version output |", "|---|---|---|"]
    for name, tool in sorted(report["tools"].get("tools", {}).items()):
        lines.append(f"| {name} | {tool['tag']} | {tool['version_output']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="e2e.run")
    parser.add_argument("--tools", required=True, help="directory written by e2e.fetch")
    parser.add_argument("--report", required=True, help="directory for report.json and report.md")
    parser.add_argument("--work", help="keep per-test work directories here (default: temporary directories)")
    args = parser.parse_args(argv)
    fetched = Path(args.tools).resolve()
    manifest = json.loads((fetched / "tools.json").read_text())
    os.environ["E2E_TOOLS"] = str(fetched / "bin")
    if args.work:
        os.environ["E2E_WORK"] = str(Path(args.work).resolve())

    # Imported after the environment is set.
    from e2e import harness

    root = Path(__file__).resolve().parent.parent
    suite = unittest.defaultTestLoader.discover(str(root / "e2e" / "tests"), top_level_dir=str(root))
    Result.ran_ids = []
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)

    failed = [{"test": test.id(), "message": trace.strip().splitlines()[-1][:300]}
              for test, trace in [*result.failures, *result.errors]]
    failed += [{"test": test.id(), "message": "unexpected success"} for test in result.unexpectedSuccesses]
    skipped = [test.id() for test, _ in [*result.skipped, *result.expectedFailures]]
    known = [{"id": identifier, **entry, "observed": identifier in harness.OBSERVED_KNOWN,
              "observations": len(harness.OBSERVED_KNOWN.get(identifier, []))}
             for identifier, entry in harness.KNOWN_FAILURES.items()]
    unseen = [item["id"] for item in known if not item["observed"]]
    green = result.testsRun > 0 and not failed and not skipped and not unseen
    verdict = f"PASS with {len(known)} known failures" if green else "FAIL"
    report = {
        "result": verdict,
        "tools": manifest,
        "tests": {"run": result.testsRun, "failed": failed, "skipped": skipped, "ids": Result.ran_ids},
        "known_failures": known,
        "leak_checks": harness.LEAK_CHECKS,
    }
    out = Path(args.report)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    summary = markdown(report)
    (out / "report.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(summary)
    for item in known:
        state = "STILL PRESENT" if item["observed"] else "NOT OBSERVED"
        print(f"KNOWN FAILURE {state}: {item['id']} ({item['repo']} {item['bead']})", file=sys.stderr)
    print(f"RESULT: {verdict}; {result.testsRun} tests, {len(failed)} failed, {len(skipped)} skipped, "
          f"{len(harness.LEAK_CHECKS)} leak checks", file=sys.stderr)
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
