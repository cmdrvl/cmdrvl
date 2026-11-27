# Cross-repo E2E: released spine binaries against each other

Each tool's own CI cannot see the seams between tools. This suite downloads the
**released** binaries, chains them over messy CSV, XLSX and Parquet, and fails
when a seam breaks. Nothing is built from source.

```sh
python3 -m e2e.fetch --out /tmp/spine                  # latest releases, checked against SHA256SUMS
python3 -m e2e.run --tools /tmp/spine --report /tmp/e2e-report
```

`--out` must not exist yet. To reproduce a recorded set of versions, add
`--pinned e2e/tools.pinned.json` to the fetch; `--write-pin FILE` records a new
one. The suite uses only the Python standard library (3.10 or later). It runs on
macOS and on x86-64 Linux; macOS needs `/usr/sbin/lsof`.

CI: `.github/workflows/e2e.yml`, nightly and on manual dispatch. Nightly takes
the latest releases, so a new release that breaks a seam turns the run red.

## Reading a result

`PASS with N known failures` is **not** a clean pass. Each known failure in
`known_failures.json` is a real defect between tools, tied to a bead in the
owning repo. Its test asserts the current wrong behaviour exactly, so:

- while the defect is there, the run passes and names it;
- when the behaviour changes in any way, the run fails with `KNOWN FAILURE CHANGED`.
  If the defect is fixed, delete the entry and assert the correct behaviour;
- an entry that no test checked also fails the run, as does any skipped test.

## Pipelines

| File | What runs |
|---|---|
| `tests/test_tabular.py` | vacuum, hashbytes (blake3 and sha256), fingerprint, lock, lock verify, profile, shape, rvl (both modes), verify, assess, benchmark, pack seal / verify / render; every `--lock` consumer against drifted files |
| `tests/test_boundary.py` | veil's hook on protected files, then the authorized tools themselves; `airlock gate` in policy-proxy mode: streaming, blocking, receipts |
| `tests/test_twin.py` | `verify compile` into `twinning postgres --port 0`, rows loaded over the wire, embedded verify with passing, failing and refused checks, redacted by default and raw with `--explicit`, pack seal / verify |
| `tests/test_fetch.py`, `tests/test_harness.py` | the downloader's refusals and the proof that the leak and known-failure checks can fail; no binaries or network needed |

## Leak checks

Every leak check uses one detector (`leaks.py`) and needs a **positive
control**: output from the same kind of channel that does carry a canary, such
as an `--explicit` run, a file whose name is a canary, or a permissive gate
policy. If the control does not fire, the check fails. Where a control is only
a path or a policy name, it shows that the channel is scanned, not that a cell
value could have reached it. The detector cannot see a canary that was
compressed, encrypted, hashed, split, truncated or rounded.

For twinning's embedded verify, in a failing and in a refused check, the report
on stdout, the `--report` file and the sealed pack are each scanned whole. Each
one's control is the same surface of an `--explicit` run, which must show every
canary the default run had to keep off it. twinning's stderr and its duplicate-key
error carry no verify report, so their control is only the snapshot.

Two things are removed before scanning, each in plain sight in the tests:

- `profile inspect`'s numeric summary for `balance` (a known failure);
- benchmark's `failures[].entity`, which repeats the caller's own gold file.

## Data

Everything is invented. `fixtures/make_fixtures.py` holds the rows, which are the
source of the expected values; the tools' output never is. Regenerating the
binary fixtures needs pyarrow and openpyxl; running the suite does not.

The tests start only local processes, and airlock's upstream is a stub inside the
test process. Only the fetch step uses the network, to download public release
assets from github.com with no token.

## Not covered

- Release signatures (`.sig` / `.pem`) are not verified, only SHA256SUMS, which
  comes from the same release as the asset.
- `canon` is not run. `boundary-detectors` has no binary and is exercised only
  through airlock and veil.
- `airlock assemble`, `verify`, `send` and the strict-manifest gate; the gate's
  `--protected-bloom` filter.
- Only Claude Code's `PreToolUse` payload is sent to veil, with the `plain`
  harness; installed hooks and `veil sandbox` are not exercised.
- Windows, and Linux or macOS on ARM in CI.
