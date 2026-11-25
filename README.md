# cmdrvl

> *One CLI front door for deterministic, agent-native data workflows.*

**Status:** Early scaffolding. The underlying open-source spine tools are live today under [github.com/cmdrvl](https://github.com/cmdrvl) and [`cmdrvl/homebrew-tap`](https://github.com/cmdrvl/homebrew-tap); `cmdrvl` is the unified porcelain CLI and local workflow runner being built on top of them.

For the full end-to-end architectural blueprint — the **L0–L10 Epistemic Tower**, **Boundary Plane (`veil` + `airlock`)**, **Counterfactual Twin Plane (`twinning`)**, **Fractal `control.v0` Grammar**, **4 Accretion Ratchets**, and **Multi-Agent Handoff** — see **[docs/SYSTEM_ARCHITECTURE.md](./docs/SYSTEM_ARCHITECTURE.md)**.

---

## Why `cmdrvl` exists

The CMD+RVL spine ships focused, deterministic Rust tools — `shape`, `rvl`, `profile`, `verify`, `benchmark`, `assess`, `fingerprint`, `vacuum`, `hashbytes`, `lock`, `pack`, `canon`, `decoding`, `twinning`, `veil`, and `airlock` — so AI coding agents get **verifiable facts instead of guesses** about data.

Chaining standalone binaries works for custom pipelines, but an agent in the driver's seat needs **one cold-start orientation call, one token-bounded control grammar (`brief` / `delta` / `frontier`), typed `next_actions[]`, and zero-ceremony composition** across local checks, synthetic twins, and sealed receipts without leaking raw sensitive data into model context.

`cmdrvl` is that front door.

---

## Planned surface

```bash
# 1. One-call cold-start orientation (boundary posture + installed fleet + active state + safe next actions)
cmdrvl orient --json
cmdrvl doctor --json
cmdrvl capabilities --json

# 2. Zero-retention single-file structural inspection (CSV, TSV, JSONL, Parquet, XLSX)
cmdrvl inspect data.xlsx --sheet Holdings --view brief --json

# 3. Structural comparability gate + minimal numeric change explanation (shape -> rvl)
cmdrvl diff old.parquet new.parquet --key loan_id --view brief --json
cmdrvl diff old.parquet new.parquet --key loan_id --view delta --since blake3:... --json

# 4. Declared or inline deterministic constraint checks (verify)
cmdrvl check data.parquet --rules rules.yaml --json

# 5. Ephemeral synthetic twin & sealed zero-retention agent workstation (twinning + veil + airlock)
cmdrvl twin up --schema schema.sql --port 0 --json
cmdrvl sandbox --twin --egress airlock -- claude

# 6. Sealed, offline-verifiable evidence receipt (shape -> rvl -> pack seal -> pack verify)
cmdrvl receipt old.csv new.csv --key loan_id --out ./receipt/
```

---

## Architecture direction

- **One coherent abstraction tower ([docs/SYSTEM_ARCHITECTURE.md](./docs/SYSTEM_ARCHITECTURE.md)):** Every command projects into the same compact, token-bounded `control.v0`-compatible envelope (`verdict`, `boundary`, `coverage`, `unknowns[]`, `budget`, `refs{}`, typed `next_actions[]` with `effect_class`) so agents spend context only on answer-changing frontiers and turn-over-turn deltas.
- **Pure, deterministic spine leaves:** `shape`, `rvl`, `profile`, `verify`, `benchmark`, `assess`, `fingerprint`, `vacuum`, `hashbytes`, `lock`, `pack`, `canon`, `decoding`, and `veil` hook mode remain fast, synchronous, `#![forbid(unsafe_code)]` Rust crates governed by `spine-rules` and `evidence-protocol`.
- **Structured concurrency at the runner & daemon shells:** Multi-file and multi-step local DAG workflows (`cmdrvl`), streaming egress proxying (`airlock gate`), and live protocol twins (`twinning`) run on [Asupersync](https://github.com/Dicklesworthstone/asupersync) — bringing region-owned fan-out, algebraic budgets, cancel-safe two-phase sealing (no partial packs or orphan witnesses), narrowed per-operator capabilities, and deterministic replay.
- **Monotone zero-retention boundaries by default:** Pairs [`veil`](https://github.com/cmdrvl/veil) (ingress OS sandbox + broker + flag policy) and [`airlock`](https://github.com/cmdrvl/airlock) (egress wire gate + signed manifests + protected-corpus Bloom filters) over shared `boundary-detectors` so agents inspect, diff, verify, and seal sensitive datasets without pulling raw bytes into model context.

---

## Use the spine tools today

While `cmdrvl` is under construction, the individual open-source tools are available now via Homebrew:

```bash
brew install cmdrvl/tap/{vacuum,cmdrvl-hash,fingerprint,profile,lock,shape,rvl,verify,cmdrvl-benchmark,assess,canon,pack,twinning,veil,airlock}
```

See [github.com/cmdrvl](https://github.com/cmdrvl) for the full tool catalog and agent prompts.

---

## License

MIT.
