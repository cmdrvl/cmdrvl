# cmdrvl

> *One CLI front door for deterministic, agent-friendly data workflows.*

**Status:** Early scaffolding. The underlying open-source spine tools are live today under [github.com/cmdrvl](https://github.com/cmdrvl) and [`cmdrvl/homebrew-tap`](https://github.com/cmdrvl/homebrew-tap); `cmdrvl` is the unified porcelain CLI and local workflow runner being built on top of them.

---

## Why `cmdrvl` exists

The CMD+RVL spine ships focused, deterministic Rust tools — `shape`, `rvl`, `profile`, `verify`, `benchmark`, `assess`, `fingerprint`, `vacuum`, `hashbytes`, `lock`, `pack`, `canon`, `veil`, and `airlock` — so AI coding agents get **verifiable facts instead of guesses** about data.

Installing and chaining 14 standalone binaries works for custom pipelines, but everyday agent data workflows want **one install, one namespace, one discovery contract, and zero-ceremony commands** that compose the spine cleanly without leaking raw data into model context.

`cmdrvl` is that front door.

---

## Planned surface

```bash
# Family discovery & fleet health (one call for agents)
cmdrvl capabilities --json
cmdrvl doctor --json
cmdrvl --robot-triage

# Zero-retention single-file structural inspection (CSV, TSV, JSONL, Parquet, XLSX)
cmdrvl inspect data.xlsx --sheet Holdings --json

# Structural comparability gate + minimal numeric change explanation (shape -> rvl)
cmdrvl diff old.parquet new.parquet --key loan_id --json

# Declared or inline deterministic constraint checks (verify)
cmdrvl check data.parquet --rules rules.yaml --json

# Sealed, offline-verifiable evidence receipt (shape -> rvl -> pack seal -> pack verify)
cmdrvl receipt old.csv new.csv --key loan_id --out ./receipt/
```

---

## Architecture direction

- **Pure, deterministic spine leaves:** `shape`, `rvl`, `profile`, `verify`, `benchmark`, `assess`, `fingerprint`, `lock`, `pack`, `canon`, `veil`, and `airlock` remain focused, testable Rust crates with shared format support (CSV, TSV, JSONL, Parquet, XLSX) and unified `spine-rules` contracts.
- **Structured concurrency & deterministic execution:** Multi-file and multi-step local DAG workflows will run on [Asupersync](https://github.com/Dicklesworthstone/asupersync) — bringing region-owned fan-out, algebraic budgets, cancel-safe two-phase sealing (no partial packs or orphan witnesses), narrowed per-operator capabilities, and deterministic replay.
- **Zero-retention by default:** Designed to pair with [`veil`](https://github.com/cmdrvl/veil) and [`airlock`](https://github.com/cmdrvl/airlock) so agents can inspect, diff, verify, and seal sensitive datasets without pulling raw cell bytes into model context.

---

## Use the spine tools today

While `cmdrvl` is under construction, the individual open-source tools are available now via Homebrew:

```bash
brew install cmdrvl/tap/{shape,rvl,verify,assess,pack,veil,airlock}
```

See [github.com/cmdrvl](https://github.com/cmdrvl) for the full tool catalog and agent prompts.

---

## License

MIT.
