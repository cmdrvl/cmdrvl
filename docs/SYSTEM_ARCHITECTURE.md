# CMD+RVL System Architecture — The Agent-Native Epistemic Tower

> **One synthetic system, not a bag of CLIs.**
> Every layer narrows ambiguity, exchanges only immutable content-addressed artifacts, enforces monotone privacy boundaries, and projects into one uniform agent control grammar.

---

## 1. The Core Architectural Thesis

AI agents fail on real data engineering and regulated analysis for four structural reasons, none of which are fixed by better prompting:

1. **Fragmented mental models:** Stitching 15 tools with 15 output schemas, flag conventions, and failure idioms burns context and invites hallucinated plumbing.
2. **Context bloat & amnesia:** Dumping raw tables or full reports blows up the context window; compaction or agent handoffs erase hard-won situational awareness.
3. **Unenforced boundaries:** Telling an agent "don't read private files" or "don't send PII to the model" is a policy wish, not a mechanical invariant.
4. **Non-compounding work:** Solving a messy schema, entity collision, or pipeline bug once leaves behind prose notes instead of immutable, replayable deterministic knowledge.

CMD+RVL solves all four with a single coherent geometry: **one Vertical Epistemic Tower (L0–L10)** cut cleanly by **two Orthogonal Planes** (the **Boundary & Exposure Plane** and the **Counterfactual Twin Plane**), operated through **one Fractal Agent Control Grammar**.

```text
                        ┌──────────────────────────────────────────────────────┐
                        │   ORTHOGONAL PLANE A: BOUNDARY & EXPOSURE LATTICE    │
                        │   public < derived < protected                       │
                        │   Ingress: veil (OS sandbox + broker + flag policy)  │
                        │   Egress:  airlock (send + gate + Bloom + Ed25519)   │
                        │   Shared:  boundary-detectors (zero-drift scanners)  │
                        └──────────────────────────┬───────────────────────────┘
                                                   │ governs every level
   L10  Agent Control        orient · control.v0 · --view brief|delta|frontier · next_actions · handoff
   L9   Strategy Evolution   canon strategy · frozen tournaments · holdout gates · promotion
   L8   Accretion            4 ratchets: epistemic cache · semantic registries · procedural champions · boundary hashes
   L7   Seal & Replay        lock · pack · airlock manifest · witness ledger · replay recipes
   L6   Decision             benchmark · assess · policy verdicts (PROCEED | RISK | ESCALATE | BLOCK)
   L5   Closure              verify · canon (lookup / entity / geo) · decoding · exact solvers
   L4   Comparability & Diff shape · rvl (redacted by default; --explicit requires clearance)
   L3   Observation          structured extractors · inventories · bounded claims
   L2   Type & Lens          fingerprint · frozen profile · registry & policy hashes
   L1   Artifact Identity    vacuum · hashbytes · content-addressed manifests & scope certificates
   L0   Bytes                immutable source files, S3 prefixes, database snapshots
                                                   ▲
                        ┌──────────────────────────┴───────────────────────────┐
                        │   ORTHOGONAL PLANE B: COUNTERFACTUAL / TWIN PLANE    │
                        │   twinning + veil sandbox --twin                     │
                        │   Ephemeral wire-compatible DB & file twins          │
                        │   Zero blast radius · ms reset · parity proof        │
                        └──────────────────────────────────────────────────────┘
```

Every link upward in the tower is a **content-addressed `blake3:` / `sha256:` reference plus the operator receipt that produced it**. No higher layer may smuggle an unstated assumption over a lower layer, and no agent ever needs to hold raw L0 bytes in context to reason accurately at L4–L10.

---

## 2. The Agent Driver's Seat: Fractal Control Grammar

Whether an agent is running a 2-second local check (`cmdrvl diff`), iterating 20x/hour on an extractor against `twinning`, resolving an entity frontier in `canon entity`, or steering a portfolio-scale run on an `evidence-protocol` runtime, **the control loop is identical**:

```text
orient → inspect/plan → [twin dry-run] → execute/verify → inspect delta → seal → accrete
```

### 2.1 One Cold-Start Call: `orient`
A cold agent must never probe 14 binaries experimentally to figure out what is installed, what is protected, or what is already in flight. One read-only call (`cmdrvl orient --json`) returns a bounded packet (~500 tokens) containing:

1. **Boundary Posture:** active enforcement (`hook-only | sandbox | sandbox+twin | sandbox+egress-airlock`), protected path/DB roots, `airlock gate` mode (`strict-manifest | policy-proxy | none`), and any preflight blockers.
2. **Fleet & Contracts:** installed spine binaries, semver/digests, health summary, available registries/profiles/fingerprints/champions — without leaking any secrets.
3. **Active Working State:** in-flight runs, open `canon entity` sessions, running `twinning` instances, and recent witness tail hash so an agent resumes instead of restarting.
4. **Ranked `next_actions[]`:** safe, immediately executable next moves.

### 2.2 Uniform Control Projection (`control.v0` Fractal Envelope)
Every workflow-level command projects into the same compact envelope (extending `evidence-protocol`'s `control.v0` downward into local `cmdrvl` porcelain):

- `state` / `verdict`: machine-readable domain outcome (`0` clean, `1` domain-negative, `2` structured refusal).
- `boundary`: `{ enforcement, twin_mode, attestation_mode, local_reads, violations }` — always visible so the agent knows its exact clearance and proof ceiling on every turn.
- `coverage` & `unknowns[]`: explicit accounting of what was checked, what was skipped/unavailable, and which unknowns carry `can_change_answer: true`.
- `budget`: `{ consumed, remaining }` (bytes, wall-time, cost units, turns).
- `refs`: content-addressed handles (`blake3:...`) to the full underlying artifacts so raw payloads stay on disk, not in the prompt.
- `next_actions[]`: typed recovery and progression moves (never prose-only hints).

### 2.3 Progressive Disclosure & Turn-Over-Turn `--view delta`
Raw data and large reports destroy agent reasoning quality and waste tokens. Every workflow surface obeys strict progressive disclosure:

| View | Token Budget | Purpose |
|---|---|---|
| `--view brief` *(default)* | ≤ ~500 tokens | Verdict, top-K ranked contributors/unknowns, counts, boundary posture, `refs`, `next_actions[]`. |
| `--view delta` | ≤ ~300 tokens | **Diff since the previous turn/artifact (`prev_ref → cur_ref`)**: `resolved: +N`, `new_regressions: M`, `remaining_blockers`, `budget_delta`. Built for tight agent iteration loops (`twinning`, `profile`, `canon`, tournaments) — cuts token burn 5–10×. |
| `--view frontier` | Bounded cursor | Only the unresolved items where `can_change_answer == true`, paginated by stable cursors. |
| `--view full` / `inspect-ref` | Explicit drill-down | Full artifact or slice by `blake3:` ref, strictly subject to `boundary` clearance. |

### 2.4 Typed `next_actions[]` With Effect Classes
Flat `next_command` strings help CLI agents recover from single-tool refusals (`E_NEED_KEY`), but multi-step and multi-agent control needs typed safety semantics. Every `next_action` carries:

- `action_id`: stable identifier for API/MCP callers.
- `effect_class`: one of:
  - `pure_read` — zero side effects; safe to auto-run without confirmation.
  - `twin_exec` — mutates only an ephemeral `twinning` overlay; safe to iterate freely.
  - `broker_exec` — runs an authorized metadata-safe spine tool via `veil exec` outside the sandbox.
  - `local_write` — writes draft configs, reports, or local working state.
  - `external_io` — touches network/warehouse/model API (gated by `grant.v0` / `airlock`).
  - `irreversible_promote` — mutates a versioned registry, seals a release, or promotes a strategy champion (requires explicit audit + authorization).
- `closes_unknowns[]`: which answer-changing unknowns this move can resolve.
- `cost_bound`: bounded estimate of wall-time, bytes, or external calls.
- `invocation`: structured `{ "bin": "...", "argv": [...] }` alongside rendered `command` — zero shell-escaping bugs.

---

## 3. Orthogonal Plane A: The Boundary & Exposure Lattice (`veil` + `airlock`)

Privacy and zero-retention are not documentation disclaimers; they are a **monotone information-flow lattice** spanning the entire tower:

```text
public  <  derived  <  protected
```

- **Agent clearance is `derived`:** The agent may freely read `public` repo/code files and `derived` metadata artifacts (redacted `shape`/`rvl`/`profile`/`verify` outputs registered by content hash), and may NEVER read `protected` source bytes directly.
- **Ingress wall (`veil`):**
  - *Hook mode (`<1ms`, pure sync Rust):* fast UX guard, path-anywhere-in-argv, shell decomposition, directory-scope Grep block, `--explicit`/`--raw`/`--dump` flag denial on spine tools, MCP argument screening, egress class denial.
  - *OS Sandbox + Broker (`veil sandbox` / `veil exec`):* mechanical A2 enforcement via unprivileged **macOS Seatbelt** and **Linux Landlock ABI 4+**. Protected paths are kernel-unreadable to the agent; only the privileged broker runs authorized spine tools, strips/refuses raw-dump flags, scans stdout through shared `boundary-detectors`, and registers safe outputs by `blake3` hash as `derived`.
- **Egress wall (`airlock`):**
  - *Deterministic pipelines (`airlock send` / `airlock gate --mode strict-manifest`):* every transmitted wire request is cryptographically bound (`REQUEST_UNBOUND` otherwise) to an assembled, provenance-mapped prompt over RFC 8785 JCS and signed with Ed25519 → earns `RAW_DOCUMENT_ABSENT` or `STRICT_TELEMETRY_ONLY`.
  - *Interactive agents (`airlock gate --mode policy-proxy`):* live `asupersync` localhost proxy screening OpenAI (`/v1/chat/completions`, `/v1/responses`), Anthropic (`/v1/messages`, incl. `tool_use`/`tool_result`/multimodal base64 blocks), and Gemini with shared `boundary-detectors` + a **one-way protected-corpus shingle Bloom filter** built outside the sandbox by `veil` → earns `POLICY_SCREENED`, blocking proprietary text/data exfiltration on the wire with HTTP 403 while streaming clean turns with zero-buffering SSE hashing.
- **Cross-boundary proof (`veil sandbox --egress airlock`):** Combines both walls in one launcher and embeds `veil attest` into `airlock` manifests so downstream auditors see two orthogonal axes: **what crossed the wire** (`STRICT_TELEMETRY_ONLY` / `RAW_DOCUMENT_ABSENT` / `POLICY_SCREENED`) AND **whether local reads stayed clean** (`LOCAL_READS_CLEAN`).

---

## 4. Orthogonal Plane B: The Counterfactual / Twin Plane (`twinning`)

Real data engineering requires iteration — trying SQL migrations, testing extractors, probing schema drift, evolving strategies — without risking production blast radius or exposing real client rows.

`twinning` provides the **universal simulation plane** across L3–L9:
- **Wire-identical synthetic execution:** Real Postgres (`pgwire`), REST, and warehouse clients run *unchanged* against deterministic, snapshot-restorable twins with embedded `verify` constraint checks.
- **Zero-retention development (`veil sandbox --twin`):** Mounts synthetic twin directories over protected paths AND injects local `twinning` DB/warehouse endpoints (`DATABASE_URL`, `PGHOST`, `SNOWFLAKE_*`) while sandbox network rules block real production egress. The agent develops and verifies real pipelines against the twin; the operator (or broker) runs the frozen artifact against real data.
- **Swarm & RLVR economics:** Ephemeral port allocation (`--port 0`) + copy-on-write snapshot overlays let dozens of concurrent agents (or tournament challengers, or RL rollouts) fork from one immutable base snapshot in milliseconds with bounded RSS and zero cross-worker interference.

---

## 5. Four Accretion Ratchets (How the System Compounds Without Epistemic Pollution)

Every session should make the next session **cheaper, faster, and more accurate** — never by silently mutating truth, always through the same four-stage ratchet:

```text
Draft / Observation  →  Twin-Verified  →  Audited / Policy-Gated  →  Immutable Promoted Asset
```

| Ratchet | Mutable Workspace | Durable Promoted Asset | Effect on Future Agents |
|---|---|---|---|
| **1. Epistemic** | Active run receipts & partial outputs | Content-addressed `artifact.v0`, `lock.v0`, `pack.v0`, coverage certificates, witness ledger | Exact semantic cache reuse; negative results carry coverage proofs so agents never re-scan unchanged universes. |
| **2. Semantic** | `profile draft`, `fingerprint infer`, `canon entity` / `canon geo` session frontiers | Frozen `profile`, compiled `fingerprint`, versioned `canon` registries (entities, geo, SKOS crosswalks) | Ambiguities resolved once compile into O(1) exact deterministic lookups with zero future LLM tokens. |
| **3. Procedural** | Candidate extractors, SQL patches, strategy mutations tested on `twinning` | Frozen `canon strategy` champions + holdout-verified tournament winners | Proven fixes become reusable deterministic operators for matching schema/task fingerprints. |
| **4. Boundary** | Per-session denials, broker stdout scans, gate interceptions | Derived-output hash registry (`veil`), protected-corpus Bloom filters, signed `airlock` manifests + `LOCAL_READS_CLEAN` attestations | Trust and zero-retention proof compound mechanically across turns without relaxing clearance. |

---

## 6. Native Multi-Agent & Swarm Legibility

The system assumes multiple agents will work concurrently and hand off across context compactions:

1. **Zero-prose handoff capsules:** Any agent can stop and pass a single content-addressed `control.v0` checkpoint (`refs.plan`, `refs.ledger`, `boundary`, `frontier_cursor`, `prev_ref`). A cold successor loads that single handle and recovers 100% accurate state in 1 call (~500 tokens), with hash verification that underlying inputs have not drifted.
2. **Conflict-free concurrency by construction:**
   - Immutable content-addressed artifacts mean parallel readers never lock.
   - `twinning` overlays (`--overlay-of <snapshot> --port 0`) give every worker an isolated database state.
   - `canon entity` sessions support shardable, claimable frontier leases so multiple agents resolve disjoint ambiguity shards concurrently without write races.
   - `veil` broker sockets and `airlock` witness entries are session-scoped and append-safe.
3. **Continuous escalation ramp — zero rewrite:**
   - **Tier 1 (Seconds — single check):** `cmdrvl inspect` / `cmdrvl diff` / `cmdrvl check` (wraps pure synchronous Rust leaves).
   - **Tier 2 (Minutes — safe iteration & proof):** `veil sandbox --twin --egress airlock` + `cmdrvl twin` + `cmdrvl receipt` (local Asupersync DAGs, cancel-safe two-phase sealing).
   - **Tier 3 (Portfolio scale — governed closure):** Escalate seamlessly into any `evidence-protocol`-compliant runtime (`inquiry.v0` → `plan.v0` → `grant.v0` → `run.v0` → `answer.v0`) using the exact same operator binaries, `control.v0` grammar, `veil`/`airlock` boundaries, and `canon`/`pack` outputs.

---

## 7. Design Invariants (Non-Negotiable Across All Repos)

1. **Pure synchronous leaves; structured concurrency at orchestration/daemon shells.** Core domain tools (`shape`, `rvl`, `verify`, `profile`, `canon`, `lock`, `pack`, `veil` hook mode) stay fast, deterministic, sync Rust (`#![forbid(unsafe_code)]`). Long-lived orchestration, local DAGs, and streaming proxies (`cmdrvl` runner, `airlock gate`, `twinning` protocol shell, `evidence-protocol` runtimes) use **Asupersync** for region-owned concurrency, algebraic budgets, and cancel-safe sealing.
2. **Exit code trinity everywhere:** `0` clean/positive, `1` domain-negative, `2` structured refusal with machine-readable recovery.
3. **Redacted by default:** No tool dumps raw sensitive cell values into stdout unless explicitly authorized (`--explicit`) and permitted by the active `veil` boundary clearance.
4. **Protocol contracts live once:** `evidence-protocol` owns the `*.v0` machine wire contracts; `spine-rules` owns `operator.v0` and golden-rule conformance; `boundary-detectors` owns shared secret/PII/tabular/blob/shingle scanners. No copy-pasted schemas or drifting regex tables across repos.
