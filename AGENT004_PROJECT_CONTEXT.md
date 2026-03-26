# Agent 004: Red Team Simulator — Project Context

**Last updated:** 2026-03-26 (Session 7)
**Status:** v0.5.0 shipped (Stage 5 complete).
**Owner:** James Toole
**Repo:** https://github.com/selfradiance/agent-004-red-team
**Local folder:** ~/Desktop/projects/agent-004-red-team
**Skill level:** Beginner — James has no prior coding experience. He directs AI coding agents (Claude Code) to build the project. Explain everything simply. Take baby steps.

---

## What This Is

Agent 004 is a bonded red team simulator. It runs predefined attack scenarios against a live AgentGate instance over HTTP — from the outside, like a real adversary. Each attack probes a different defense: replay protection, bond capacity enforcement, signature verification, authorization boundaries, input validation, and rate limiting. After all attacks complete, the Claude API generates a structured findings report.

This is the fourth instantiation of the single-task agent pattern built on AgentGate. Agent 001 proved deterministic bonded work (hash verification). Agent 002 proved bonded guarding (command-based verification). Agent 003 proved human judgment in the bond loop. Agent 004 proves that AgentGate can withstand systematic adversarial probing from an external agent.

The full vision has four stages:
- **Stage 1 (v0.1.0):** Static red team — predefined attacks, structured report ✅
- **Stage 2 (v0.2.0):** Adaptive red team — agent evaluates results and shifts strategy between rounds. Attack library expanded to 47 scenarios across 12 categories. Claude-powered strategist picks attacks per round. 3-round adaptive loop. → PLANNING COMPLETE
- **Stage 3 (v0.3.0):** Recursive red team — agent reasons about *why* strategies failed, generates novel attack functions using a constrained combat toolkit, and executes them in a permission-restricted child process. Claude writes real JavaScript attack code, but the child process is logic-only — all HTTP calls go through IPC to the parent. Four layers of defense: Node 22 permission flags (filesystem/process restrictions), global nullification (dangerous globals deleted before generated code runs), IPC-only toolkit (parent owns all network access), and string-level validator (catches hallucinations before execution). Architecture audited across 4 rounds × 3 auditors (ChatGPT, Gemini, Grok) with consensus on every design decision.

- **Stage 4 (v0.4.0):** Coordinated team — three specialist personas (Shadow, Whale, Chaos) with mechanically distinct bond budgets and attack-family priorities, coordinated by the strategist via two coordination patterns (handoff and distributed_probe). Tests whether AgentGate's per-identity defenses hold under coordinated multi-identity pressure. Architecture audited across 3 auditors (ChatGPT, Gemini, Grok) with ChatGPT providing the sharpest structural corrections.

- **Stage 5 (v0.5.0):** Coordinated Swarms — three teams of three agents (9 identities total) with distinct strategic objectives, per-team strategists, and a campaign coordinator. Indirect coordination via shared intelligence log. Interleaved execution with deterministic logging. 5-round default campaigns. Three-layer budget model. Counterfactual success test for swarm-emergent findings. Three-tier provenance in reporting. → DESIGN LOCKED

Stages 1–5 shipped.

---

## What Problem It Solves

AI agents are being deployed with broad access and zero adversarial testing. Autonomous agents like OpenClaw, browser extensions, and coding assistants operate without sandboxes, and all it takes is one real incident to change everything. AgentGate already has internal red team tests (20 scenarios in test/red-team.test.ts), but those run inside the codebase with direct database access. That's not how real attackers work.

Agent 004 attacks from the outside — over HTTP, with its own identity and its own consequences. The question it answers: can AgentGate's bond-and-slash model withstand systematic adversarial probing from an external agent?

---

## How It Relates to AgentGate

AgentGate is both the enforcement substrate AND the attack target for this project. Agent 004 calls AgentGate's API for identity and bond management, and also sends intentionally malformed/adversarial requests to test AgentGate's defenses.

AgentGate must be running locally for Agent 004 to work.

- **AgentGate local:** http://127.0.0.1:3000
- **AgentGate remote:** https://agentgate.run
- **AgentGate repo:** https://github.com/selfradiance/agentgate

---

## Tech Stack

- **Language:** TypeScript (matches AgentGate and Agents 001/002/003)
- **Runtime:** Node.js 20+, tsx for TypeScript execution
- **Testing:** Vitest
- **LLM:** Anthropic Claude API (claude-sonnet-4-20250514) via @anthropic-ai/sdk — used for generating the findings report
- **HTTP client:** Native fetch (to call AgentGate API)
- **Signing:** Node.js built-in crypto (Ed25519) — replicated from AgentGate's signing logic
- **Config:** dotenv
- **Coding tool:** Claude Code

---

## The Flow

1. Human runs CLI: `npx tsx src/cli.ts` (or with `--target <url>` to override default)
2. Agent creates an identity on AgentGate (or loads existing from agent-identity.json)
3. Agent runs each of 15 attack scenarios in sequence
4. Each attack sends requests to AgentGate and logs whether the attack was caught or got through
5. After all attacks complete, agent sends the full attack log to Claude API
6. Claude API generates a structured findings report (executive summary, results table, final assessment)
7. Agent displays the report in the terminal
8. Agent prints a final summary: total attacks, caught, uncaught
9. Exit code 0 if all caught, exit code 1 if any uncaught

---

## Architecture

```
┌─────────────────────────────────┐
│  CLI (src/cli.ts)               │  ← Entry point, orchestrates the full run
├─────────────────────────────────┤
│  Attack Runner (src/runner.ts)  │  ← Iterates through 15 scenarios, collects results
├─────────────────────────────────┤
│  Attack Scenarios               │  ← Each scenario: description, execute function, expected result
│  (src/attacks/*.ts)             │     6 files, one per attack category
├─────────────────────────────────┤
│  Attack Log (src/log.ts)        │  ← Structured log of every attack attempt and result
├─────────────────────────────────┤
│  Reporter (src/reporter.ts)     │  ← Sends attack log to Claude API, returns findings report
├─────────────────────────────────┤
│  AgentGate Client               │  ← Calls AgentGate API (identity, bond, execute, resolve)
│  (src/agentgate-client.ts)      │     Handles Ed25519 signing + raw request crafting for attacks
├─────────────────────────────────┤
│  AgentGate Server (external)    │  ← Running separately — the target being attacked
├─────────────────────────────────┤
│  Claude API (external)          │  ← Running remotely — generates the findings report
└─────────────────────────────────┘
```

---

## Attack Scenarios (v0.1.0) — 15 total, all implemented and passing

### Category 1: Replay Attacks (3 scenarios)
- **1.1 Exact duplicate request** — same nonce/timestamp/body sent twice → 409 DUPLICATE_NONCE ✅
- **1.2 Same signature, fresh nonce** — old signature with new nonce → signature verification fails ✅
- **1.3 Expired timestamp** — timestamp 120s in the past → rejected for stale timestamp ✅

### Category 2: Bond Capacity Attacks (3 scenarios)
- **2.1 Over-commit exposure** — exposure exceeding bond capacity → INSUFFICIENT_BOND_CAPACITY ✅
- **2.2 Double-resolve** — resolve same action twice → second resolution rejected ✅
- **2.3 Act on expired bond** — execute action on expired bond → rejected ✅

### Category 3: Signature Tampering (3 scenarios)
- **3.1 Wrong private key** — sign with different key than registered identity → signature fails ✅
- **3.2 Malformed signature** — garbage in x-signature header → rejected ✅
- **3.3 Missing signature headers** — no x-signature/x-timestamp/x-nonce → 400 ✅

### Category 4: Authorization Boundary (2 scenarios)
- **4.1 Admin endpoint without admin key** — hit /admin/ban-identity without key → 401/403 ✅
- **4.2 Resolve another identity's action** — identity B tries to resolve identity A's action → rejected ✅

### Category 5: Input Validation (3 scenarios)
- **5.1 Oversized payload** — payload > 4096 bytes → PAYLOAD_TOO_LARGE ✅
- **5.2 TTL exceeding cap** — TTL > 86400s → TTL_TOO_LONG ✅
- **5.3 Negative bond amount** — negative amount_cents → validation error ✅

### Category 6: Rate Limiting (1 scenario)
- **6.1 Exceed execution rate limit** — 11 executes in rapid succession → 11th rate-limited with 429 ✅

---

## Stage 2 Design (v0.2.0) — Planning Complete, Ready to Build

### What Stage 2 Adds

Stage 1 runs 15 fixed attacks in order. Stage 2 adds an adaptive loop: a Claude-powered strategist picks attacks from an expanded library, watches what happens, and adapts its strategy across 3 rounds.

### Attack Library (47 Tier 1 + 2 Tier 2)

The attack library was drafted with full knowledge of AgentGate's defenses (v0.3.0, 70 tests, 117 milestones), then audited by ChatGPT, Gemini, and Grok. All three audits incorporated. The full library is in `agent-004-stage2-attack-library-FINAL.md` (gitignored).

| Category | Count | New in Stage 2? |
|----------|-------|-----------------|
| 1. Replay & Timestamp | 5 | 2 new |
| 2. Bond & Exposure | 7 | 4 new |
| 3. Signature & Header Abuse | 5 | 2 new (merged from 4) |
| 4. Authorization & Identity | 5 | 3 new |
| 5. Input Validation | 5 | 3 new (merged from 4) |
| 6. Rate Limiting & Sybil | 3 | 2 new |
| 7. Timing & Race Conditions | 3 | 3 new |
| 8. Protocol Abuse | 2 | 2 new (merged from 3) |
| 9. MCP Transport Abuse | 3 | 3 new |
| 10. Market Abuse | 4 | 4 new |
| 11. Economic & Reputation | 3 | 3 new |
| 12. Recon & Side-Channel | 2 | 2 new |
| **Tier 1 Total** | **47** | |
| Tier 2 (low-priority mapping) | 2 | |

Key additions from audit consensus:
- MCP surface attacks (all 3 auditors flagged as biggest gap in the draft)
- Market abuse scenarios targeting the documented known limitation (REST key auth only, not identity-signed)
- Economic/reputation manipulation (cheap successes to inflate score, then exploit)
- Sybil campaign chains (recon → create identities → distribute pressure)
- Resource exhaustion via long-TTL open actions
- 24 parameterizable scenarios (up from 8 in draft)

### Strategist Design

The strategist is a Claude API call inside the adaptive loop. It decides what to attack each round.

**How it works:**
- Sees the full 47-scenario library every round (IDs, names, defenses targeted, parameterization options, difficulty tier)
- Picks 5-15 attacks per round
- Returns structured JSON: attack IDs, parameters, and one-sentence reasoning per pick
- Round 1: prefers low-cost probes (recon, protocol checks, baseline confirmations)
- Round 2: escalates based on Round 1 results (boundary probes, timing, race conditions)
- Round 3: highest-value targets (multi-step chains, Sybil campaigns, economic attacks, market abuse)
- Can re-run scenarios with different parameters across rounds
- Can chain attacks (use recon from Round 1 to inform Rounds 2-3)
- Cannot invent new attacks not in the library (that's Stage 3)
- Discovers attack chains organically rather than following hardcoded templates → real attackers improvise, so the strategist should too

**Strategist output format:**
```json
{
  "round": 1,
  "strategy": "Brief description of overall approach for this round",
  "attacks": [
    {
      "id": "1.4",
      "params": { "timestamp_age_seconds": 60 },
      "reasoning": "Probing exact boundary of staleness check"
    }
  ]
}
```

### Runner Loop Architecture

**Stage 1 flow:** CLI → identity → run all 15 → report → exit

**Stage 2 flow:**
1. Parse CLI args (--target, --rounds)
2. Create identity on AgentGate
3. Load attack registry (all 47 scenarios mapped to execute functions)
4. For each round (1 to N, default 3):
   a. Call strategist API with: full library menu, round number, all prior results
   b. Parse strategist response (JSON: attack IDs + params)
   c. For each selected attack: look up in registry, execute with params, collect rich result
   d. Print round summary to terminal
5. Call reporter API with: all rounds' results, all strategist reasoning
6. Print final report covering all rounds and strategy evolution
7. Exit code 0 if all caught, exit code 1 if any uncaught

**Rich success criteria (from audit feedback):** Don't just check HTTP status codes. Also check: did bond state change? Did reputation change? Did dashboard HTML leak unescaped data? Binary caught/uncaught is too coarse for adaptive strategy.

**Error handling:** If strategist API call fails, fall back to top 10 "High priority" attacks from the library. Report notes that a round used fallback selection.

**New/changed files:**
| File | Change |
|------|--------|
| src/cli.ts | Refactor to loop over rounds instead of single pass |
| src/runner.ts | Accept attack IDs + params instead of hardcoded list |
| src/strategist.ts | NEW — calls Claude API with library + results, returns attack picks |
| src/registry.ts | NEW — maps scenario IDs to execute functions + metadata |
| src/attacks/*.ts | Refactor to accept params, register in registry |
| src/reporter.ts | Expand to cover multiple rounds + strategist reasoning |
| src/log.ts | Expand AttackResult to include side effects, round number |

**CLI flags:**
- `--rounds N` (default 3) — number of adaptive rounds
- `--target <url>` (existing) — AgentGate URL
- `--static` (optional) — run all attacks in fixed order like Stage 1, for regression testing

### Stage 2 Audit Trail

| Auditor | Key additions suggested | Key trims suggested | Verdict |
|---------|------------------------|--------------------|---------|
| Gemini | MCP session exhaustion, reputation pumping, slow-loris resource clog, market hijack, header bloat | Merge 5.1+5.7, merge 9.1+9.2 (original numbering) | "Solid foundation" |
| ChatGPT | 2-4 MCP scenarios, economic/reputation chains, market spam + deadline abuse | Merge 3.2+3.4, drop 5.1, merge 4.6+10.2. Target 32-40. | "Meaningfully incomplete without MCP and economic vectors" |
| Grok | MCP auth + malformed + session, full market mini-category, multi-step Sybil campaigns, header canonicalization | Merge 4.6+10.2, demote 1.6, trim one protocol check. Target 34-40. | "Solid but not yet final. Tighten menu, add MCP and market properly." |

All three agreed on: MCP as biggest gap, market abuse too thin, economic/reputation missing, Category 7 (timing) as highest ROI for finding real bugs, Sybil should be a campaign not isolated checks.

---

## Stage 3 Design (v0.3.0) — Ready to Build

### What Stage 3 Adds

Stage 2 picks from a fixed library of 48 attacks and adapts across rounds. Stage 3 adds recursive attack generation: after each round, the agent reasons about why attacks were caught, hypothesizes new attack vectors, and generates novel JavaScript attack functions that weren't in the original library. The generated code runs in a sandboxed child process through a constrained combat toolkit.

### Architecture: Constrained Code Generation + Permission-Flagged Child Process

The child process is logic-only. The parent process is effects-only.

**Four layers of defense:**
1. **Node 22 permission flags** — `--allow-fs-write=false`, `--allow-child-process=false`, `--allow-worker=false`, `--allow-fs-read` restricted to temp file and node_modules only
2. **Global nullification** — `fetch`, `require`, `process`, `eval`, `Function`, `setTimeout`, `setInterval`, `XMLHttpRequest`, and other dangerous globals deleted from the V8 context before generated code runs
3. **IPC-only toolkit** — generated code can only call toolkit methods, which send IPC messages to the parent. The parent makes all real HTTP calls. The child never touches the network.
4. **String-level validator** — blocklist + positive structural checks catch hallucinations and obvious mistakes before execution starts

**The flow:**
1. Reasoner (Claude API call): analyzes prior round results, identifies what defenses blocked each attack, hypothesizes novel attack vectors
2. Generator (Claude API call): turns hypotheses into executable JavaScript functions using only the toolkit API
3. Validator (local): checks generated code against blocklist + structural rules + novelty gate
4. Executor (parent): writes temp runner file, spawns permission-restricted child process with scrubbed env, 15s timeout, 64MB memory cap
5. Child runner: deletes dangerous globals, evaluates generated function with injected toolkit, sends result back via IPC
6. Parent: receives result, normalizes it, adds to round results, feeds into next round's reasoner

**Toolkit methods (all execute in parent via IPC):**
- `toolkit.signedPost(path, body)` — signed request as agent identity
- `toolkit.rawPost(path, body, headers)` — unsigned/custom request
- `toolkit.rawGet(path)` — GET request
- `toolkit.createIdentity()` — capped at 3 per attack execution
- `toolkit.signedPostAs(identity, path, body)` — signed as a different identity
- `toolkit.sleep(ms)` — capped at 5000ms
- `toolkit.getReputation(identityId)` — read reputation
- `toolkit.getBondStatus(bondId)` — read bond state
- `toolkit.getActionStatus(actionId)` — read action state
- `toolkit.checkDashboardForRawHtml()` — probe dashboard for XSS/leaks
- `toolkit.log(message)` — send log to parent

All HTTP calls hardcoded to target URL only, 5s timeout, 4KB response cap, Object.freeze() on returned data.

**Validator rules:**
- Blocklist: `require(`, `import `, `import(`, `process.`, `fs.`, `child_process`, `net.`, `http.`, `https.`, `fetch(`, `eval(`, `Function(`, `globalThis`, `__dirname`, `__filename`, `module`, `exports`, `constructor`, `prototype`, `Reflect`, `Proxy`, `Symbol`, `AsyncFunction`, `WebAssembly`, `setImmediate`, `queueMicrotask`, `setTimeout`, `setInterval`, `dns.`, `tls.`, `worker_threads`
- Structural: must contain exactly one `async function novelAttack(toolkit)`, max 10KB, no unbounded loops, max 3 nesting levels, max 20 toolkit calls, must return `{ caught, reason }`
- Novelty gate: reject near-duplicates of existing 48-scenario library

**Accepted limitations (documented as transparency):**
- No `--allow-net` in Node 22 (arrived in Node 25). Network safety enforced by IPC toolkit + global nullification, not OS flags.
- Node 22 permission model has had bypass CVEs (symlink traversal CVE-2025-55130). Blast radius is minimal — child has no secrets, temp dir has no symlinks, parent deletes temp immediately.
- String-level validator is bypassable via obfuscation. It catches accidents; real boundaries are permission flags + global nullification + IPC toolkit.
- This is constrained local execution, not hardened isolation. Appropriate for a local CLI portfolio tool where the code generator is Claude.

**CLI interface:**
- `--recursive` flag enables Stage 3 (default off — static and adaptive modes unchanged)
- `--rounds N` works with recursive mode (default 3)
- Each round: strategist picks library attacks + reasoner/generator produce novel attacks
- Terminal shows generated code before execution

### Stage 3 Audit Trail

Architecture audited across 4 rounds × 3 auditors (ChatGPT, Gemini, Grok):

| Round | Key question | Consensus |
|-------|-------------|-----------|
| 1 | vm vs Docker vs JSON recipes vs isolated-vm vs child process? | No vm (prompt injection → RCE). No Docker (overengineering). JSON recipes too weak for article. |
| 2 | Gemini: child process + Node permission flags. ChatGPT: rich DSL + safe executor. Grok: isolated-vm. | Gemini and Grok favor real code gen. ChatGPT favors constrained primitives. |
| 3 | Live test: `--allow-net` doesn't exist in Node 22. Only in Node 25. | Permission flags work for filesystem (tested live: ERR_ACCESS_DENIED). No network restriction at OS level. |
| 4 | Final design: IPC toolkit (parent does all HTTP) + global nullification + permission flags + validator. | All three approved. ChatGPT: move HTTP to parent via IPC. Gemini: delete globals. Grok: add dashboard check. |

Key contributions per auditor:
- **Gemini:** Global nullification pattern (delete fetch/require/process before generated code runs). Node permission flag approach. Extra validator patterns (import(, setTimeout, setInterval).
- **ChatGPT:** IPC-only toolkit (parent handles all HTTP — child is logic-only). Cap createIdentity() at 3. Object.freeze() toolkit. Positive structural checks in validator. "Constrained local execution" framing. toolkit.getActionStatus().
- **Grok:** toolkit.checkDashboardForRawHtml(). Concatenation/base64 bypass patterns in validator. Document accepted limitations as transparency in README.

---

## Stage 4 Design (v0.4.0) — Complete

### Thesis

Can an accountability system that is robust against one attacker still hold up when adversarial pressure is distributed across multiple identities with coordinated roles?

### Three Personas

| Persona | Specialty | Bond Budget | Attack Families |
|---------|-----------|-------------|-----------------|
| Shadow | Recon & Timing | 50¢ | 1 (Replay), 3 (Signature), 7 (Timing), 12 (Recon) |
| Whale | Economic & Bond | 200¢ | 2 (Bond), 6 (Rate Limit/Sybil), 10 (Market), 11 (Economic) |
| Chaos | Input Fuzzing & Protocol | 100¢ | 4 (Authorization), 5 (Input Validation), 8 (Protocol), 9 (MCP) |

Bond budgets are advisory (enforced by strategist prompt, not runtime). Attack-family affinities guide the strategist but don't restrict assignment.

### Two Coordination Types

1. **Handoff:** Persona A runs → extract intel → pass as `sharedIntel` param to Persona B's attack. Sequential.
2. **Distributed Probe:** Two personas attack the same defense concurrently with 500ms stagger. Tests per-identity isolation under simultaneous cross-identity load.

Both types require the strategist to declare: target defense, expected signal, and why multi-identity is required.

### Strategist Rules

- All three personas must be exercised by end of Round 2
- At least one coordinated operation required after Round 1
- Respect bond budgets (prompt-level guidance)
- Per-persona assignments + coordinated ops in structured JSON

### Generator Persona Targeting

Narrow context only: persona name + allowed families + one compact prior finding + one concrete objective. No full persona lore or round history. Generated code receives `toolkit.personaName` as a read-only constant.

### Reporter Three-Category Outcome Classification

Each coordinated op result classified as:
- **Intended behavior** — multi-identity result matches AgentGate's per-identity design
- **Inconclusive** — ambiguous, possibly due to timing or insufficient signal
- **Genuine coordinated-pressure finding** — enforcement inconsistency that single-identity testing did not surface

### CLI Interface

- `--team` enables Stage 4 (implies `--recursive`)
- `--fresh-team` deletes persona identity files before creating new ones (required for canonical verification runs)
- `--static` and `--team` are mutually exclusive

### Identity Persistence

Default: load existing persona identities if files exist, create if not. `--fresh-team` deletes and recreates. Canonical runs must use `--fresh-team`.

---

## Stage 5 Design (v0.5.0) — Coordinated Swarms

### Thesis

Can an accountability system that held up against one coordinated team still hold when adversarial pressure comes from three independent teams with distinct strategic objectives and indirect coordination?

### Structure

Three teams of three agents — 9 identities total — each team with a distinct strategic objective:

| Team | Objective | Agents |
|------|-----------|--------|
| Alpha | Reconnaissance — map defenses, discover endpoints, probe timing | 3 agents |
| Beta | Trust exploitation — build reputation, then exploit trust assumptions | 3 agents |
| Gamma | Coordinated pressure — synchronized attacks to overwhelm per-identity defenses | 3 agents |

### Per-Team Strategists

Each team has its own Claude-powered strategist that picks attacks for its agents each round. Strategists see their own team's results plus the shared intelligence log — they do not see other teams' raw results directly.

### Campaign Coordinator

An informational campaign coordinator synthesizes intelligence across teams via a shared intelligence log. The coordinator does not direct teams — it synthesizes findings and publishes summaries that per-team strategists can read. Indirect coordination: teams influence each other through shared intelligence, not commands.

### Shared Intelligence Log

Teams publish findings to a shared log after each round. The coordinator synthesizes cross-team patterns. Per-team strategists read the log before picking next-round attacks. This creates emergent coordination without top-down control.

### Execution Model

Interleaved execution with deterministic logging. Teams take turns executing rounds (Alpha → Beta → Gamma per round cycle). 5-round default campaigns. Deterministic logging ensures reproducible analysis of cross-team interactions.

### Three-Layer Budget Model

1. **Per-agent budget** — each of the 9 agents has an individual bond budget
2. **Per-team budget** — each team has a team-level cap (sum of its agents' budgets)
3. **Campaign cap** — overall campaign budget caps total spend across all teams

### Counterfactual Success Test

A finding is classified as **swarm-emergent** only if removing any one contributing team makes it materially less plausible. This prevents inflating single-team findings as swarm results.

### Reporter Three-Tier Provenance

Each finding classified by provenance:
- **Single-team** — one team discovered it independently
- **Cross-team assisted** — one team's intel helped another team find it
- **Swarm-emergent** — required contributions from multiple teams; fails the counterfactual test without any one team

### Build Plan

Two sub-stages:
- **v0.5.0-alpha:** Architecture + Alpha team + Gamma team (reconnaissance + pressure — the two ends of the attack spectrum)
- **v0.5.0:** Add Beta team (trust exploitation) + full reporting with three-tier provenance

### Audit Trail

Design triple-audited by ChatGPT, Gemini, and Grok with final ChatGPT confirmation.

---

## Key Files

| File | Purpose |
|------|---------|
| src/cli.ts | Entry point — startup banner, orchestrates full red team run |
| src/runner.ts | Attack runner — iterates 15 scenarios, prints progress, collects results |
| src/log.ts | AttackResult type + AttackLog class (array-backed, returns copies) |
| src/reporter.ts | Sends attack log to Claude API, returns structured findings report |
| src/agentgate-client.ts | AgentGate HTTP client — Ed25519 signing + raw request crafting |
| src/attacks/replay.ts | Replay attack scenarios (1.1–1.3) |
| src/attacks/bond-capacity.ts | Bond capacity attack scenarios (2.1–2.3) |
| src/attacks/signature.ts | Signature tampering scenarios (3.1–3.3) |
| src/attacks/authorization.ts | Authorization boundary scenarios (4.1–4.2) |
| src/attacks/input-validation.ts | Input validation scenarios (5.1–5.3) |
| src/attacks/rate-limit.ts | Rate limiting scenario (6.1) |
| src/personas.ts | Persona type definition, 3 persona configs, identity creation/loading/fresh-team deletion |
| test/agentgate-client.test.ts | AgentGate client tests (2 unit + 1 integration) |
| test/log.test.ts | Attack log tests (3 tests) |
| test/attacks/replay.test.ts | Replay attack integration tests (3 tests) |
| test/attacks/bond-capacity.test.ts | Bond capacity integration tests (3 tests) |
| test/attacks/signature.test.ts | Signature tampering integration tests (3 tests) |
| test/attacks/authorization.test.ts | Authorization boundary integration tests (2 tests) |
| test/attacks/input-validation.test.ts | Input validation integration tests (3 tests) |
| test/attacks/rate-limit.test.ts | Rate limit integration test (1 test) |
| test/runner.test.ts | Full runner integration test (1 test — all 15 scenarios) |
| test/reporter.test.ts | Reporter tests (1 unit + 1 integration) |
| .env.example | Template for environment variables |
| tsconfig.json | TypeScript configuration |
| AGENTS.md | Conventions for AI coding agents |
| README.md | Public-facing documentation |
| LICENSE | MIT License, 2026, James Toole |

---

## What "Done" Looks Like (v0.1.0) — ALL COMPLETE

1. ✅ A CLI tool that runs a predefined battery of attacks against a live AgentGate instance
2. ✅ 15 attack scenarios across 6 categories, all attacking over HTTP from outside
3. ✅ Each attack logged with: scenario name, what was attempted, what AgentGate returned, whether caught
4. ✅ After all attacks complete, Claude API generates a structured findings report
5. ✅ Findings report displayed in terminal
6. ✅ Final summary shows total attacks, caught count, uncaught count
7. ✅ 24 tests across 10 test files, all passing
8. ✅ All attacks target AgentGate over HTTP from outside (no direct database access)

---

## What Is Explicitly NOT Part of v0.1.0

- No adaptive strategy (Stage 2) — attacks are predefined, not adjusted between rounds
- No recursive self-improvement (Stage 3) — no novel attack generation
- No web UI — CLI only
- No CI — GitHub Actions not set up yet
- No deployment — local only
- No multi-round attack campaigns — one pass through all scenarios per run
- No concurrent attacks — scenarios run sequentially
- No report persistence — report displayed in terminal, not saved to file

---

## What "Done" Looks Like (v0.2.0) — ALL COMPLETE

1. ✅ Attack library expanded to 48 scenarios across 12 categories (up from 15 across 6)
2. ✅ Attack registry maps all scenario IDs to parameterized execute functions
3. ✅ Claude-powered strategist picks 5-15 attacks per round based on prior results
4. ✅ Multi-round adaptive loop (default 3 rounds) with strategy escalation
5. ✅ Fallback to default high-priority attacks if strategist API fails
6. ✅ Reporter generates multi-round report with strategy evolution analysis
7. ✅ Rich side-effect collection (reputation, bond state, dashboard checks)
8. ✅ --static flag for backward-compatible fixed-order regression testing
9. ✅ --rounds N flag for configurable round count
10. ✅ All 48 attacks caught in static mode against live AgentGate
11. ✅ 51 tests across 18 test files, all passing

---

## What "Done" Looks Like (v0.3.0) — ALL COMPLETE

1. ✅ Sandbox child runner with global nullification — dangerous globals deleted, IPC communication working
2. ✅ Parent-side executor — spawns permission-restricted child, scrubbed env, timeout, memory cap, cleanup
3. ✅ IPC toolkit — all 11 toolkit methods execute in parent via IPC, child is logic-only
4. ✅ Validator — blocklist + positive structural checks + novelty gate
5. ✅ Reasoner — Claude API analyzes prior results, produces novel attack hypotheses
6. ✅ Generator — Claude API turns hypotheses into toolkit-constrained JavaScript functions
7. ✅ Recursive mode wired into runner loop — --recursive flag, novel attacks run alongside library attacks
8. ✅ Reporter expanded for recursive mode — distinguishes library vs novel attacks, shows reasoning
9. ✅ End-to-end verification — 3-round recursive session against live AgentGate
10. ✅ 8-round Claude Code audit of v0.3.0
11. ✅ README sync + v0.3.0 tag

---

## What "Done" Looks Like (v0.4.0) — ALL COMPLETE

1. ✅ Three personas with separate AgentGate identities and mechanically distinct bond budgets
2. ✅ Strategist assigns attacks to specific personas with reasoning
3. ✅ Two working coordination patterns: handoff and distributed_probe
4. ✅ Every coordinated op declares target defense, expected signal, and why multi-identity is required
5. ✅ All three personas exercised by end of Round 2 in canonical run
6. ✅ At least one coordinated operation executed after Round 1 in canonical run
7. ✅ Recursive novel attack generation can be persona-targeted (narrow context only)
8. ✅ Reporter shows empirical per-persona breakdown and coordinated operation results with three-category outcome classification
9. ✅ One live 3-round --fresh-team run verified against live AgentGate
10. ✅ 8-round Claude Code audit completed
11. ✅ README sync + v0.4.0 tag

---

## Completed Milestones

1. ✅ Project setup: repo initialized, .gitignore, AGENTS.md, package.json, tsconfig.json, .env.example
2. ✅ Dependencies installed: typescript, tsx, vitest, @anthropic-ai/sdk, dotenv, @types/node
3. ✅ Source file structure scaffolded with placeholder exports (11 source files)
4. ✅ AgentGate client copied from Agent 003, adapted. 3 tests (2 unit + 1 integration).
5. ✅ Attack log module implemented with copy protection. 3 tests.
6. ✅ Replay attack scenarios implemented and tested: 3/3 caught by AgentGate
7. ✅ Bond capacity attack scenarios implemented and tested: 3/3 caught by AgentGate
8. ✅ Signature tampering attack scenarios implemented and tested: 3/3 caught by AgentGate
9. ✅ Authorization boundary attack scenarios implemented and tested: 2/2 caught by AgentGate
10. ✅ Input validation attack scenarios implemented and tested: 3/3 caught by AgentGate
11. ✅ Rate limit attack scenario implemented and tested: 1/1 caught by AgentGate
12. ✅ Attack runner implemented — iterates all 15 scenarios, prints progress. 1 integration test.
13. ✅ Reporter implemented — Claude API generates structured findings report. 2 tests (1 unit + 1 integration).
14. ✅ CLI wired up — full orchestration: identity → attacks → report → summary. Verified end to end against live AgentGate.
15. ✅ README and MIT License added.
16. ✅ v0.1.0 tagged — 24 tests passing, 15/15 attacks caught.
17. ✅ 8-round Claude Code audit of v0.1.0 completed — Auth & Identity, Attack Scenario Correctness, Input Validation & Edge Cases, AgentGate Client & HTTP Safety, Error Handling & Resilience, Reporter & LLM Integration, Documentation Accuracy, Dependency & Supply Chain. 7 items documented as known limitations across 8 rounds, 0 code fixes needed. Rounds 1, 6, 7, 8 passed clean. No critical or high findings.
18. ✅ Stage 2 attack library drafted — 46 scenarios across 10 categories, designed against AgentGate's actual defenses (v0.3.0).
19. ✅ Triple audit of Stage 2 attack library (ChatGPT + Gemini + Grok) — all three flagged MCP surface, market abuse, and economic/reputation manipulation as gaps. Consensus: add 12 scenarios across 4 new categories, merge 4 redundancy pairs, demote 2 to Tier 2. Final library: 47 Tier 1 + 2 Tier 2 across 12 categories.
20. ✅ Strategist prompt designed — Claude API inside the adaptive loop, sees full library every round, picks 5-15 attacks, returns structured JSON, escalates from recon → boundary → chains, discovers chains organically.
21. ✅ Runner loop architecture designed — multi-round orchestration, attack registry pattern, rich success criteria, strategist fallback on API failure, --rounds and --static CLI flags.
22. ✅ Stage 2 planning complete — ready to build.
23. ✅ Attack registry implemented (src/registry.ts) — maps all scenario IDs to metadata and execute functions. 24 tests passing.
24. ✅ Step 3b complete — all 15 existing attacks refactored to accept optional params. Replay (1.1–1.3), bond-capacity (2.1–2.3), signature (3.1–3.3), authorization (4.1–4.2), input-validation (5.1–5.3), rate-limit (6.1). All parameterizable by the strategist. 24 tests passing.
25. ✅ Step 3c complete — all 32 new attack scenarios implemented across 7 new files + 5 expanded files. 48 total scenarios across 12 categories, all registered in the registry, all parameterized. New categories: Timing & Race Conditions (7), Protocol Abuse (8), MCP Transport Abuse (9), Market Abuse (10), Economic & Reputation (11), Recon & Side-Channel (12). MCP and market attacks gracefully handle unavailable services. Runner test timeout bumped to 120s. 24 tests passing, all 48 scenarios caught by AgentGate.
26. ✅ Step 3d complete — Strategist module (src/strategist.ts) implemented. pickAttacks() calls Claude API with full library menu, parses structured JSON. getDefaultAttacks() fallback for API failure. buildLibraryMenu() converts registry metadata. 3 tests (27 total).
27. ✅ Step 3e complete — Runner loop refactored for multi-round adaptive orchestration. runSelectedAttacks() for strategist-picked attacks, runAllAttacksStatic() for --static mode. CLI supports --rounds N and --static flags. Updated startup banner. 2 new tests (29 total).
28. ✅ Step 3f complete — Reporter expanded for multi-round coverage. generateReport() accepts optional StrategyResponse[] for per-round breakdown and strategy evolution analysis. max_tokens bumped to 4000. Backward-compatible — static mode unchanged. 2 new tests (31 total).
29. ✅ Step 3g complete — Rich result collection via side-effects utilities. SideEffects interface added to AttackResult (backward-compatible). getReputation(), getBondStatus(), checkDashboardForRawHtml() — all error-safe with 5s timeout. Wired into attacks 11.1 and 12.2 as proof of concept. Strategist formats side-effects in prior results. 3 new tests (34 total).
30. ✅ Step 3i complete — Integration tests for attack categories 7-12. 6 new test files covering timing, protocol, MCP, market, economic, and recon attacks. All follow established pattern with generous timeouts. 17 new tests (51 total).
31. ✅ Step 3j complete — Manual end-to-end verification against live AgentGate. Adaptive loop (3 rounds, 37 attacks) ran successfully. Strategist demonstrated genuine adaptation: broad recon → boundary probing → economic escalation. Found 4 documented design limitations (Sybil, identity flood, reputation pumping, resource exhaustion).
32. ✅ Rate-limit interference fix — Attacks 2.6, 2.7, 4.2, 7.1 now create fresh identities for setup steps to avoid rate-limit budget consumption from other attacks in the same round. Also fixed 4.2 correctness (now uses separate identities for victim/attacker).
33. ✅ Static mode verified — all 48 attacks caught, 0 uncaught against live AgentGate.
34. ✅ v0.2.0 tagged — Stage 2 (Adaptive Red Team) complete. 51 tests passing, 48 attack scenarios across 12 categories, 3-round adaptive loop with Claude-powered strategist.
35. ✅ 8-round Claude Code audit of v0.2.0 completed — Auth & Identity, Attack Scenario Correctness, Strategist & LLM Integration, Runner & Orchestration, Input Validation & Edge Cases, Error Handling & Resilience, Documentation Accuracy, Dependency & Supply Chain. 7 findings across 8 rounds: 3 code fixes (attack 2.5 tautological caught logic, attack 12.2 dashboard-unreachable false positive, --rounds capped at 20), 1 config fix (reporter max_tokens 4000→8000), 1 documentation fix (--static + --rounds precedence), 2 documented as known limitations (Claude API timeout, --target credential exposure). Rounds 1, 7, 8 passed clean. No critical findings. All 51 tests passing.
36. ✅ Multi-AI audit of v0.2.0 (ChatGPT + Gemini + Grok) — scoped to concept/positioning/article readiness. All three confirmed 001→004 progression is coherent and not forced. Consensus on strongest objection: "this is just automated testing with extra steps" — article must lead with internal-tests-vs-external-HTTP distinction. All three warned against overclaiming Stage 3 (recursive) before it ships. All three said the four discovered limitations (Sybil, identity flood, reputation pumping, resource exhaustion) should be featured as evidence of rigor, not hidden. ChatGPT's recommended positioning: "external adversarial harness for bonded-agent infrastructure." Grok flagged that public READMEs are out of sync with v0.2.0 reality — fix before publishing. Article deferred until after v0.3.0.
37. ✅ Milestone 1 complete — Sandbox child runner (`src/sandbox/child-runner.js`) with global nullification. 15 dangerous globals deleted before generated code runs. IPC communication working. Frozen stub toolkit. 6 tests (fetch blocked, require blocked, process blocked, createIdentity cap, toolkit frozen, basic execution).
38. ✅ Milestone 2 complete — Parent-side sandbox executor (`src/sandbox/executor.ts`). Permission-restricted child process with scrubbed env, 15s timeout, 64MB memory cap, temp directory lifecycle, macOS symlink resolution. 6 tests (basic execution, syntax error handling, timeout/SIGKILL, filesystem block, temp cleanup, log collection).
39. ✅ Milestone 3 complete — IPC toolkit (`src/sandbox/toolkit-host.ts`). All HTTP calls execute in parent via IPC — child is logic-only. 11 toolkit methods, all with 5s timeout and 4KB response cap. createIdentity capped at 3 (defense in depth). Stub host for unit tests. 3 integration tests against live AgentGate.
40. ✅ Milestone 4 complete — Validator (`src/sandbox/validator.ts`). Blocklist (34 patterns + 3 obfuscation + concatenation heuristic), positive structural checks (signature, length, nesting, toolkit count, loops, return shape), novelty gate (60% word-overlap threshold). 18 tests.
41. ✅ Milestone 5 complete — Reasoner (`src/reasoner.ts`). Claude API analyzes prior round results, produces 2-5 novel attack hypotheses with target defense, rationale, and confidence. Graceful fallback on API failure. 6 tests.
42. ✅ Milestone 6 complete — Generator (`src/generator.ts`). Claude API turns hypotheses into toolkit-constrained JavaScript functions. Two one-shot examples, strict constraints, retry on validation failure, novelty check. 7 tests.
43. ✅ Milestone 7 complete — Recursive mode wired into runner loop. `--recursive` flag, `runRecursiveRound()` orchestrates strategist → reasoner → generator → sandbox per round. Novel attacks run alongside library attacks. 1 integration test.
44. ✅ Milestone 8 complete — Reporter expanded for recursive mode. Distinguishes library vs novel attacks, includes hypotheses, generated code samples, strategy evolution analysis. Backward compatible. 2 tests.
45. ✅ Milestone 9 complete — End-to-end verification. All three modes verified: static (48/48 caught), adaptive (working), recursive (3 rounds, 15 novel attacks generated and executed, 14/15 caught, 1 uncaught health endpoint probe). 100 tests passing. No code fixes needed.
46. ✅ 8-round Claude Code audit of v0.3.0 completed — Auth & Identity, Attack Scenario Correctness, Sandbox & Isolation, Validator & Generator, Error Handling & Resilience, Runner & Orchestration, Documentation Accuracy, Dependency & Supply Chain. 4 code fixes (SSRF path validation, generator example API paths, generator example identity handling, README update). 5 items documented as acceptable limitations. Rounds 3, 5, 6, 8 passed clean. No critical findings. 100 tests passing. Zero new dependencies.
47. ✅ README updated for v0.3.0 — all three modes documented, sandbox architecture described, CLI flags documented, test count corrected to 100, Node.js requirement updated to 22+.
48. ✅ v0.4.0 design drafted — multi-identity coordinated pressure with 3 specialist personas (Shadow, Whale, Chaos), two coordination types (handoff, distributed_probe), mechanically distinct bond budgets. Design audited by ChatGPT, Gemini, and Grok. ChatGPT's five structural corrections adopted as backbone: mechanize personas, reframe thesis, restrict coordination types, tighten strategist schema, narrow generator context. Gemini and Grok implementation details folded in.
49. ✅ v0.4.0 build complete — personas.ts, strategist update, runner coordination (handoff + distributed_probe with 500ms stagger), CLI flags (--team, --fresh-team), reporter per-persona breakdown with three-category outcome classification, sandbox persona routing (toolkit.personaName injection), reasoner/generator persona targeting. All 7 build steps completed.
50. ✅ v0.4.0 end-to-end verification — 3-round --fresh-team run against live AgentGate. 8 minutes 14 seconds. 19 library attacks (all caught), 2 coordinated ops (both caught, classified "intended behavior"), 15 novel attacks (15/15 validated, 5 uncaught — all novel boundary probes). AgentGate held up under coordinated multi-identity pressure. No enforcement inconsistency found.
51. ✅ 8-round Claude Code audit of v0.4.0 completed — Auth & Identity, Attack Scenario Correctness, Sandbox & Isolation, Strategist & LLM Integration, Error Handling & Resilience, Runner & Orchestration, Documentation Accuracy, Dependency & Supply Chain. 4 low findings (advisory budgets, sharedIntel passthrough, family affinity — all by design; coordinated op attribution cosmetic). 2 documentation findings fixed in finalization. Rounds 1, 3, 4, 5, 8 passed clean. No critical findings. 130 tests passing. Zero new dependencies.
52. ✅ v0.4.0 finalized — package.json bumped to 0.4.0, README fully updated (four modes, persona table, coordination types, all CLI flags, test count 130/26), Round 6 cosmetic finding documented in Known Issues, v0.4.0 annotated tag pushed.
53. ✅ Codex (OpenAI) cold-eyes code audit of v0.4.0 — 5 findings: 1 critical (SSRF origin escape in sandbox toolkit-host.ts), 3 medium (file permissions on private keys, inconclusive sandbox crash reporting, hard-coded caught:true in recon 12.1), 1 low (tests not hermetic). 4 fixes applied: SSRF origin validation on all 4 HTTP methods with 4 new tests, identity files written with mode 0o600, sandbox crashes prefixed [INCONCLUSIVE], recon 12.1 flipped to caught:false when endpoints leak without auth. Low finding documented as known limitation.
54. ✅ v0.5.0 shipped — Stage 5: Coordinated Swarms. Canonical run results: 97 total attacks (Alpha 37, Beta 22, Gamma 38). 77 caught, 20 uncaught (79% catch rate). Gamma: 100% catch rate (38/38) — economic pressure fully contained. Beta: 48 clean bond cycles in trust-building phase, offensive phase confirmed no reputation-gated capacity. 0 swarm-emergent findings, 2 cross-team findings, remaining single-team. Coordinator synthesis ran every round, demonstrably influenced team strategy. 73 intel log entries. ~5 minutes runtime. Key finding: AgentGate's defenses hold under coordinated 9-agent swarm pressure but lack reputation-gated bond capacity.
55. ✅ Recursive red team run against hardened AgentGate (post-Codex + Claude Code cross-audit, 95 tests, 24 security fixes). 55 total attacks (40 library + 15 novel). 45 caught, 10 reported uncaught. Investigation revealed zero genuinely new vulnerabilities — uncaught results were: already-documented design decisions (unauthenticated GET endpoints), self-resolution blocking (added during audit) preventing Agent 004 from resolving its own actions to trigger auto-ban, and capacity math misunderstandings. Key insight: the self-resolution fix made AgentGate harder to attack from the outside — Agent 004 couldn't manipulate the governance system because it couldn't grade its own work. Auto-ban confirmed working via dedicated test in AgentGate repo.

---

## Known Issues / Tech Debt

- **New identity generated every run** — keypair persisted to file but not shared across agents. Same limitation as Agents 001-003.
- **Integration tests require running services** — both AgentGate and Claude API must be available. Tests skip cleanly when keys are missing.
- **No CI yet** — GitHub Actions not set up. Tests require API keys that can't be in CI without secrets management.
- **Claude report sometimes miscounts** — the LLM-generated report occasionally states the wrong total attack count in prose (e.g., "14" instead of "15"), though the results table is always correct. Cosmetic, varies per API call.
- **Rate limit test assumes clean state** — attack 6.1 assumes no other requests have been made in the last 60 seconds from that identity. In practice not an issue because each test creates a fresh identity. When run via the runner with a shared identity, earlier attacks may consume some of the rate limit budget, so 6.1 may see rate limiting kick in before the 11th request. Still detects rate limiting correctly, but the exact trigger point varies.
- **Orphaned bonds and actions after attacks** — attacks 1.1–1.3, 2.1, 2.3, 3.1–3.3, 4.2, 5.1 all lock bonds that are never resolved. These sit open until AgentGate's sweeper auto-slashes after TTL expiry. No test interference (each attack uses unique IDs). Acceptable for v0.1.0.
- **No report persistence** — findings report printed to terminal, not saved to disk. Could be added with a `--output` flag.
- **Attack 2.3 is slow** — the expired bond test waits 6-7 seconds for TTL to expire. Acceptable.
- **Exposure cents uses Agent 001's pattern** — Math.floor(amountCents / 1.2) to fit within AgentGate's capacity rule. If AgentGate changes the multiplier, this breaks.
- **Claude model is hardcoded** — claude-sonnet-4-20250514 in reporter.ts. Could be configurable.
- **--target with no URL silently falls through** — `npx tsx src/cli.ts --target` (no value) falls through to env var or default. User thinks they're overriding but they're not. UX surprise, not a security issue.
- **--target accepts any URL scheme** — no validation that the scheme is http:// or https://. Could accept file://, ftp://, etc. Not exploitable by a third party (self-hosted CLI tool), but not validated either.
- **Prompt injection via AgentGate responses** — AgentGate error messages are included in attack results sent to Claude API for report generation. A malicious AgentGate could inject prompt instructions. Blast radius limited to a corrupted report — no destructive actions possible. Acceptable for v0.1.0.
- **No top-level error handling in CLI** — `main()` has no try/catch or `.catch()`. If AgentGate is unreachable, Claude API fails, or agent-identity.json is corrupted, the process crashes with a raw stack trace instead of a friendly error message. Attack results printed line-by-line during the run are not lost, but the summary box and report won't print if the failure happens after attacks complete. Same pattern as Agent 003. Acceptable for v0.1.0.
- **Attack helper fetch calls have no timeout** — the main agentgate-client.ts has a 10s AbortController timeout, but the attack files' signedPost/rawPost helpers do not. If AgentGate hangs during an attack, that attack hangs indefinitely. Low risk — user would Ctrl+C, and the runner test has a 60s vitest timeout as backstop.
- **Stage 2 attack count above auditor consensus** — auditors suggested 34-42 scenarios, library has 47 Tier 1. May trim during implementation if any prove redundant in practice.
- **MCP attacks require port 3001 access** — Agent 004 currently only targets port 3000 (REST API). MCP attacks (Category 9) need the agent to also reach port 3001. If running against remote AgentGate, this means mcp.agentgate.run must be reachable.
- **Strategist chain discovery is untested** — the design assumes the strategist will organically discover attack chains across rounds. If it doesn't, we may need to add chain hints to the prompt. Won't know until we test with live API calls.
- **Runner test takes ~70 seconds** — due to timing-dependent attacks (6.3 bucket expiry wait, 2.3 bond expiry wait).
- **Rate limit interference in adaptive mode** — when the strategist picks many setup-heavy attacks in one round, the shared identity can hit the 10/60s rate limit. Fixed for attacks 2.6, 2.7, 4.2, 7.1 (fresh identities). Other attacks may still be affected if the strategist picks an unusually dense round. Acceptable — the static mode is the clean regression path.
- **Temp identity files accumulate** — attacks that create fresh identities may leave agent-identity-temp-*.json files. These are gitignored but accumulate on disk. Manual cleanup or a post-run cleanup step is a v0.3.0 candidate.
- **Reporter attack count sometimes differs from actual** — the Claude-generated report may state a different total (e.g., "42 scenarios" when 48 ran) because it summarizes from the data rather than counting raw results. The terminal SUMMARY box is always correct.
- **Market endpoints return 404** — AgentGate's market feature may not be enabled in all configurations. Market attacks (10.1-10.4) handle this gracefully (return caught with a note).
- **Attack 7.2 parallel resolve allows 0 successes as "caught"** — `caught: succeeded <= 1` means 0 successes also counts as caught. This is defensible: zero successes means no double-resolve exploit occurred — AgentGate blocked all concurrent resolves, which is a stricter outcome than allowing exactly one. No code change needed.
- **Claude API calls have no explicit timeout** — strategist and reporter use the Anthropic SDK's `messages.create()` with no custom timeout. The SDK has a built-in default timeout (~10 minutes). If Claude hangs, the strategist call is protected by the try/catch fallback path; the reporter call would block the summary box. Extremely unlikely in practice. SDK default is a sufficient backstop for a CLI tool.
- **No runtime validation of sandbox result shape** — if generated code returns a malformed object (missing `caught`/`reason`), it's cast without validation. Validator catches this at code level but runtime mismatch would produce misleading results. Low severity.
- **Novel attacks self-report `caught` with no verification** — generated code decides its own caught value. A generated attack could misreport. By design — the generated code has the context to interpret the response, and the operator reviews the details.
- **Hypothesis fields interpolated raw into generator prompt** — a malicious AgentGate response could influence the reasoner's output, which feeds into the generator prompt. Blast radius limited to a bad novel attack — same prompt injection chain documented for the reporter in v0.1.0.
- **Several non-dangerous globals not deleted in sandbox** — Buffer, TextEncoder, TextDecoder, AbortController, SharedArrayBuffer, Atomics, crypto, performance, Reflect, Proxy remain available. None provide network/filesystem/process access. Defense in depth would suggest deleting them.
- **No per-round cap on toolkit calls from child** — validator limits toolkit references in code (max 20), but a loop could repeat calls. 15-second executor timeout is the backstop.
- **Runner test takes ~90-120 seconds** — due to API calls and sandbox execution in recursive mode.
- **Coordinated op results attributed to first persona in summary** — in team mode, coordinated op results are accumulated into perPersonaAccum under the first persona in the op. The final TEAM SUMMARY per-persona counts are slightly inaccurate for the second persona. Does not affect overall totals, exit code, or reporter (which gets coordinated ops separately). Cosmetic.
- **Bond budgets are advisory, not enforced at runtime** — strategist is told persona budgets in the prompt but no code prevents Shadow from locking a 100-cent bond. By design — budgets are a constraint the strategist reasons about, not a runtime guard.
- **sharedIntel param passed but ignored by library attacks** — handoff intel is passed as a param to Persona B's attack but no library attack reads it. Intel informs strategist's attack selection, not attack execution. Novel attacks can use it via generator prompt.
- **Attack-family affinity not enforced at runtime** — strategist is told each persona's categories but can assign any attack to any persona. By design — preserves strategist flexibility.
- **FIXED in Codex audit: SSRF origin escape in sandbox toolkit** — `//attacker.example/...` paths could redirect parent HTTP calls to arbitrary hosts. Fixed: `buildAndValidateUrl()` verifies resolved origin matches target origin.
- **FIXED in Codex audit: Private key files (agent-identity*.json) written world-readable** — Fixed: `mode: 0o600` on all `writeFileSync` calls.
- **FIXED in Codex audit: Sandbox crashes/timeouts silently reported as caught: true** — Fixed: prefixed with `[INCONCLUSIVE]` to distinguish from genuine catches.
- **FIXED in Codex audit: Recon attack 12.1 hard-coded caught: true when unauthenticated endpoints leaked data** — Fixed: now reports `caught: false`.
- **Agent 004's novel attacks may misinterpret self-resolution blocking as a defense failure** — the attacker can't resolve its own actions, so governance triggers (like auto-ban) appear broken from the attacker's perspective. This is AgentGate working correctly, not a bug.
- **Beta's trust-building completes successfully but AgentGate does not expose reputation scores or gate bond capacity on identity history.** The offensive phase tests whether capacity limits exist at all, not whether trust unlocks them. The canonical v0.5.0 run found 0 swarm-emergent findings — the 500¢ bond acceptance is an identity-agnostic capacity gap, not a reputation-based privilege escalation. This is documented as an AgentGate enhancement opportunity.
- **Prompt injection via AgentGate responses flows through swarm coordinator and intel log** — attack result details are included in the coordinator's Claude API prompt, which produces synthesis entries in the shared intel log, which feeds into all three team strategists. A malicious AgentGate could corrupt coordinator synthesis → intel log → strategist picks. Three amplification points. Blast radius: suboptimal attack selection. No destructive actions possible (coordinator can only write to intel log, strategists can only pick from the library). Same pattern as the v0.1.0 reporter prompt injection, but with a longer chain.
- **FIXED in v0.5.0 audit: Cross-team agentId validation** — strategist parsers now validate that Claude-returned agentIds belong to the requesting team. Invalid agentIds default to agent-1 of the correct team. Execution guard in swarm-runner rejects cross-team identity mismatches.

---

## Design Decisions

| Decision | Why | Would Reconsider If... |
|----------|-----|----------------------|
| Stage 1 only for v0.1.0 | Foundation first. Can't build adaptive/recursive on a shaky harness. | Stage 1 is trivially simple (it isn't — 15 scenarios is substantial) |
| Claude API for report generation | Claude synthesizes patterns across 15 results better than a template. Also wires in LLM plumbing for Stage 2. | Cost concern (unlikely — one API call per run) |
| Sequential attacks, not concurrent | Easier to debug, clearer logs. Concurrent is a Stage 2/3 feature. | Need to test AgentGate's concurrency handling |
| Each attack manages its own bonds | Simpler than having the runner add a bond layer on top. Each attack knows what setup it needs. | Attacks need a shared bond for economic reasons |
| Local AgentGate as default target | Safe for development. --target flag allows remote targeting. | Article demo needs remote attacks |
| Separate attack files per category | Clean separation. Each category testable independently. | Total count small enough for one file (it isn't) |
| Copy agentgate-client.ts from Agent 003 | Keeps repos decoupled. Same pattern as all previous agents. | Shared npm package would be cleaner (future) |
| 15 scenarios, not 16 | Original plan had 16 but implementation landed at 15. Correct count. | We identify a missing attack vector worth adding |
| 47 scenarios (above 34-42 auditor consensus) | Auditors agreed the gaps (MCP, market, economic) were real. Adding them plus keeping baselines pushed the count above target. Tier 2 demotion keeps active menu focused. | Implementation shows >5 scenarios are near-identical in practice |
| Full library sent to strategist every round | Strategist needs full context. Sending only unused scenarios prevents re-running with different params. Extra tokens cost ~$0.01/round. | Token cost becomes a concern (extremely unlikely) |
| Loose chain guidance (discover, don't prescribe) | Real attackers improvise. Hardcoded chains make Stage 2 just a longer Stage 1. All three auditors' feedback supported this for Stage 2, with prescribed chains being a Stage 3 feature. | Strategist consistently fails to discover chains after multiple test runs |
| 3 rounds default, configurable | Matches recon → escalate → chain pattern. Keeps API costs low. --rounds flag for power users. | Testing shows 3 rounds is too few for meaningful adaptation |
| Fallback on strategist API failure | A Claude API failure shouldn't kill the entire run. Default to top 10 high-priority attacks. Report notes the fallback. | Fallback selection is too predictable and masks bugs |
| Constrained code gen + IPC toolkit (not raw code execution) | Child is logic-only, parent handles all HTTP. Eliminates network risk without --allow-net. Four rounds of triple audit converged on this. | Stage 4 needs true arbitrary code execution for some reason (unlikely) |
| Global nullification (not just blocklist) | Deleting fetch/require/process from globalThis means even if validator is bypassed, network primitives don't exist in memory. | Node.js changes how globals work in a future version |
| Node 22 permission flags (not Node 25) | Stay on LTS. --allow-fs-write=false and --allow-child-process=false work. Accept missing --allow-net. | Need OS-level network restriction (upgrade to Node 25+ or use Docker) |
| createIdentity() capped at 3 per attack | Prevents degenerate Sybil spam. Forces novel attacks to be clever, not just noisy. Stage 2 already surfaced identity flood as a limitation. | A specific attack hypothesis genuinely needs >3 identities |

---

## Assumptions & Unknowns

### What I know for sure
- AgentGate's API works from external codebases (proven in Agents 001-003, re-proven here)
- All 15 attack vectors are caught by AgentGate — verified via automated tests and live CLI run
- Ed25519 signing format: sha256(nonce + method + path + timestamp + body)
- Claude API generates useful structured reports from attack log data
- The full CLI loop works end to end: identity → attacks → report → summary
- Stage 2 attack library audited by three independent AI auditors — all three converged on MCP, market, and economic gaps; all incorporated
- Strategist prompt design and runner loop architecture are locked
- Stage 4 coordinated operations produce clean results — both handoff and distributed_probe work, AgentGate holds under multi-identity pressure
- 130 tests passing across 26 files, zero new dependencies in v0.4.0
- Stage 5 swarm campaign verified — 9 identities, 5-round interleaved campaigns, coordinator synthesis every round, 97 attacks in canonical run
- AgentGate does not expose reputation scores or gate bond capacity on identity history — Beta's trust-building succeeds mechanically but offensive payoff is identity-agnostic

### What I'm assuming without proof
- That 47 scenarios is the right library size (auditors suggested 34-42, we landed at 47 with Tier 2 demotion — may trim during implementation)
- That 3 rounds is enough for meaningful adaptation (configurable via --rounds flag)
- That the strategist will discover useful attack chains organically without hardcoded templates
- That the article framing will land with a security-minded audience
- That the four-stage arc (static → adaptive → recursive → coordinated) is the right narrative structure for the article

### What I don't know yet
- How long a 3-round adaptive run takes against live AgentGate (more API calls + more attacks per run)
- Whether the strategist produces genuinely different strategies across runs or converges on the same pattern
- How the final report should visualize strategy evolution across rounds
- What Agent 004 Stage 3 (recursive/novel attack generation) will look like architecturally

### What would break this design if wrong
- If AgentGate changes its error codes or response format, attacks will get false positives/negatives
- If AgentGate's auth model changes, the client breaks
- If Claude API changes its response format, the reporter breaks
- If the Claude API strategist consistently picks the same attacks regardless of prior results, the adaptive loop adds cost without value
- If AgentGate's MCP layer (port 3001) is unreachable from Agent 004's HTTP client, the MCP attack category can't be tested

---

## Confidence Tags

- **Project direction:** Tested — v0.1.0 built and verified end to end
- **Architecture:** Tested — all pieces wired together and working
- **Attack scenarios:** Tested — 48 scenarios across 12 categories, all caught by AgentGate, 51 tests passing
- **AgentGate client:** Tested — 3 tests (2 unit + 1 integration)
- **Claude API integration:** Tested — report generation verified with live API call
- **CLI orchestration:** Manually verified — full end-to-end run confirmed in terminal
- **Stage 2 attack library:** Audited — triple-audited by ChatGPT, Gemini, and Grok; all feedback incorporated
- **Stage 2 strategist design:** Tested — strategist demonstrated genuine adaptation across 3 rounds
- **Stage 2 runner architecture:** Tested — multi-round loop verified end-to-end with adaptive and static modes
- **Sandbox isolation:** Audited — 4-layer defense (permission flags, global nullification, IPC toolkit, validator) tested live and audited in Round 3. No critical or high findings on isolation.
- **Recursive reasoning:** Tested — reasoner demonstrated genuine adaptation across 3 rounds (baseline → boundary → economic/Sybil). 15/15 novel attacks passed validation.
- **Generator quality:** Tested — 100% first-attempt validation pass rate in end-to-end run. Corrected API paths in audit Round 2.
- **Stage 4 personas:** Tested — 3-round --fresh-team run verified all three personas receive assignments matching specialties
- **Coordinated operations:** Tested — both handoff and distributed_probe executed successfully, classified as "intended behavior"
- **Multi-identity pressure:** Tested — AgentGate held up, no enforcement inconsistency under coordinated cross-identity load
- **Codex audit:** Completed — cold-eyes code audit by OpenAI Codex, 5 findings, 4 fixed, 1 documented
- **Stage 5 swarm campaigns:** Tested — canonical 5-round run with 9 agents, 97 attacks, coordinator synthesis every round
- **Dual-control resolution:** Tested — all resolve calls use separate resolver identity, verified against live AgentGate
- **Beta trust-building:** Tested — 48 clean bond cycles succeeded, but reputation-gated capacity not present in AgentGate

---

## Next Steps

1. Write the Medium article for Agent 003 (Email Rewriter) — give Agent 002's article breathing room
2. Write the Medium article for Agent 004 — all five stages shipped. Full arc: static → adaptive → recursive → coordinated team → coordinated swarms. Lead with internal-tests-vs-external-HTTP distinction. Feature the swarm result ("AgentGate held up under coordinated 9-agent swarm pressure"). Show generated attack code. Address "this is just automated testing with extra steps" objection. Feature discovered limitations (including honest Beta reputation finding) as evidence of rigor. Note: 0 swarm-emergent findings — the swarm methodology is sound but AgentGate's lack of reputation-gated capacity means trust-building doesn't unlock differential outcomes.
3. Update AgentGate README with Agent 004 v0.5.0 in "Built With AgentGate" section.
4. Consider Agent 005 — Recursive Code Reviewer. Reuse the sandbox architecture from Agent 004 in a constructive context. Strongest framing: "I took the sandbox that survived 100+ adversarial tests and turned it into something constructive."
5. Stage 5 (v0.5.0): Coordinated Swarms — design locked, ready to build v0.5.0-alpha.

---

## Important Notes for Future Claude Sessions

- James has zero prior coding experience and directs AI agents to write all code
- Always take baby steps and explain terminal commands simply — always specify what folder to be in before giving a terminal command
- The project folder is at ~/Desktop/projects/agent-004-red-team
- Claude Code is the primary coding tool — James pastes instructions into Claude Code
- Claude Code edits files locally — James must run git push separately to update GitHub (though Claude Code sometimes pushes on its own)
- The GitHub repo is "agent-004-red-team" under the "selfradiance" account — remote uses SSH: git@github.com:selfradiance/agent-004-red-team.git
- AgentGate must be running for this agent to work — remind James to start it with: cd ~/Desktop/projects/agentgate && npm run restart
- All projects live under ~/Desktop/projects/ — never reference ~/Desktop/<project> directly
- James also keeps ChatGPT and Gemini updated with the latest markdown file as backup collaborators
- At the end of every session, always update both the project context file and README.md before the final commit
- .env contains both AGENTGATE_REST_KEY and ANTHROPIC_API_KEY — never commit .env
- When working across multiple projects in one session (e.g., Agent 004 + AgentGate), update BOTH project context files before ending the session
- The Claude Code desktop app doesn't clearly show which folder it's working in — always confirm with `cd <path> && pwd` when starting a new session
