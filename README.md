# Agent 004: Red Team Simulator

An adaptive, recursive, and coordinated red team agent that attacks live AgentGate infrastructure with three specialist personas. Claude picks attacks, reasons about defense gaps, generates novel JavaScript attack code in a sandbox, and coordinates multi-identity pressure testing. Built on the bond-and-slash accountability model — the attacker posts collateral too.

## What This Does

Agent 004 runs 48 attack scenarios across 12 categories against a live AgentGate instance over HTTP. Four modes of operation:

- **Static:** Runs all 48 attacks in fixed order (regression testing)
- **Adaptive:** A Claude-powered strategist picks attacks each round and adapts based on results (default)
- **Recursive:** Adaptive mode plus novel attack generation — Claude writes new JavaScript attack code and executes it in a permission-restricted sandbox
- **Team:** Three specialist personas (Shadow, Whale, Chaos) with separate identities, bond budgets, and coordinated operations — tests whether per-identity defenses hold under multi-identity pressure

This is the fourth agent built on [AgentGate](https://github.com/selfradiance/agentgate). It's the first one designed to attack rather than use the system.

## The Agent Progression

- **Agent 001** ([File Transform](https://github.com/selfradiance/agent-001-file-transform)): Deterministic verification — hash match
- **Agent 002** ([File Guardian](https://github.com/selfradiance/agent-002-file-guardian)): Command-based verification — script pass/fail
- **Agent 003** ([Email Rewriter](https://github.com/selfradiance/agent-003-email-rewriter)): Human judgment — approve/reject
- **Agent 004** (Red Team Simulator): Adversarial testing — attack and report

## Prerequisites

- Node.js 22+ (for `--permission` flag used by the sandbox)
- A running [AgentGate](https://github.com/selfradiance/agentgate) instance (local or remote)
- An Anthropic API key (for strategist, reasoner, generator, and report generation)

## Setup

```bash
git clone git@github.com:selfradiance/agent-004-red-team.git
cd agent-004-red-team
npm install
cp .env.example .env
# Edit .env with your keys
```

## Usage

Adaptive mode (default — 3 rounds, strategist picks attacks):

```bash
npx tsx src/cli.ts
```

Adaptive with custom rounds:

```bash
npx tsx src/cli.ts --rounds 5
```

Static mode (all 48 attacks in fixed order — for regression testing):

```bash
npx tsx src/cli.ts --static
```

Recursive mode (adaptive + novel attack generation in a sandbox):

```bash
npx tsx src/cli.ts --recursive
```

Team mode (3 personas with coordinated operations):

```bash
npx tsx src/cli.ts --team
```

Team mode with fresh identities (required for canonical verification runs):

```bash
npx tsx src/cli.ts --team --fresh-team
```

Team mode with custom rounds:

```bash
npx tsx src/cli.ts --team --rounds 5
```

Target a specific AgentGate instance:

```bash
npx tsx src/cli.ts --target https://agentgate.run
```

**Flag rules:**
- `--static` and `--team` are mutually exclusive (exits with error)
- `--static` and `--recursive` are mutually exclusive
- `--fresh-team` requires `--team`
- `--team` implies recursive mode (novel attack generation is included)
- If `--static` and `--rounds` are both passed, `--static` takes precedence and `--rounds` is ignored

## Stage 2: Adaptive Mode

The default mode runs a 3-round adaptive loop:

1. **Round 1:** Strategist picks low-cost probes — recon, protocol checks, signature fuzzing. Gathers intelligence across many categories.
2. **Round 2:** Strategist escalates based on Round 1 results — boundary probing, timing attacks, race conditions. Doubles down on anything that returned unexpected results.
3. **Round 3:** Highest-value targets — multi-step chains, Sybil campaigns, economic attacks, market abuse. Uses everything learned in prior rounds.

The strategist cannot invent new attacks — it picks from the 48-scenario library and can tune parameters (e.g., timestamp age, payload size, identity count) to probe boundaries.

## Stage 3: Recursive Mode

Recursive mode adds novel attack generation on top of the adaptive loop. Each round:

1. **Strategist** picks library attacks (same as adaptive)
2. **Reasoner** analyzes all prior results and hypothesizes 2-5 novel attack vectors
3. **Generator** turns each hypothesis into a JavaScript attack function using a constrained toolkit API
4. **Validator** checks the generated code against a blocklist, structural rules, and novelty gate
5. **Sandbox** executes the validated code in a permission-restricted Node.js child process

The sandbox has four layers of defense:
- **Node.js permission flags** — filesystem and child process restrictions
- **Global nullification** — dangerous globals (fetch, require, process, eval, Function, timers) deleted before code runs
- **IPC-only toolkit** — generated code can only call toolkit methods that send IPC messages to the parent; the parent makes all real HTTP calls
- **String-level validator** — blocklist catches hallucinated dangerous patterns before execution

## Stage 4: Team Mode

Team mode adds three specialist personas with separate AgentGate identities and coordinated operations. The thesis: can an accountability system that is robust against one attacker still hold up when adversarial pressure is distributed across multiple identities with coordinated roles?

### The Personas

| Persona | Specialty | Bond Budget | Attack Families |
|---------|-----------|-------------|-----------------|
| Shadow | Recon & Timing | 50¢ | Replay, Signature, Timing, Recon |
| Whale | Economic & Bond | 200¢ | Bond, Rate Limit/Sybil, Market, Economic |
| Chaos | Input Fuzzing & Protocol | 100¢ | Authorization, Input Validation, Protocol, MCP |

### Coordination Types

**Handoff:** Persona A runs an attack and produces a finding. That intel is passed to Persona B, whose attack is parameterized by the intel. Tests whether intel from one identity helps another identity exploit a defense.

**Distributed Probe:** Two personas attack the same defense simultaneously from their own identities (500ms stagger). Tests whether AgentGate's per-identity defenses remain correctly isolated under concurrent cross-identity load.

## Attack Categories

| Category | Scenarios | What It Tests |
|----------|-----------|---------------|
| Replay & Timestamp | 5 | Duplicate nonces, reused signatures, expired and future timestamps |
| Bond & Exposure | 7 | Capacity limits, double-resolve, expired bonds, multi-action exhaustion |
| Signature & Header Abuse | 5 | Wrong keys, garbage signatures, cross-endpoint, header canonicalization |
| Authorization & Identity | 5 | Admin access, cross-identity resolution, duplicate keys, auto-ban |
| Input Validation | 6 | Oversized payloads, TTL caps, negative amounts, type coercion, max-length |
| Rate Limiting & Sybil | 3 | Burst floods, Sybil bypass, bucket expiry |
| Timing & Race Conditions | 3 | Sweeper races, parallel resolve, rapid identity creation |
| Protocol Abuse | 2 | Wrong HTTP methods, wrong Content-Type |
| MCP Transport Abuse | 3 | Unauthenticated MCP, session exhaustion, oversized payloads |
| Market Abuse | 4 | Early resolution, auth bypass, position spam, malformed payloads |
| Economic & Reputation | 3 | Reputation pumping, Sybil campaigns, resource exhaustion |
| Recon & Side-Channel | 2 | Endpoint data mapping, XSS payload escaping |

## Tests

```bash
npm test
```

130 tests across 26 test files. Integration tests require a running AgentGate instance and valid API keys.

## Tech Stack

TypeScript, Node.js 22+, Vitest, Anthropic Claude API, Ed25519 signing

## License

MIT

## Part of the AgentGate Ecosystem

- [AgentGate](https://github.com/selfradiance/agentgate) — the enforcement engine
- [Agent 001: File Transform](https://github.com/selfradiance/agent-001-file-transform)
- [Agent 002: File Guardian](https://github.com/selfradiance/agent-002-file-guardian)
- [Agent 003: Email Rewriter](https://github.com/selfradiance/agent-003-email-rewriter)
