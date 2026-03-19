# Agent 004: Red Team Simulator

A bonded red team agent that attacks live AgentGate infrastructure, logs results, and generates a findings report. Built on the bond-and-slash accountability model — the attacker posts collateral too.

## What This Does

Agent 004 runs 15 predefined attack scenarios against a live AgentGate instance over HTTP. Each attack probes a different defense: replay protection, bond capacity enforcement, signature verification, authorization boundaries, input validation, and rate limiting. After all attacks complete, Claude API generates a structured security findings report.

This is the fourth agent built on [AgentGate](https://github.com/selfradiance/agentgate). It's the first one designed to attack rather than use the system.

## The Agent Progression

- **Agent 001** ([File Transform](https://github.com/selfradiance/agent-001-file-transform)): Deterministic verification — hash match
- **Agent 002** ([File Guardian](https://github.com/selfradiance/agent-002-file-guardian)): Command-based verification — script pass/fail
- **Agent 003** ([Email Rewriter](https://github.com/selfradiance/agent-003-email-rewriter)): Human judgment — approve/reject
- **Agent 004** (Red Team Simulator): Adversarial testing — attack and report

## Prerequisites

- Node.js 20+
- A running [AgentGate](https://github.com/selfradiance/agentgate) instance (local or remote)
- An Anthropic API key (for report generation)

## Setup

```bash
git clone git@github.com:selfradiance/agent-004-red-team.git
cd agent-004-red-team
npm install
cp .env.example .env
# Edit .env with your keys
```

## Usage

```bash
npx tsx src/cli.ts
```

Or target a specific AgentGate instance:

```bash
npx tsx src/cli.ts --target https://agentgate.run
```

## Attack Categories

| Category | What It Tests |
|----------|---------------|
| Replay Attacks | Duplicate nonces, reused signatures, and expired timestamps are rejected |
| Bond Capacity | Over-committed exposure, double-resolve, and expired bonds are blocked |
| Signature Tampering | Wrong keys, garbage signatures, and missing headers are caught |
| Authorization Boundaries | Admin endpoints require admin keys, cross-identity resolution is denied |
| Input Validation | Oversized payloads, excessive TTLs, and negative amounts are rejected |
| Rate Limiting | Burst request floods beyond the per-identity limit are throttled |

## Tests

```bash
npm test
```

24 tests across 10 test files. Integration tests require a running AgentGate instance and valid API keys.

## Tech Stack

TypeScript, Node.js 20+, Vitest, Anthropic Claude API, Ed25519 signing

## License

MIT

## Part of the AgentGate Ecosystem

- [AgentGate](https://github.com/selfradiance/agentgate) — the enforcement engine
- [Agent 001: File Transform](https://github.com/selfradiance/agent-001-file-transform)
- [Agent 002: File Guardian](https://github.com/selfradiance/agent-002-file-guardian)
- [Agent 003: Email Rewriter](https://github.com/selfradiance/agent-003-email-rewriter)
