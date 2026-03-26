// Tests for Per-Team Swarm Strategist (Stage 5)

import { describe, it, expect, beforeEach } from "vitest";
import { IntelLog } from "../src/intel-log";
import { getSwarmConfig, type SwarmTeam } from "../src/swarm";
import type { LibraryEntry } from "../src/strategist";
import type { AttackResult } from "../src/log";
import type { SwarmStrategistConfig, SwarmStrategyResponse } from "../src/swarm-strategist";
import {
  buildSwarmSystemPrompt,
  buildSwarmUserMessage,
  parseSwarmStrategyResponse,
  getDefaultSwarmAttacks,
  submitTeamQuestions,
  pickSwarmAttacks,
} from "../src/swarm-strategist";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const swarmConfig = getSwarmConfig();
const alphaTeam = swarmConfig.teams[0];
const betaTeam = swarmConfig.teams[1];
const gammaTeam = swarmConfig.teams[2];

function makeSampleLibrary(): LibraryEntry[] {
  return [
    { id: "1.1", name: "Replay basic", category: "Replay Attacks", defenseTargeted: "nonce", parameterizable: false, priority: "Baseline" },
    { id: "2.1", name: "Bond overspend", category: "Bond & Economic", defenseTargeted: "bond-cap", parameterizable: true, paramDescription: "amount", priority: "High" },
    { id: "3.1", name: "Sig fuzzing", category: "Protocol", defenseTargeted: "signature", parameterizable: false, priority: "Baseline" },
    { id: "4.1", name: "Rate probe", category: "Recon", defenseTargeted: "rate-limit", parameterizable: true, paramDescription: "rate", priority: "Medium" },
    { id: "5.1", name: "Timing attack", category: "Timing", defenseTargeted: "timing", parameterizable: true, paramDescription: "delay_ms", priority: "High" },
    { id: "6.1", name: "Trust escalation", category: "Trust Exploitation", defenseTargeted: "reputation", parameterizable: false, priority: "Medium" },
    { id: "7.1", name: "Economic flood", category: "Economic Attacks", defenseTargeted: "capacity", parameterizable: true, paramDescription: "count", priority: "High" },
  ];
}

function makeConfig(team: SwarmTeam, overrides: Partial<SwarmStrategistConfig> = {}): SwarmStrategistConfig {
  return {
    team,
    currentRound: 1,
    totalRounds: 5,
    priorResults: [],
    sharedIntel: "No prior intelligence available.",
    attackLibrary: makeSampleLibrary(),
    novelAttackResults: [],
    ...overrides,
  };
}

function makeResult(overrides: Partial<AttackResult> = {}): AttackResult {
  return {
    scenarioId: "1.1",
    scenarioName: "Test Scenario",
    category: "recon",
    expectedOutcome: "caught",
    actualOutcome: "403 Forbidden",
    caught: true,
    details: "Request blocked",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// System prompt — team name and objective
// ---------------------------------------------------------------------------

describe("swarm-strategist — system prompt includes team identity", () => {
  it("Alpha prompt includes team name and objective", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(alphaTeam));
    expect(prompt).toContain("Team ALPHA");
    expect(prompt).toContain(alphaTeam.objective);
  });

  it("Beta prompt includes team name and objective", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(betaTeam));
    expect(prompt).toContain("Team BETA");
    expect(prompt).toContain(betaTeam.objective);
  });

  it("Gamma prompt includes team name and objective", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(gammaTeam));
    expect(prompt).toContain("Team GAMMA");
    expect(prompt).toContain(gammaTeam.objective);
  });
});

// ---------------------------------------------------------------------------
// System prompt — team-specific guidance
// ---------------------------------------------------------------------------

describe("swarm-strategist — team-specific guidance", () => {
  it("Alpha prompt emphasizes reconnaissance", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(alphaTeam));
    expect(prompt).toContain("RECONNAISSANCE");
    expect(prompt).toContain("map the attack surface");
    expect(prompt).toContain("Do NOT pick destructive or high-cost attacks");
  });

  it("Beta prompt references trust building in early rounds", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(betaTeam, { currentRound: 1, totalRounds: 5 }));
    expect(prompt).toContain("TRUST EXPLOITATION");
    expect(prompt).toContain("trust-building phase");
    expect(prompt).toContain("Do NOT burn trust yet");
  });

  it("Beta prompt references offensive spending in late rounds", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(betaTeam, { currentRound: 4, totalRounds: 5 }));
    expect(prompt).toContain("TRUST EXPLOITATION");
    expect(prompt).toContain("offensive spending phase");
    expect(prompt).toContain("Burn trust strategically");
  });

  it("Beta prompt transitions at midpoint (round 3 of 5 is still early)", () => {
    const earlyPrompt = buildSwarmSystemPrompt(makeConfig(betaTeam, { currentRound: 3, totalRounds: 5 }));
    expect(earlyPrompt).toContain("trust-building phase");

    const latePrompt = buildSwarmSystemPrompt(makeConfig(betaTeam, { currentRound: 4, totalRounds: 5 }));
    expect(latePrompt).toContain("offensive spending phase");
  });

  it("Gamma prompt emphasizes economic pressure", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(gammaTeam));
    expect(prompt).toContain("COORDINATED ECONOMIC PRESSURE");
    expect(prompt).toContain("bond manipulation");
    expect(prompt).toContain("high-cost, high-impact");
  });
});

// ---------------------------------------------------------------------------
// System prompt — budget and round context
// ---------------------------------------------------------------------------

describe("swarm-strategist — budget and round context", () => {
  it("includes team budget in prompt", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(alphaTeam));
    expect(prompt).toContain(`${alphaTeam.teamBudgetCents}¢`);
    expect(prompt).toContain(`${alphaTeam.agents[0].bondBudgetCents}¢ each`);
  });

  it("includes round context", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(alphaTeam, { currentRound: 3, totalRounds: 7 }));
    expect(prompt).toContain("Round: 3 of 7");
  });

  it("lists all agent IDs", () => {
    const prompt = buildSwarmSystemPrompt(makeConfig(alphaTeam));
    expect(prompt).toContain("alpha-1");
    expect(prompt).toContain("alpha-2");
    expect(prompt).toContain("alpha-3");
  });
});

// ---------------------------------------------------------------------------
// User message — shared intel
// ---------------------------------------------------------------------------

describe("swarm-strategist — user message includes shared intel", () => {
  it("includes shared intel when available", () => {
    const config = makeConfig(alphaTeam, {
      sharedIntel: "=== SHARED INTELLIGENCE LOG ===\n\n--- Round 1 ---\n[beta] (observation) rate-limit: 429 after 10 requests",
    });
    const msg = buildSwarmUserMessage(config);
    expect(msg).toContain("SHARED INTELLIGENCE FROM OTHER TEAMS");
    expect(msg).toContain("429 after 10 requests");
  });

  it("excludes shared intel section when none available", () => {
    const config = makeConfig(alphaTeam, { sharedIntel: "No prior intelligence available." });
    const msg = buildSwarmUserMessage(config);
    expect(msg).not.toContain("SHARED INTELLIGENCE FROM OTHER TEAMS");
  });

  it("includes prior results when available", () => {
    const config = makeConfig(alphaTeam, {
      priorResults: [makeResult({ scenarioId: "3.1", scenarioName: "Sig Fuzz", caught: false, details: "Signature accepted", actualOutcome: "200 OK" })],
    });
    const msg = buildSwarmUserMessage(config);
    expect(msg).toContain("YOUR TEAM'S PRIOR RESULTS");
    expect(msg).toContain("[3.1] Sig Fuzz");
    expect(msg).toContain("UNCAUGHT");
  });

  it("includes novel attack results when available", () => {
    const config = makeConfig(alphaTeam, {
      novelAttackResults: [makeResult({ scenarioId: "N.1", scenarioName: "Novel Probe", caught: true })],
    });
    const msg = buildSwarmUserMessage(config);
    expect(msg).toContain("NOVEL ATTACK RESULTS");
    expect(msg).toContain("[N.1] Novel Probe");
  });

  it("includes round context in user message", () => {
    const config = makeConfig(alphaTeam, { currentRound: 2, totalRounds: 5 });
    const msg = buildSwarmUserMessage(config);
    expect(msg).toContain("round 2 of 5");
  });
});

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

describe("swarm-strategist — parseSwarmStrategyResponse", () => {
  it("parses valid response", () => {
    const json = JSON.stringify({
      round: 1,
      strategy: "Recon sweep",
      selectedAttacks: [
        { id: "1.1", agentId: "alpha-1", reasoning: "Baseline replay check" },
        { id: "3.1", agentId: "alpha-2", params: { delay: 100 }, reasoning: "Sig probe" },
      ],
      questionsForIntelLog: [
        { subject: "rate-limit", content: "Is rate limit per-IP or per-identity?", targetHint: "/v1/actions/execute" },
      ],
    });

    const result = parseSwarmStrategyResponse(json, "alpha");
    expect(result.teamName).toBe("alpha");
    expect(result.round).toBe(1);
    expect(result.strategy).toBe("Recon sweep");
    expect(result.selectedAttacks).toHaveLength(2);
    expect(result.selectedAttacks[0].agentId).toBe("alpha-1");
    expect(result.selectedAttacks[1].params).toEqual({ delay: 100 });
    expect(result.questionsForIntelLog).toHaveLength(1);
    expect(result.questionsForIntelLog[0].targetHint).toBe("/v1/actions/execute");
  });

  it("handles markdown-wrapped JSON", () => {
    const json = "```json\n" + JSON.stringify({
      round: 1,
      strategy: "test",
      selectedAttacks: [{ id: "1.1", agentId: "alpha-1", reasoning: "test" }],
      questionsForIntelLog: [],
    }) + "\n```";

    const result = parseSwarmStrategyResponse(json, "alpha");
    expect(result.selectedAttacks).toHaveLength(1);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseSwarmStrategyResponse("not json", "alpha")).toThrow("invalid JSON");
  });

  it("throws on missing selectedAttacks", () => {
    expect(() => parseSwarmStrategyResponse(JSON.stringify({ round: 1, strategy: "x" }), "alpha")).toThrow("missing 'selectedAttacks'");
  });

  it("defaults agentId when missing", () => {
    const json = JSON.stringify({
      round: 1,
      strategy: "test",
      selectedAttacks: [{ id: "1.1", reasoning: "no agent specified" }],
      questionsForIntelLog: [],
    });
    const result = parseSwarmStrategyResponse(json, "beta");
    expect(result.selectedAttacks[0].agentId).toBe("beta-1");
  });

  it("handles empty questionsForIntelLog gracefully", () => {
    const json = JSON.stringify({
      round: 1,
      strategy: "test",
      selectedAttacks: [{ id: "1.1", agentId: "gamma-1", reasoning: "test" }],
    });
    const result = parseSwarmStrategyResponse(json, "gamma");
    expect(result.questionsForIntelLog).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

describe("swarm-strategist — fallback", () => {
  it("returns valid response with usedFallback flag", () => {
    const config = makeConfig(alphaTeam);
    const result = getDefaultSwarmAttacks(config);
    expect(result.usedFallback).toBe(true);
    expect(result.teamName).toBe("alpha");
    expect(result.round).toBe(1);
    expect(result.selectedAttacks.length).toBeGreaterThan(0);
    expect(result.questionsForIntelLog).toHaveLength(0);
  });

  it("Alpha fallback selects recon/baseline attacks", () => {
    const config = makeConfig(alphaTeam);
    const result = getDefaultSwarmAttacks(config);
    expect(result.strategy).toContain("alpha");
    // Should have selected some attacks
    expect(result.selectedAttacks.length).toBeGreaterThan(0);
  });

  it("Beta fallback selects medium-priority attacks", () => {
    const config = makeConfig(betaTeam);
    const result = getDefaultSwarmAttacks(config);
    expect(result.strategy).toContain("beta");
    expect(result.selectedAttacks.length).toBeGreaterThan(0);
  });

  it("Gamma fallback selects high-priority/economic attacks", () => {
    const config = makeConfig(gammaTeam);
    const result = getDefaultSwarmAttacks(config);
    expect(result.strategy).toContain("gamma");
    expect(result.selectedAttacks.length).toBeGreaterThan(0);
  });

  it("fallback distributes attacks across agents round-robin", () => {
    const config = makeConfig(gammaTeam);
    const result = getDefaultSwarmAttacks(config);
    const agentIds = result.selectedAttacks.map((a) => a.agentId);
    // Should use multiple agents if enough attacks
    if (result.selectedAttacks.length >= 3) {
      expect(agentIds).toContain("gamma-1");
      expect(agentIds).toContain("gamma-2");
      expect(agentIds).toContain("gamma-3");
    }
  });

  it("pickSwarmAttacks returns fallback when ANTHROPIC_API_KEY is not set", async () => {
    const savedKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    const config = makeConfig(alphaTeam);
    const result = await pickSwarmAttacks(config);
    expect(result.usedFallback).toBe(true);
    expect(result.teamName).toBe("alpha");

    if (savedKey) process.env.ANTHROPIC_API_KEY = savedKey;
  });
});

// ---------------------------------------------------------------------------
// submitTeamQuestions
// ---------------------------------------------------------------------------

describe("swarm-strategist — submitTeamQuestions", () => {
  it("writes questions to intel log with correct team and type", () => {
    const log = new IntelLog();
    const response: SwarmStrategyResponse = {
      teamName: "alpha",
      round: 2,
      strategy: "Recon sweep",
      selectedAttacks: [],
      questionsForIntelLog: [
        { subject: "rate-limit", content: "Is it per-IP or per-identity?", targetHint: "/v1/actions/execute" },
        { subject: "bond-timing", content: "How fast do refunds arrive?", targetHint: null },
      ],
    };

    submitTeamQuestions(response, log, 2);

    const entries = log.getAllEntries();
    expect(entries).toHaveLength(2);
    for (const entry of entries) {
      expect(entry.team).toBe("alpha");
      expect(entry.type).toBe("question");
      expect(entry.round).toBe(2);
    }
    expect(entries[0].subject).toBe("rate-limit");
    expect(entries[0].targetHint).toBe("/v1/actions/execute");
    expect(entries[1].subject).toBe("bond-timing");
    expect(entries[1].targetHint).toBeNull();
  });

  it("handles empty questions array", () => {
    const log = new IntelLog();
    const response: SwarmStrategyResponse = {
      teamName: "beta",
      round: 1,
      strategy: "Trust building",
      selectedAttacks: [],
      questionsForIntelLog: [],
    };

    submitTeamQuestions(response, log, 1);
    expect(log.getAllEntries()).toHaveLength(0);
  });

  it("uses the response teamName, not a hardcoded value", () => {
    const log = new IntelLog();
    const response: SwarmStrategyResponse = {
      teamName: "gamma",
      round: 3,
      strategy: "Economic flood",
      selectedAttacks: [],
      questionsForIntelLog: [
        { subject: "capacity", content: "What's the bond cap?", targetHint: null },
      ],
    };

    submitTeamQuestions(response, log, 3);
    expect(log.getAllEntries()[0].team).toBe("gamma");
  });
});

// ---------------------------------------------------------------------------
// Live integration test (skippable)
// ---------------------------------------------------------------------------

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("test-"))("swarm-strategist — live Claude API", () => {
  it("picks attacks for Alpha team via live API", { timeout: 30000 }, async () => {
    const config = makeConfig(alphaTeam, {
      sharedIntel: "No prior intelligence available.",
      currentRound: 1,
      totalRounds: 5,
    });

    const result = await pickSwarmAttacks(config);
    expect(result.teamName).toBe("alpha");
    expect(result.round).toBe(1);
    expect(result.selectedAttacks.length).toBeGreaterThan(0);
    expect(result.strategy.length).toBeGreaterThan(0);

    for (const attack of result.selectedAttacks) {
      expect(attack.id).toBeTruthy();
      expect(attack.agentId).toBeTruthy();
      expect(attack.reasoning).toBeTruthy();
    }
  });
});
