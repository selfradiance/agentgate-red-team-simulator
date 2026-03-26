// Tests for Swarm Reporter (Stage 5 — Step 9)

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SwarmCampaignResult, SwarmAttackResult, SwarmRoundResult, TeamSummary } from "../src/swarm-runner";
import type { SwarmTeamName } from "../src/swarm";
import { IntelLog } from "../src/intel-log";
import { buildSwarmUserMessage, buildFallbackReport } from "../src/swarm-reporter";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAttackResult(overrides: Partial<SwarmAttackResult> = {}): SwarmAttackResult {
  return {
    scenarioId: "test-1",
    scenarioName: "Test Attack",
    category: "Recon",
    expectedOutcome: "Expected outcome",
    actualOutcome: "Actual outcome",
    caught: true,
    details: "Test details for attack result",
    teamName: "alpha",
    agentId: "alpha-1",
    roundNumber: 1,
    executionPosition: 0,
    ...overrides,
  };
}

function makeCampaignResult(overrides: Partial<SwarmCampaignResult> = {}): SwarmCampaignResult {
  const intelLog = new IntelLog();
  intelLog.addEntry({ round: 1, team: "alpha", type: "observation", subject: "test-obs", content: "Alpha observed something", targetHint: null });
  intelLog.addEntry({ round: 1, team: "coordinator", type: "synthesis", subject: "round-1-synthesis", content: "Coordinator synthesized patterns", targetHint: null });

  const alphaResults: SwarmAttackResult[] = [
    makeAttackResult({ scenarioId: "1.1", scenarioName: "Replay Attack", caught: true, teamName: "alpha", agentId: "alpha-1" }),
    makeAttackResult({ scenarioId: "1.2", scenarioName: "Endpoint Probe", caught: false, teamName: "alpha", agentId: "alpha-2" }),
  ];
  const betaResults: SwarmAttackResult[] = [
    makeAttackResult({ scenarioId: "beta:cleanBondCycle", scenarioName: "cleanBondCycle", category: "Beta Trust", caught: false, teamName: "beta", agentId: "beta-1", sideEffects: { reputationBefore: 0, reputationAfter: 10 } }),
  ];
  const gammaResults: SwarmAttackResult[] = [
    makeAttackResult({ scenarioId: "3.1", scenarioName: "Bond Flood", caught: true, teamName: "gamma", agentId: "gamma-1" }),
  ];

  const teamResults = new Map<SwarmTeamName, SwarmAttackResult[]>();
  teamResults.set("alpha", alphaResults);
  teamResults.set("beta", betaResults);
  teamResults.set("gamma", gammaResults);

  const round: SwarmRoundResult = {
    roundNumber: 1,
    teamResults,
    coordinatorSynthesis: false,
  };

  const perTeamSummary = new Map<SwarmTeamName, TeamSummary>();
  perTeamSummary.set("alpha", { attacks: 2, caught: 1, uncaught: 1 });
  perTeamSummary.set("beta", { attacks: 1, caught: 0, uncaught: 1 });
  perTeamSummary.set("gamma", { attacks: 1, caught: 1, uncaught: 0 });

  return {
    rounds: [round],
    intelLog,
    totalAttacks: 4,
    totalCaught: 2,
    totalUncaught: 2,
    perTeamSummary,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// buildSwarmUserMessage
// ---------------------------------------------------------------------------

describe("swarm-reporter — buildSwarmUserMessage", () => {
  it("includes mode and campaign totals", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.mode).toBe("swarm");
    expect(parsed.totalAttacks).toBe(4);
    expect(parsed.totalCaught).toBe(2);
    expect(parsed.totalUncaught).toBe(2);
  });

  it("includes per-team summary", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.perTeamSummary.alpha).toEqual({ attacks: 2, caught: 1, uncaught: 1 });
    expect(parsed.perTeamSummary.beta).toEqual({ attacks: 1, caught: 0, uncaught: 1 });
    expect(parsed.perTeamSummary.gamma).toEqual({ attacks: 1, caught: 1, uncaught: 0 });
  });

  it("includes round details with team results", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.rounds).toHaveLength(1);
    expect(parsed.rounds[0].roundNumber).toBe(1);
    expect(parsed.rounds[0].teamResults.alpha).toHaveLength(2);
    expect(parsed.rounds[0].teamResults.beta).toHaveLength(1);
    expect(parsed.rounds[0].teamResults.gamma).toHaveLength(1);
  });

  it("includes intel log entries", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.intelLog.length).toBeGreaterThanOrEqual(2);
    const obs = parsed.intelLog.find((e: any) => e.type === "observation");
    expect(obs).toBeDefined();
    expect(obs.team).toBe("alpha");
  });

  it("includes coordinator syntheses", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.coordinatorSyntheses).toHaveLength(1);
    expect(parsed.coordinatorSyntheses[0].subject).toBe("round-1-synthesis");
  });

  it("includes budget info", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.budgetInfo.campaignCap).toBe(900);
    expect(parsed.budgetInfo.perAgent.alpha).toBe(50);
    expect(parsed.budgetInfo.perAgent.beta).toBe(100);
    expect(parsed.budgetInfo.perAgent.gamma).toBe(150);
  });

  it("includes counterfactual test definition", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    expect(parsed.counterfactualTest).toContain("isolation");
    expect(parsed.counterfactualTest).toContain("single-team");
    expect(parsed.counterfactualTest).toContain("cross-team");
    expect(parsed.counterfactualTest).toContain("swarm-emergent");
  });

  it("includes side effects for Beta results", () => {
    const msg = buildSwarmUserMessage(makeCampaignResult());
    const parsed = JSON.parse(msg);

    const betaResult = parsed.rounds[0].teamResults.beta[0];
    expect(betaResult.sideEffects).toBeDefined();
    expect(betaResult.sideEffects.reputationBefore).toBe(0);
    expect(betaResult.sideEffects.reputationAfter).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// buildFallbackReport
// ---------------------------------------------------------------------------

describe("swarm-reporter — buildFallbackReport", () => {
  it("includes fallback header", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("Fallback");
    expect(report).toContain("Claude API unavailable");
  });

  it("includes campaign overview numbers", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("Total attacks: 4");
    expect(report).toContain("Caught: 2");
    expect(report).toContain("Uncaught: 2");
  });

  it("includes per-team summary", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("alpha:");
    expect(report).toContain("beta:");
    expect(report).toContain("gamma:");
    expect(report).toContain("catch rate");
  });

  it("includes per-round breakdown", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("Round 1");
  });

  it("lists uncaught attacks", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("Uncaught Attacks");
    expect(report).toContain("Endpoint Probe");
    expect(report).toContain("cleanBondCycle");
  });

  it("includes intel log entry count", () => {
    const report = buildFallbackReport(makeCampaignResult());
    expect(report).toContain("Intel log entries:");
  });

  it("handles campaign with zero uncaught", () => {
    const result = makeCampaignResult({
      totalUncaught: 0,
      totalCaught: 4,
    });
    // Override round results to all caught
    const allCaught = new Map<SwarmTeamName, SwarmAttackResult[]>();
    allCaught.set("alpha", [
      makeAttackResult({ caught: true, teamName: "alpha" }),
    ]);
    result.rounds = [{ roundNumber: 1, teamResults: allCaught, coordinatorSynthesis: false }];

    const report = buildFallbackReport(result);
    expect(report).toContain("Uncaught: 0");
    expect(report).not.toContain("## Uncaught Attacks");
  });
});

// ---------------------------------------------------------------------------
// generateSwarmReport — API call structure
// ---------------------------------------------------------------------------

describe("swarm-reporter — generateSwarmReport API call", () => {
  const mockCreate = vi.fn();

  beforeEach(() => {
    mockCreate.mockReset();
    vi.resetModules();
  });

  it("uses correct model and max_tokens", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: "# Report\nTest report content" }],
    });

    vi.doMock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = { create: mockCreate };
      },
    }));

    // Temporarily set API key
    const originalKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "test-key";

    try {
      const { generateSwarmReport } = await import("../src/swarm-reporter");
      await generateSwarmReport(makeCampaignResult());

      expect(mockCreate).toHaveBeenCalledOnce();
      const callArgs = mockCreate.mock.calls[0][0];
      expect(callArgs.model).toBe("claude-sonnet-4-20250514");
      expect(callArgs.max_tokens).toBe(12000);
    } finally {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("system prompt includes all 6 report sections", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: "# Report" }],
    });

    vi.doMock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = { create: mockCreate };
      },
    }));

    const originalKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "test-key";

    try {
      const { generateSwarmReport } = await import("../src/swarm-reporter");
      await generateSwarmReport(makeCampaignResult());

      const systemPrompt = mockCreate.mock.calls[0][0].system;
      expect(systemPrompt).toContain("Executive Summary");
      expect(systemPrompt).toContain("Per-Team Breakdown");
      expect(systemPrompt).toContain("Shared Intelligence Analysis");
      expect(systemPrompt).toContain("Findings Classification");
      expect(systemPrompt).toContain("Coordinator Synthesis Review");
      expect(systemPrompt).toContain("Campaign Assessment");
    } finally {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("system prompt includes counterfactual test", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: "# Report" }],
    });

    vi.doMock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = { create: mockCreate };
      },
    }));

    const originalKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "test-key";

    try {
      const { generateSwarmReport } = await import("../src/swarm-reporter");
      await generateSwarmReport(makeCampaignResult());

      const systemPrompt = mockCreate.mock.calls[0][0].system;
      expect(systemPrompt).toContain("counterfactual");
      expect(systemPrompt).toContain("single-team");
      expect(systemPrompt).toContain("cross-team");
      expect(systemPrompt).toContain("swarm-emergent");
    } finally {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("falls back when API key is missing", async () => {
    vi.doMock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = { create: mockCreate };
      },
    }));

    const originalKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { generateSwarmReport } = await import("../src/swarm-reporter");
      const report = await generateSwarmReport(makeCampaignResult());

      expect(mockCreate).not.toHaveBeenCalled();
      expect(report).toContain("Fallback");
    } finally {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("falls back when API throws", async () => {
    mockCreate.mockRejectedValue(new Error("API error"));

    vi.doMock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = { create: mockCreate };
      },
    }));

    const originalKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "test-key";

    try {
      const { generateSwarmReport } = await import("../src/swarm-reporter");
      const report = await generateSwarmReport(makeCampaignResult());

      expect(report).toContain("Fallback");
    } finally {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });
});

// ---------------------------------------------------------------------------
// Integration test (requires ANTHROPIC_API_KEY)
// ---------------------------------------------------------------------------

describe.skipIf(!process.env.ANTHROPIC_API_KEY)("swarm-reporter — live API", () => {
  it("generates a report from campaign data", async () => {
    const { generateSwarmReport } = await import("../src/swarm-reporter");
    const report = await generateSwarmReport(makeCampaignResult());

    expect(report.length).toBeGreaterThan(100);
    expect(report).toContain("Summary");
  }, 30000);
});
