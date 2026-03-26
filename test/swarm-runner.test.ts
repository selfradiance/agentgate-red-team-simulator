// Tests for Interleaved Swarm Runner (Stage 5)

import { describe, it, expect } from "vitest";
import { getSwarmConfig, type SwarmAgentIdentity, type SwarmConfig } from "../src/swarm";
import type { QueuedAttack, SwarmAttackResult, SwarmCampaignConfig, SwarmRoundResult } from "../src/swarm-runner";
import {
  interleaveAttacks,
  sequentialAttacks,
  validateCampaignConfig,
  aggregateCampaignResults,
  printSwarmRoundSummary,
  printCampaignBanner,
} from "../src/swarm-runner";
import { IntelLog } from "../src/intel-log";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const swarmConfig = getSwarmConfig();

function makeQueued(teamName: string, id: string, agentId?: string): QueuedAttack {
  return {
    pick: { id, agentId: agentId ?? `${teamName}-1`, reasoning: "test" },
    teamName: teamName as "alpha" | "beta" | "gamma",
    agentId: agentId ?? `${teamName}-1`,
  };
}

function makeSwarmResult(overrides: Partial<SwarmAttackResult> = {}): SwarmAttackResult {
  return {
    scenarioId: "1.1",
    scenarioName: "Test",
    category: "recon",
    expectedOutcome: "caught",
    actualOutcome: "403 Forbidden",
    caught: true,
    details: "Blocked",
    teamName: "alpha",
    agentId: "alpha-1",
    roundNumber: 1,
    executionPosition: 0,
    ...overrides,
  };
}

function makeMockIdentities(): Map<string, SwarmAgentIdentity> {
  const identities = new Map<string, SwarmAgentIdentity>();
  for (const team of swarmConfig.teams) {
    for (const agent of team.agents) {
      identities.set(agent.agentId, {
        config: agent,
        keys: { publicKey: "test-pub", privateKey: "test-priv" },
        identityId: `id-${agent.agentId}`,
      });
    }
  }
  return identities;
}

// ---------------------------------------------------------------------------
// interleaveAttacks
// ---------------------------------------------------------------------------

describe("swarm-runner — interleaveAttacks", () => {
  it("round-robins across 3 teams with equal sizes", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", [makeQueued("alpha", "1.1"), makeQueued("alpha", "1.2")]);
    teamAttacks.set("beta", [makeQueued("beta", "2.1"), makeQueued("beta", "2.2")]);
    teamAttacks.set("gamma", [makeQueued("gamma", "3.1"), makeQueued("gamma", "3.2")]);

    const result = interleaveAttacks(teamAttacks);

    expect(result).toHaveLength(6);
    // Round 1: alpha, beta, gamma
    expect(result[0].teamName).toBe("alpha");
    expect(result[1].teamName).toBe("beta");
    expect(result[2].teamName).toBe("gamma");
    // Round 2: alpha, beta, gamma
    expect(result[3].teamName).toBe("alpha");
    expect(result[4].teamName).toBe("beta");
    expect(result[5].teamName).toBe("gamma");
  });

  it("handles unequal team sizes — remaining attacks at end", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", [makeQueued("alpha", "1.1")]);
    teamAttacks.set("beta", [makeQueued("beta", "2.1"), makeQueued("beta", "2.2"), makeQueued("beta", "2.3")]);
    teamAttacks.set("gamma", [makeQueued("gamma", "3.1"), makeQueued("gamma", "3.2")]);

    const result = interleaveAttacks(teamAttacks);

    expect(result).toHaveLength(6);
    // Round 1: all three
    expect(result[0].teamName).toBe("alpha");
    expect(result[1].teamName).toBe("beta");
    expect(result[2].teamName).toBe("gamma");
    // Round 2: beta and gamma (alpha exhausted)
    expect(result[3].teamName).toBe("beta");
    expect(result[4].teamName).toBe("gamma");
    // Round 3: only beta
    expect(result[5].teamName).toBe("beta");
  });

  it("preserves attack IDs through interleaving", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", [makeQueued("alpha", "A1"), makeQueued("alpha", "A2")]);
    teamAttacks.set("beta", [makeQueued("beta", "B1"), makeQueued("beta", "B2")]);

    const result = interleaveAttacks(teamAttacks);

    expect(result[0].pick.id).toBe("A1");
    expect(result[1].pick.id).toBe("B1");
    expect(result[2].pick.id).toBe("A2");
    expect(result[3].pick.id).toBe("B2");
  });

  it("handles empty team list", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    const result = interleaveAttacks(teamAttacks);
    expect(result).toHaveLength(0);
  });

  it("handles one team with attacks, others empty", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", []);
    teamAttacks.set("beta", [makeQueued("beta", "2.1"), makeQueued("beta", "2.2")]);
    teamAttacks.set("gamma", []);

    const result = interleaveAttacks(teamAttacks);

    expect(result).toHaveLength(2);
    expect(result[0].teamName).toBe("beta");
    expect(result[1].teamName).toBe("beta");
  });

  it("preserves agent attribution", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", [makeQueued("alpha", "1.1", "alpha-2")]);
    teamAttacks.set("beta", [makeQueued("beta", "2.1", "beta-3")]);

    const result = interleaveAttacks(teamAttacks);

    expect(result[0].agentId).toBe("alpha-2");
    expect(result[1].agentId).toBe("beta-3");
  });
});

// ---------------------------------------------------------------------------
// sequentialAttacks
// ---------------------------------------------------------------------------

describe("swarm-runner — sequentialAttacks", () => {
  it("preserves team ordering: alpha → beta → gamma", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("gamma", [makeQueued("gamma", "3.1"), makeQueued("gamma", "3.2")]);
    teamAttacks.set("alpha", [makeQueued("alpha", "1.1"), makeQueued("alpha", "1.2")]);
    teamAttacks.set("beta", [makeQueued("beta", "2.1")]);

    const result = sequentialAttacks(teamAttacks);

    expect(result).toHaveLength(5);
    // Alpha first (sorted alphabetically)
    expect(result[0].teamName).toBe("alpha");
    expect(result[1].teamName).toBe("alpha");
    // Then beta
    expect(result[2].teamName).toBe("beta");
    // Then gamma
    expect(result[3].teamName).toBe("gamma");
    expect(result[4].teamName).toBe("gamma");
  });

  it("preserves attack order within each team", () => {
    const teamAttacks = new Map<string, QueuedAttack[]>();
    teamAttacks.set("alpha", [makeQueued("alpha", "A1"), makeQueued("alpha", "A2"), makeQueued("alpha", "A3")]);

    const result = sequentialAttacks(teamAttacks);

    expect(result[0].pick.id).toBe("A1");
    expect(result[1].pick.id).toBe("A2");
    expect(result[2].pick.id).toBe("A3");
  });
});

// ---------------------------------------------------------------------------
// validateCampaignConfig
// ---------------------------------------------------------------------------

describe("swarm-runner — validateCampaignConfig", () => {
  it("returns no errors for valid config", () => {
    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: false,
    };

    const errors = validateCampaignConfig(config);
    expect(errors).toHaveLength(0);
  });

  it("catches missing targetUrl", () => {
    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "",
      totalRounds: 5,
      sequential: false,
    };

    const errors = validateCampaignConfig(config);
    expect(errors).toContain("targetUrl is required");
  });

  it("catches empty identities map", () => {
    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: new Map(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: false,
    };

    const errors = validateCampaignConfig(config);
    expect(errors.some((e) => e.includes("identities"))).toBe(true);
  });

  it("catches totalRounds less than 1", () => {
    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 0,
      sequential: false,
    };

    const errors = validateCampaignConfig(config);
    expect(errors).toContain("totalRounds must be at least 1");
  });

  it("catches missing agent identities", () => {
    const partial = new Map<string, SwarmAgentIdentity>();
    // Only add alpha-1, missing the rest
    const alphaAgent = swarmConfig.teams[0].agents[0];
    partial.set("alpha-1", {
      config: alphaAgent,
      keys: { publicKey: "test-pub", privateKey: "test-priv" },
      identityId: "id-alpha-1",
    });

    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: partial,
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: false,
    };

    const errors = validateCampaignConfig(config);
    // Should have errors for 8 missing agents
    expect(errors.filter((e) => e.includes("Missing identity"))).toHaveLength(8);
  });
});

// ---------------------------------------------------------------------------
// aggregateCampaignResults
// ---------------------------------------------------------------------------

describe("swarm-runner — aggregateCampaignResults", () => {
  it("correctly aggregates per-team results across rounds", () => {
    const intelLog = new IntelLog();
    const rounds: SwarmRoundResult[] = [
      {
        roundNumber: 1,
        teamResults: new Map([
          ["alpha" as const, [
            makeSwarmResult({ teamName: "alpha", caught: true }),
            makeSwarmResult({ teamName: "alpha", caught: false }),
          ]],
          ["beta" as const, [
            makeSwarmResult({ teamName: "beta", caught: true }),
          ]],
        ]),
        coordinatorSynthesis: false,
      },
      {
        roundNumber: 2,
        teamResults: new Map([
          ["alpha" as const, [
            makeSwarmResult({ teamName: "alpha", caught: true }),
          ]],
          ["gamma" as const, [
            makeSwarmResult({ teamName: "gamma", caught: false }),
            makeSwarmResult({ teamName: "gamma", caught: false }),
          ]],
        ]),
        coordinatorSynthesis: true,
      },
    ];

    const result = aggregateCampaignResults(rounds, intelLog);

    expect(result.totalAttacks).toBe(6);
    expect(result.totalCaught).toBe(3);
    expect(result.totalUncaught).toBe(3);

    const alpha = result.perTeamSummary.get("alpha")!;
    expect(alpha.attacks).toBe(3);
    expect(alpha.caught).toBe(2);
    expect(alpha.uncaught).toBe(1);

    const beta = result.perTeamSummary.get("beta")!;
    expect(beta.attacks).toBe(1);
    expect(beta.caught).toBe(1);
    expect(beta.uncaught).toBe(0);

    const gamma = result.perTeamSummary.get("gamma")!;
    expect(gamma.attacks).toBe(2);
    expect(gamma.caught).toBe(0);
    expect(gamma.uncaught).toBe(2);
  });

  it("handles empty rounds", () => {
    const intelLog = new IntelLog();
    const result = aggregateCampaignResults([], intelLog);

    expect(result.totalAttacks).toBe(0);
    expect(result.totalCaught).toBe(0);
    expect(result.totalUncaught).toBe(0);
    expect(result.perTeamSummary.size).toBe(0);
    expect(result.intelLog).toBe(intelLog);
  });

  it("preserves the intel log reference", () => {
    const intelLog = new IntelLog();
    intelLog.addEntry({ round: 1, team: "alpha", type: "observation", subject: "test", content: "data", targetHint: null });

    const result = aggregateCampaignResults([], intelLog);
    expect(result.intelLog.getAllEntries()).toHaveLength(1);
  });

  it("preserves round data", () => {
    const rounds: SwarmRoundResult[] = [
      { roundNumber: 1, teamResults: new Map(), coordinatorSynthesis: false },
      { roundNumber: 2, teamResults: new Map(), coordinatorSynthesis: true },
    ];

    const result = aggregateCampaignResults(rounds, new IntelLog());
    expect(result.rounds).toHaveLength(2);
    expect(result.rounds[0].coordinatorSynthesis).toBe(false);
    expect(result.rounds[1].coordinatorSynthesis).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Print helpers (smoke tests — just verify they don't throw)
// ---------------------------------------------------------------------------

describe("swarm-runner — print helpers", () => {
  it("printSwarmRoundSummary does not throw", () => {
    const results: SwarmAttackResult[] = [
      makeSwarmResult({ teamName: "alpha", caught: true }),
      makeSwarmResult({ teamName: "alpha", caught: false }),
      makeSwarmResult({ teamName: "beta", caught: true }),
      makeSwarmResult({ teamName: "gamma", caught: false }),
    ];

    expect(() => printSwarmRoundSummary(1, results)).not.toThrow();
  });

  it("printCampaignBanner does not throw", () => {
    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: false,
    };

    expect(() => printCampaignBanner(config)).not.toThrow();
  });

  it("printCampaignBanner shows interleaved mode", () => {
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(" "));

    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: false,
    };
    printCampaignBanner(config);

    console.log = origLog;
    expect(logs.some((l) => l.includes("interleaved"))).toBe(true);
  });

  it("printCampaignBanner shows sequential mode", () => {
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(" "));

    const config: SwarmCampaignConfig = {
      swarmConfig,
      identities: makeMockIdentities(),
      targetUrl: "http://127.0.0.1:3000",
      totalRounds: 5,
      sequential: true,
    };
    printCampaignBanner(config);

    console.log = origLog;
    expect(logs.some((l) => l.includes("sequential"))).toBe(true);
  });
});
