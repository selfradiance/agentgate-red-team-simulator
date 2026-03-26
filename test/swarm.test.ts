// Tests for swarm identity management (Stage 5)

import "dotenv/config";
import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  getSwarmConfig,
  getAllAgentConfigs,
  deleteSwarmIdentities,
  getSwarmAgent,
  getTeamIdentities,
  loadOrCreateSwarmAgentIdentity,
  createSwarmIdentities,
  type SwarmAgentIdentity,
  type SwarmTeamName,
} from "../src/swarm";

// Clean up any swarm identity files after each test
afterEach(() => {
  for (const config of getAllAgentConfigs()) {
    const filePath = path.resolve(config.identityFilePath);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
});

describe("swarm — config structure", () => {
  it("returns 3 teams with 3 agents each", () => {
    const config = getSwarmConfig();
    expect(config.teams).toHaveLength(3);
    for (const team of config.teams) {
      expect(team.agents).toHaveLength(3);
    }
  });

  it("teams have correct names", () => {
    const config = getSwarmConfig();
    const names = config.teams.map((t) => t.name);
    expect(names).toEqual(["alpha", "beta", "gamma"]);
  });

  it("each team has a non-empty objective", () => {
    const config = getSwarmConfig();
    for (const team of config.teams) {
      expect(team.objective.length).toBeGreaterThan(0);
    }
  });

  it("all 9 agents have unique agentIds", () => {
    const allConfigs = getAllAgentConfigs();
    expect(allConfigs).toHaveLength(9);
    const ids = allConfigs.map((a) => a.agentId);
    expect(new Set(ids).size).toBe(9);
  });

  it("agent IDs follow team-index pattern", () => {
    const allConfigs = getAllAgentConfigs();
    const expectedIds = [
      "alpha-1", "alpha-2", "alpha-3",
      "beta-1", "beta-2", "beta-3",
      "gamma-1", "gamma-2", "gamma-3",
    ];
    expect(allConfigs.map((a) => a.agentId)).toEqual(expectedIds);
  });
});

describe("swarm — budget math", () => {
  it("Alpha agents have 50¢ each, team cap 150¢", () => {
    const config = getSwarmConfig();
    const alpha = config.teams.find((t) => t.name === "alpha")!;
    for (const agent of alpha.agents) {
      expect(agent.bondBudgetCents).toBe(50);
    }
    expect(alpha.teamBudgetCents).toBe(150);
  });

  it("Beta agents have 100¢ each, team cap 300¢", () => {
    const config = getSwarmConfig();
    const beta = config.teams.find((t) => t.name === "beta")!;
    for (const agent of beta.agents) {
      expect(agent.bondBudgetCents).toBe(100);
    }
    expect(beta.teamBudgetCents).toBe(300);
  });

  it("Gamma agents have 150¢ each, team cap 450¢", () => {
    const config = getSwarmConfig();
    const gamma = config.teams.find((t) => t.name === "gamma")!;
    for (const agent of gamma.agents) {
      expect(agent.bondBudgetCents).toBe(150);
    }
    expect(gamma.teamBudgetCents).toBe(450);
  });

  it("campaign cap is 900¢ (sum of all team caps)", () => {
    const config = getSwarmConfig();
    const teamSum = config.teams.reduce((sum, t) => sum + t.teamBudgetCents, 0);
    expect(teamSum).toBe(config.campaignCapCents);
    expect(config.campaignCapCents).toBe(900);
  });
});

describe("swarm — identity file naming", () => {
  it("all 9 agents have unique identity file paths", () => {
    const allConfigs = getAllAgentConfigs();
    const files = allConfigs.map((a) => a.identityFilePath);
    expect(new Set(files).size).toBe(9);
  });

  it("identity files follow swarm-identity-{team}-{index}.json pattern", () => {
    const allConfigs = getAllAgentConfigs();
    for (const agent of allConfigs) {
      expect(agent.identityFilePath).toBe(`swarm-identity-${agent.agentId}.json`);
      expect(agent.identityFilePath).toMatch(/^swarm-identity-[a-z]+-\d\.json$/);
    }
  });
});

describe("swarm — identity file management", () => {
  it("deleteSwarmIdentities removes all swarm files", () => {
    // Create dummy files
    for (const config of getAllAgentConfigs()) {
      fs.writeFileSync(
        path.resolve(config.identityFilePath),
        JSON.stringify({ publicKey: "test", privateKey: "test" }),
      );
    }

    deleteSwarmIdentities();

    for (const config of getAllAgentConfigs()) {
      expect(fs.existsSync(path.resolve(config.identityFilePath))).toBe(false);
    }
  });

  it("deleteSwarmIdentities is safe when files don't exist", () => {
    // Should not throw
    deleteSwarmIdentities();
  });
});

describe("swarm — lookup helpers", () => {
  it("getSwarmAgent finds agent by agentId", () => {
    const mockIdentities: SwarmAgentIdentity[] = getAllAgentConfigs().map((config) => ({
      config,
      keys: { publicKey: "test-pub", privateKey: "test-priv" },
      identityId: `id-${config.agentId}`,
    }));

    expect(getSwarmAgent(mockIdentities, "alpha-1")?.config.agentId).toBe("alpha-1");
    expect(getSwarmAgent(mockIdentities, "gamma-3")?.config.agentId).toBe("gamma-3");
    expect(getSwarmAgent(mockIdentities, "nonexistent")).toBeUndefined();
  });

  it("getTeamIdentities returns only agents from the specified team", () => {
    const mockIdentities: SwarmAgentIdentity[] = getAllAgentConfigs().map((config) => ({
      config,
      keys: { publicKey: "test-pub", privateKey: "test-priv" },
      identityId: `id-${config.agentId}`,
    }));

    const alphaTeam = getTeamIdentities(mockIdentities, "alpha");
    expect(alphaTeam).toHaveLength(3);
    for (const agent of alphaTeam) {
      expect(agent.config.team).toBe("alpha");
    }

    const betaTeam = getTeamIdentities(mockIdentities, "beta");
    expect(betaTeam).toHaveLength(3);
    for (const agent of betaTeam) {
      expect(agent.config.team).toBe("beta");
    }
  });
});

describe.skipIf(!process.env.AGENTGATE_REST_KEY || process.env.AGENTGATE_REST_KEY.includes("your-"))(
  "swarm — live AgentGate identity creation",
  () => {
    it("creates a single swarm agent identity on AgentGate", { timeout: 15000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;
      const config = getAllAgentConfigs()[0]; // alpha-1

      const identity = await loadOrCreateSwarmAgentIdentity(config, agentGateUrl, restKey);

      expect(identity.config.agentId).toBe("alpha-1");
      expect(identity.keys.publicKey).toBeTruthy();
      expect(identity.keys.privateKey).toBeTruthy();
      expect(identity.identityId).toMatch(/^id_/);
      expect(fs.existsSync(path.resolve(config.identityFilePath))).toBe(true);
    });

    it("reloads existing swarm agent identity from file", { timeout: 15000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;
      const config = getAllAgentConfigs()[0]; // alpha-1

      const first = await loadOrCreateSwarmAgentIdentity(config, agentGateUrl, restKey);
      const second = await loadOrCreateSwarmAgentIdentity(config, agentGateUrl, restKey);

      expect(second.identityId).toBe(first.identityId);
      expect(second.keys.publicKey).toBe(first.keys.publicKey);
    });

    it("createSwarmIdentities creates all 9 identities", { timeout: 90000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      const identities = await createSwarmIdentities(agentGateUrl, restKey);

      expect(identities).toHaveLength(9);
      const ids = identities.map((i) => i.identityId);
      expect(new Set(ids).size).toBe(9);

      // Verify team distribution
      const alphas = identities.filter((i) => i.config.team === "alpha");
      const betas = identities.filter((i) => i.config.team === "beta");
      const gammas = identities.filter((i) => i.config.team === "gamma");
      expect(alphas).toHaveLength(3);
      expect(betas).toHaveLength(3);
      expect(gammas).toHaveLength(3);
    });

    it("createSwarmIdentities with freshSwarm creates new identities", { timeout: 90000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      const first = await createSwarmIdentities(agentGateUrl, restKey);
      const firstIds = first.map((i) => i.identityId);

      const second = await createSwarmIdentities(agentGateUrl, restKey, true);
      const secondIds = second.map((i) => i.identityId);

      for (let i = 0; i < 9; i++) {
        expect(secondIds[i]).not.toBe(firstIds[i]);
      }
    });
  },
);
