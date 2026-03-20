// Tests for persona definitions and identity management

import "dotenv/config";
import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  SHADOW, WHALE, CHAOS, ALL_PERSONAS,
  loadOrCreatePersonaIdentity,
  deleteAllPersonaIdentityFiles,
  initializeTeam,
  getPersona,
  type PersonaIdentity,
} from "../src/personas";

// Clean up any persona identity files after each test
afterEach(() => {
  for (const config of ALL_PERSONAS) {
    const filePath = path.resolve(config.identityFile);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
});

describe("personas — config definitions", () => {
  it("defines three personas with distinct names", () => {
    expect(ALL_PERSONAS).toHaveLength(3);
    const names = ALL_PERSONAS.map((p) => p.name);
    expect(new Set(names).size).toBe(3);
    expect(names).toContain("shadow");
    expect(names).toContain("whale");
    expect(names).toContain("chaos");
  });

  it("personas have distinct bond budgets", () => {
    expect(SHADOW.bondBudgetCents).toBe(50);
    expect(WHALE.bondBudgetCents).toBe(200);
    expect(CHAOS.bondBudgetCents).toBe(100);
  });

  it("personas have non-overlapping attack family priorities", () => {
    const allFamilies = ALL_PERSONAS.flatMap((p) => p.attackFamilies);
    expect(new Set(allFamilies).size).toBe(allFamilies.length);
  });

  it("each persona has a distinct identity file", () => {
    const files = ALL_PERSONAS.map((p) => p.identityFile);
    expect(new Set(files).size).toBe(3);
    for (const f of files) {
      expect(f).toMatch(/^agent-identity-.*\.json$/);
    }
  });
});

describe("personas — identity file management", () => {
  it("deleteAllPersonaIdentityFiles removes all persona files", () => {
    // Create dummy files
    for (const config of ALL_PERSONAS) {
      fs.writeFileSync(path.resolve(config.identityFile), JSON.stringify({ publicKey: "test", privateKey: "test" }));
    }

    deleteAllPersonaIdentityFiles();

    for (const config of ALL_PERSONAS) {
      expect(fs.existsSync(path.resolve(config.identityFile))).toBe(false);
    }
  });

  it("deleteAllPersonaIdentityFiles is safe when files don't exist", () => {
    // Should not throw
    deleteAllPersonaIdentityFiles();
  });
});

describe("personas — getPersona helper", () => {
  it("finds persona by name", () => {
    const mockTeam: PersonaIdentity[] = ALL_PERSONAS.map((config) => ({
      config,
      keys: { publicKey: "test-pub", privateKey: "test-priv" },
      identityId: `id-${config.name}`,
    }));

    expect(getPersona(mockTeam, "shadow")?.config.name).toBe("shadow");
    expect(getPersona(mockTeam, "whale")?.config.name).toBe("whale");
    expect(getPersona(mockTeam, "chaos")?.config.name).toBe("chaos");
    expect(getPersona(mockTeam, "nonexistent")).toBeUndefined();
  });
});

describe.skipIf(!process.env.AGENTGATE_REST_KEY || process.env.AGENTGATE_REST_KEY.includes("your-"))(
  "personas — live AgentGate identity creation",
  () => {
    it("creates a persona identity on AgentGate", { timeout: 15000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      const identity = await loadOrCreatePersonaIdentity(SHADOW, agentGateUrl, restKey);

      expect(identity.config.name).toBe("shadow");
      expect(identity.keys.publicKey).toBeTruthy();
      expect(identity.keys.privateKey).toBeTruthy();
      expect(identity.identityId).toMatch(/^id_/);

      // File should have been created
      expect(fs.existsSync(path.resolve(SHADOW.identityFile))).toBe(true);
    });

    it("reloads existing persona identity from file", { timeout: 15000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      // Create first
      const first = await loadOrCreatePersonaIdentity(SHADOW, agentGateUrl, restKey);

      // Load again — should reuse
      const second = await loadOrCreatePersonaIdentity(SHADOW, agentGateUrl, restKey);

      expect(second.identityId).toBe(first.identityId);
      expect(second.keys.publicKey).toBe(first.keys.publicKey);
    });

    it("initializeTeam creates all three identities", { timeout: 30000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      const team = await initializeTeam(agentGateUrl, restKey);

      expect(team).toHaveLength(3);
      expect(team[0].config.name).toBe("shadow");
      expect(team[1].config.name).toBe("whale");
      expect(team[2].config.name).toBe("chaos");

      // All should have distinct identity IDs
      const ids = team.map((p) => p.identityId);
      expect(new Set(ids).size).toBe(3);
    });

    it("initializeTeam with freshTeam creates new identities", { timeout: 30000 }, async () => {
      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const restKey = process.env.AGENTGATE_REST_KEY!;

      // Create first
      const first = await initializeTeam(agentGateUrl, restKey);
      const firstIds = first.map((p) => p.identityId);

      // Fresh team — should create entirely new identities
      const second = await initializeTeam(agentGateUrl, restKey, true);
      const secondIds = second.map((p) => p.identityId);

      // All IDs should be different
      for (let i = 0; i < 3; i++) {
        expect(secondIds[i]).not.toBe(firstIds[i]);
      }
    });
  },
);
