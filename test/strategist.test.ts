// Tests for the strategist module — fallback, library menu, and live API integration

import "dotenv/config";
import { describe, it, expect } from "vitest";
import { getDefaultAttacks, buildLibraryMenu, pickAttacks } from "../src/strategist";

describe("strategist — unit tests", () => {
  it("getDefaultAttacks returns correct fallback", () => {
    const mockLibrary = [
      { id: "1.1", name: "Test A", category: "Cat1", defenseTargeted: "D1", parameterizable: false, priority: "Baseline" },
      { id: "2.5", name: "Test B", category: "Cat2", defenseTargeted: "D2", parameterizable: true, priority: "High" },
      { id: "7.1", name: "Test C", category: "Cat3", defenseTargeted: "D3", parameterizable: true, priority: "High" },
      { id: "7.2", name: "Test D", category: "Cat3", defenseTargeted: "D4", parameterizable: true, priority: "High" },
      { id: "3.2", name: "Test E", category: "Cat4", defenseTargeted: "D5", parameterizable: true, priority: "Medium" },
      { id: "9.2", name: "Test F", category: "Cat5", defenseTargeted: "D6", parameterizable: true, priority: "High" },
    ];

    const result = getDefaultAttacks(mockLibrary, 1);

    expect(result.usedFallback).toBe(true);
    expect(result.round).toBe(1);
    expect(result.strategy).toContain("Fallback");
    // Should only include High-priority entries (4 of 6)
    expect(result.attacks).toHaveLength(4);
    expect(result.attacks.every((a) => a.reasoning.includes("Fallback"))).toBe(true);
    // Should not include Baseline or Medium entries
    const ids = result.attacks.map((a) => a.id);
    expect(ids).not.toContain("1.1");
    expect(ids).not.toContain("3.2");
    expect(ids).toContain("2.5");
    expect(ids).toContain("7.1");
  });

  it("buildLibraryMenu transforms registry metadata", () => {
    const menu = buildLibraryMenu();

    // Should have all registered scenarios (48)
    expect(menu.length).toBe(48);

    // Each entry should have required fields
    for (const entry of menu) {
      expect(typeof entry.id).toBe("string");
      expect(typeof entry.name).toBe("string");
      expect(typeof entry.category).toBe("string");
      expect(typeof entry.defenseTargeted).toBe("string");
      expect(typeof entry.parameterizable).toBe("boolean");
      expect(["Baseline", "Medium", "High"]).toContain(entry.priority);
    }

    // Spot check a known entry
    const replay11 = menu.find((e) => e.id === "1.1");
    expect(replay11).toBeDefined();
    expect(replay11!.name).toBe("Exact duplicate request");
    expect(replay11!.category).toBe("Replay Attacks");
    expect(replay11!.priority).toBe("Baseline");
  });
});

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("your-"))(
  "strategist — live Claude API",
  () => {
    it("pickAttacks returns valid strategy for round 1", { timeout: 30000 }, async () => {
      const library = buildLibraryMenu();
      const result = await pickAttacks(library, 1, 3, []);

      expect(result.round).toBe(1);
      expect(typeof result.strategy).toBe("string");
      expect(result.strategy.length).toBeGreaterThan(0);
      expect(result.attacks.length).toBeGreaterThanOrEqual(5);
      expect(result.attacks.length).toBeLessThanOrEqual(15);

      // Every pick should have id and reasoning
      for (const pick of result.attacks) {
        expect(typeof pick.id).toBe("string");
        expect(typeof pick.reasoning).toBe("string");
      }

      // Every returned attack ID should exist in the library
      const libraryIds = new Set(library.map((e) => e.id));
      for (const pick of result.attacks) {
        expect(libraryIds.has(pick.id)).toBe(true);
      }
    });
  },
);
