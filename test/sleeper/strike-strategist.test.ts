// Unit tests for strike strategist — tests with mocked/default responses.

import { describe, it, expect } from "vitest";
import { getDefaultStrategy } from "../../src/sleeper/strike-strategist.js";

describe("Strike Strategist", () => {
  it("getDefaultStrategy returns valid structure for recon run", () => {
    const strategy = getDefaultStrategy(1, false);
    expect(strategy.round).toBe(1);
    expect(strategy.strategy).toBeTruthy();
    expect(strategy.attacks.length).toBeGreaterThanOrEqual(2);
    expect(strategy.attacks.length).toBeLessThanOrEqual(4);

    for (const attack of strategy.attacks) {
      expect(attack.objective_id).toMatch(/^T[1-6]$/);
      expect(typeof attack.params).toBe("object");
      expect(typeof attack.reasoning).toBe("string");
      expect(typeof attack.recon_dependency).toBe("boolean");
    }
  });

  it("getDefaultStrategy returns valid structure for blind run", () => {
    const strategy = getDefaultStrategy(1, true);
    expect(strategy.round).toBe(1);

    // All attacks in blind mode must have recon_dependency = false
    for (const attack of strategy.attacks) {
      expect(attack.recon_dependency).toBe(false);
    }
  });

  it("getDefaultStrategy sets recon_dependency = true for recon runs", () => {
    const strategy = getDefaultStrategy(1, false);
    const reconDependent = strategy.attacks.filter((a) => a.recon_dependency);
    expect(reconDependent.length).toBeGreaterThan(0);
  });

  it("default strategy targets multiple objectives", () => {
    const strategy = getDefaultStrategy(1, false);
    const objectives = new Set(strategy.attacks.map((a) => a.objective_id));
    expect(objectives.size).toBeGreaterThanOrEqual(2);
  });

  it("default strategy respects round number", () => {
    const s1 = getDefaultStrategy(1, false);
    const s2 = getDefaultStrategy(2, false);
    expect(s1.round).toBe(1);
    expect(s2.round).toBe(2);
  });
});
