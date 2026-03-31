import { describe, expect, it } from "vitest";
import { prepareStrikeAttack } from "../../src/sleeper/strike-executor.js";
import type { StrikeAttack } from "../../src/sleeper/strike-strategist.js";

function makeAttack(
  objectiveId: StrikeAttack["objective_id"],
  params: Record<string, unknown>,
): StrikeAttack {
  return {
    objective_id: objectiveId,
    params,
    reasoning: "test",
    recon_dependency: false,
  };
}

describe("prepareStrikeAttack", () => {
  it("caps T1 burst count to remaining exposure budget", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T1", { burst_count: 20, exposure_cents: 25 }),
      60,
    );

    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.burst_count).toBe(2);
      expect(prepared.attack.estimatedExposure).toBe(50);
    }
  });

  it("rejects T2 attacks that exceed the remaining budget", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T2", { bond_cents: 100, exposure_cents: 300 }),
      200,
    );

    expect(prepared.ready).toBe(false);
    if (!prepared.ready) {
      expect(prepared.reason).toMatch(/only 200¢ remaining/);
    }
  });

  it("normalizes T5 endpoint and payload", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T5", { endpoint: "//evil.example", payload: "bad-payload" }),
      500,
    );

    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.endpoint).toBe("/v1/bonds/lock");
      expect(prepared.attack.params.payload).toEqual({
        identityId: "__STRIKE_IDENTITY__",
        amountCents: -100,
        currency: "USD",
        ttlSeconds: 300,
        reason: "strike-t5",
      });
    }
  });
});
