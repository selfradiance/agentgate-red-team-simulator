import { describe, expect, it } from "vitest";
import { prepareStrikeAttack, buildStrikeCode, type StrikeExecutionContext, type PreparedStrikeAttack } from "../../src/sleeper/strike-executor.js";
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

const testCtx: StrikeExecutionContext = {
  targetUrl: "http://127.0.0.1:3000",
  apiKey: "test-key",
  strikeKeys: { publicKey: "strike-pub", privateKey: "strike-priv" },
  strikeIdentityId: "strike-id-123",
  resolverKeys: { publicKey: "resolver-pub", privateKey: "resolver-priv" },
  resolverIdentityId: "resolver-id-456",
};

// ===========================================================================
// prepareStrikeAttack — all 7 branches
// ===========================================================================

describe("prepareStrikeAttack", () => {
  // T1
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

  it("T1 rejects when budget below one action", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T1", { burst_count: 5, exposure_cents: 100 }),
      0,
    );
    expect(prepared.ready).toBe(false);
    if (!prepared.ready) {
      expect(prepared.reason).toMatch(/Budget remaining/);
    }
  });

  it("T1 clamps exposure_cents to [1, 100] and burst_count to [1, 20]", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T1", { burst_count: 999, exposure_cents: 999, delay_ms: 9999 }),
      10000,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.burst_count).toBeLessThanOrEqual(20);
      expect(prepared.attack.params.exposure_cents).toBeLessThanOrEqual(100);
      expect(prepared.attack.params.delay_ms).toBeLessThanOrEqual(500);
    }
  });

  // T2
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

  it("T2 accepts attack within budget", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T2", { bond_cents: 100, exposure_cents: 85 }),
      500,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.exposure_cents).toBe(85);
      expect(prepared.attack.estimatedExposure).toBe(85);
    }
  });

  // T3
  it("T3 clamps bond_cents to [1, 2000] with zero exposure", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T3", { bond_cents: 5000 }),
      1000,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.bond_cents).toBe(2000);
      expect(prepared.attack.estimatedExposure).toBe(0);
    }
  });

  it("T3 defaults bond_cents to 500 when missing", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T3", {}),
      1000,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.bond_cents).toBe(500);
    }
  });

  // T4
  it("T4 clamps wait_seconds to [0, 420] and calculates timeout", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T4", { wait_seconds: 999 }),
      1000,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.wait_seconds).toBe(420);
      expect(prepared.attack.timeoutMs).toBeGreaterThanOrEqual(420 * 1000 + 15_000);
      expect(prepared.attack.estimatedExposure).toBe(0);
    }
  });

  it("T4 defaults wait_seconds to 0", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T4", {}),
      1000,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.wait_seconds).toBe(0);
    }
  });

  // T5
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

  it("T5 rejects path traversal in endpoint", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T5", { endpoint: "/v1/../../admin" }),
      500,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      // Should fall back to default
      expect(prepared.attack.params.endpoint).toBe("/v1/bonds/lock");
    }
  });

  it("T5 rejects when exposure exceeds budget", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T5", {
        endpoint: "/v1/bonds/lock",
        payload: { exposure_cents: 9999 },
      }),
      100,
    );
    expect(prepared.ready).toBe(false);
  });

  // T6
  it("T6 filters non-string endpoints and normalizes paths", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T6", {
        endpoints: ["/health", 42, null, "//evil", "/v1/../admin", "/v1/stats"],
      }),
      500,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      const eps = prepared.attack.params.endpoints as string[];
      expect(eps).toContain("/health");
      expect(eps).toContain("/v1/stats");
      // Should exclude non-strings, //, and ..
      expect(eps).not.toContain("//evil");
      expect(eps).not.toContain("/v1/../admin");
      expect(eps.length).toBe(2);
      expect(prepared.attack.estimatedExposure).toBe(0);
    }
  });

  it("T6 falls back to defaults when no valid endpoints", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T6", { endpoints: [42, null] }),
      500,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      expect(prepared.attack.params.endpoints).toEqual(["/health", "/v1/stats"]);
    }
  });

  it("T6 caps endpoints to MAX_PUBLIC_ENDPOINTS", () => {
    const manyEndpoints = Array.from({ length: 20 }, (_, i) => `/ep/${i}`);
    const prepared = prepareStrikeAttack(
      makeAttack("T6", { endpoints: manyEndpoints }),
      500,
    );
    expect(prepared.ready).toBe(true);
    if (prepared.ready) {
      const eps = prepared.attack.params.endpoints as string[];
      expect(eps.length).toBeLessThanOrEqual(10);
    }
  });

  // Unknown objective
  it("rejects unknown objective_id", () => {
    const prepared = prepareStrikeAttack(
      makeAttack("T99", {}),
      500,
    );
    expect(prepared.ready).toBe(false);
    if (!prepared.ready) {
      expect(prepared.reason).toMatch(/Unknown objective/);
    }
  });
});

// ===========================================================================
// buildStrikeCode — all 7 branches + security properties
// ===========================================================================

describe("buildStrikeCode", () => {
  function makePrepared(objectiveId: string, params: Record<string, unknown>): PreparedStrikeAttack {
    return {
      objective_id: objectiveId,
      params,
      reasoning: "test",
      recon_dependency: false,
      estimatedExposure: 0,
      timeoutMs: 15000,
    };
  }

  it("T1 generates valid JS with no resolver private key", () => {
    const code = buildStrikeCode(
      makePrepared("T1", { bond_cents: 100, burst_count: 5, delay_ms: 0, exposure_cents: 10 }),
      testCtx,
    );
    expect(code).toContain("async function novelAttack");
    expect(code).toContain("signedPostAsResolver");
    expect(code).not.toContain("signedPostAs(");
    // Must NOT contain resolver private key
    expect(code).not.toContain("resolver-priv");
    expect(code).not.toContain(testCtx.resolverKeys.privateKey);
    // Should contain resolver identity ID
    expect(code).toContain("resolver-id-456");
  });

  it("T2 generates valid JS with no resolver private key", () => {
    const code = buildStrikeCode(
      makePrepared("T2", { bond_cents: 100, exposure_cents: 85 }),
      testCtx,
    );
    expect(code).toContain("signedPostAsResolver");
    expect(code).not.toContain("resolver-priv");
    expect(code).toContain("resolver-id-456");
  });

  it("T3 generates bond lock only — no resolver needed", () => {
    const code = buildStrikeCode(
      makePrepared("T3", { bond_cents: 500 }),
      testCtx,
    );
    expect(code).toContain("strike-tier-cap");
    expect(code).not.toContain("resolver-priv");
    expect(code).not.toContain("signedPostAs");
  });

  it("T4 generates nonce replay with wait", () => {
    const code = buildStrikeCode(
      makePrepared("T4", { wait_seconds: 60 }),
      testCtx,
    );
    expect(code).toContain("signedPostWithControl");
    expect(code).toContain("strike-replay");
    expect(code).not.toContain("resolver-priv");
  });

  it("T5 signed generates signedPost call", () => {
    const code = buildStrikeCode(
      makePrepared("T5", {
        endpoint: "/v1/bonds/lock",
        payload: { identityId: "x", amountCents: 100 },
        headers: {},
        signed: true,
      }),
      testCtx,
    );
    expect(code).toContain("signedPost");
    expect(code).not.toContain("resolver-priv");
  });

  it("T5 unsigned generates rawPost call", () => {
    const code = buildStrikeCode(
      makePrepared("T5", {
        endpoint: "/v1/test",
        payload: { test: true },
        headers: { "x-custom": "value" },
        signed: false,
      }),
      testCtx,
    );
    expect(code).toContain("rawPost");
    expect(code).not.toContain("resolver-priv");
  });

  it("T6 generates rawGet loop over endpoints", () => {
    const code = buildStrikeCode(
      makePrepared("T6", { endpoints: ["/health", "/v1/stats"] }),
      testCtx,
    );
    expect(code).toContain("rawGet");
    expect(code).toContain("/health");
    expect(code).toContain("/v1/stats");
    expect(code).not.toContain("resolver-priv");
  });

  it("throws on unknown objective", () => {
    expect(() =>
      buildStrikeCode(makePrepared("T99", {}), testCtx),
    ).toThrow(/Unknown objective/);
  });

  it("never embeds any private key in generated code", () => {
    const objectives = ["T1", "T2", "T3", "T4", "T5", "T6"];
    const paramsByObjective: Record<string, Record<string, unknown>> = {
      T1: { bond_cents: 100, burst_count: 5, delay_ms: 0, exposure_cents: 10 },
      T2: { bond_cents: 100, exposure_cents: 85 },
      T3: { bond_cents: 500 },
      T4: { wait_seconds: 0 },
      T5: { endpoint: "/v1/bonds/lock", payload: {}, headers: {}, signed: true },
      T6: { endpoints: ["/health"] },
    };

    for (const id of objectives) {
      const code = buildStrikeCode(makePrepared(id, paramsByObjective[id]), testCtx);
      expect(code).not.toContain("strike-priv");
      expect(code).not.toContain("resolver-priv");
    }
  });
});
