// Tests for the generator module — validation pipeline + live Claude API integration

import "dotenv/config";
import { describe, it, expect } from "vitest";
import { validateAndCheck, stripFences, generateAttack } from "../src/generator";
import type { AttackHypothesis } from "../src/reasoner";

const SAMPLE_HYPOTHESIS: AttackHypothesis = {
  id: "novel-test",
  description: "Test what happens when a bond is locked with TTL of exactly 1 second",
  targetDefense: "TTL and sweeper timing",
  rationale: "Nobody tested the minimum TTL boundary",
  confidence: "medium",
};

const VALID_CODE = `async function novelAttack(toolkit) {
  toolkit.log("Testing minimum TTL boundary");
  const result = await toolkit.signedPost("/v1/bonds/lock", {
    identityId: "test",
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 1,
    reason: "ttl-boundary-test"
  });
  const caught = result.status >= 400;
  return { caught, reason: caught ? "TTL of 1s rejected" : "TTL of 1s accepted" };
}`;

const INVALID_CODE_REQUIRE = `async function novelAttack(toolkit) {
  const fs = require('fs');
  return { caught: false, reason: "used require" };
}`;

const INVALID_CODE_FETCH = `async function novelAttack(toolkit) {
  await fetch("http://evil.com");
  return { caught: false, reason: "used fetch" };
}`;

describe("generator — unit tests", () => {
  it("validates valid attack code", () => {
    const result = validateAndCheck(VALID_CODE, SAMPLE_HYPOTHESIS, null);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.attack.code).toContain("async function novelAttack(toolkit)");
      expect(result.attack.validationResult.valid).toBe(true);
      expect(result.attack.hypothesis.id).toBe("novel-test");
    }
  });

  it("rejects code with blocked patterns", () => {
    const result = validateAndCheck(INVALID_CODE_REQUIRE, SAMPLE_HYPOTHESIS, null);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.failure.reason).toContain("require(");
    }
  });

  it("rejects code failing validation after both attempts", () => {
    const result = validateAndCheck(INVALID_CODE_FETCH, SAMPLE_HYPOTHESIS, null);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.failure.reason).toContain("fetch(");
    }
  });

  it("rejects near-duplicate via novelty check", () => {
    const registry = new Map([
      ["2.3", { name: "Act on expired bond", description: "Execute an action against a bond after its TTL has expired" }],
    ]);
    const duplicateHypothesis: AttackHypothesis = {
      ...SAMPLE_HYPOTHESIS,
      description: "Execute an action against a bond after its TTL has expired to test enforcement",
    };
    const result = validateAndCheck(VALID_CODE, duplicateHypothesis, registry);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.failure.reason).toContain("Too similar");
    }
  });

  it("strips markdown fences from code", () => {
    const wrapped = "```javascript\n" + VALID_CODE + "\n```";
    const stripped = stripFences(wrapped);
    expect(stripped).not.toContain("```");
    expect(stripped).toContain("async function novelAttack(toolkit)");
  });

  it("handles API error gracefully via generateAttack", async () => {
    // Temporarily unset the API key to trigger the error path
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      const result = await generateAttack(SAMPLE_HYPOTHESIS, null);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.failure.reason).toContain("API error");
      }
    } finally {
      process.env.ANTHROPIC_API_KEY = saved;
    }
  });
});

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("your-"))(
  "generator — live Claude API",
  () => {
    it("generates valid attack code from hypothesis", { timeout: 30000 }, async () => {
      const result = await generateAttack(SAMPLE_HYPOTHESIS, null);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.attack.code).toContain("async function novelAttack(toolkit)");
        expect(result.attack.validationResult.valid).toBe(true);
        expect(result.attack.hypothesis.id).toBe("novel-test");
      }
    });
  },
);
