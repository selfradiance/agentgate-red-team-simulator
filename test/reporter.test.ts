// Tests for the report generator — unit test + live Claude API integration

import "dotenv/config";
import { describe, it, expect } from "vitest";
import { generateReport } from "../src/reporter";
import type { AttackResult } from "../src/log";

describe("reporter", () => {
  it("throws if ANTHROPIC_API_KEY is missing", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      await expect(generateReport([])).rejects.toThrow("ANTHROPIC_API_KEY not set");
    } finally {
      process.env.ANTHROPIC_API_KEY = saved;
    }
  });
});

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("your-"))(
  "reporter — live Claude API",
  () => {
    it("generates a report from attack results", { timeout: 30000 }, async () => {
      const fakeResults: AttackResult[] = [
        {
          scenarioId: "1.1",
          scenarioName: "Exact duplicate request",
          category: "Replay Attacks",
          expectedOutcome: "Duplicate rejected with 409",
          actualOutcome: "409 DUPLICATE_NONCE",
          caught: true,
          details: "AgentGate correctly rejected the duplicate nonce.",
        },
        {
          scenarioId: "3.2",
          scenarioName: "Malformed signature",
          category: "Signature Tampering",
          expectedOutcome: "Rejected — invalid signature",
          actualOutcome: "401 INVALID_SIGNATURE",
          caught: true,
          details: "AgentGate rejected the malformed signature.",
        },
      ];

      const report = await generateReport(fakeResults);
      expect(report).toBeTruthy();
      expect(report.length).toBeGreaterThan(50);
      expect(report).toContain("AgentGate");
    });
  },
);
