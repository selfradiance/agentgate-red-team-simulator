// Tests for the reasoner module — response parsing + live Claude API integration

import "dotenv/config";
import { describe, it, expect } from "vitest";
import { parseReasonerResponse, analyzeResults } from "../src/reasoner";
import type { AttackResult } from "../src/log";

const SAMPLE_RESULTS: AttackResult[] = [
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
    scenarioId: "2.1",
    scenarioName: "Over-commit exposure",
    category: "Bond Capacity",
    expectedOutcome: "Rejected with INSUFFICIENT_BOND_CAPACITY",
    actualOutcome: "400 INSUFFICIENT_BOND_CAPACITY",
    caught: true,
    details: "AgentGate rejected the over-committed exposure.",
  },
  {
    scenarioId: "3.1",
    scenarioName: "Wrong private key",
    category: "Signature Tampering",
    expectedOutcome: "Rejected — signature mismatch",
    actualOutcome: "401 INVALID_SIGNATURE",
    caught: true,
    details: "AgentGate rejected the wrong-key signature.",
  },
];

describe("reasoner — unit tests", () => {
  it("parses valid reasoner response", () => {
    const json = JSON.stringify({
      analysis: "All three attacks were caught by their respective defenses.",
      hypotheses: [
        {
          id: "novel-1",
          description: "Send a bond lock with amount at the exact 1.2x boundary",
          targetDefense: "Bond capacity enforcement",
          rationale: "Prior test used 100 cents which clearly exceeds, but exact boundary might have off-by-one",
          confidence: "medium",
        },
        {
          id: "novel-2",
          description: "Send two concurrent identity registrations with the same public key",
          targetDefense: "Identity uniqueness constraint",
          rationale: "Race condition in identity creation might allow duplicate keys",
          confidence: "low",
        },
      ],
    });

    const result = parseReasonerResponse(json);
    expect(result.analysis).toContain("caught");
    expect(result.hypotheses).toHaveLength(2);
    expect(result.hypotheses[0].id).toBe("novel-1");
    expect(result.hypotheses[0].description).toContain("boundary");
    expect(result.hypotheses[0].targetDefense).toBe("Bond capacity enforcement");
    expect(result.hypotheses[0].rationale).toContain("off-by-one");
    expect(result.hypotheses[0].confidence).toBe("medium");
    expect(result.hypotheses[1].id).toBe("novel-2");
    expect(result.hypotheses[1].confidence).toBe("low");
  });

  it("handles malformed API response gracefully", () => {
    const result = parseReasonerResponse("This is not JSON at all. Just some random text.");
    expect(result.analysis).toContain("not JSON");
    expect(result.hypotheses).toHaveLength(0);
  });

  it("handles JSON with missing hypotheses array", () => {
    const result = parseReasonerResponse(JSON.stringify({ analysis: "Some analysis" }));
    expect(result.analysis).toBe("Some analysis");
    expect(result.hypotheses).toHaveLength(0);
  });

  it("strips markdown fences from response", () => {
    const json = JSON.stringify({
      analysis: "Analysis here",
      hypotheses: [{ id: "novel-1", description: "Test", targetDefense: "Test", rationale: "Test", confidence: "high" }],
    });
    const wrapped = "```json\n" + json + "\n```";
    const result = parseReasonerResponse(wrapped);
    expect(result.analysis).toBe("Analysis here");
    expect(result.hypotheses).toHaveLength(1);
  });

  it("handles invalid confidence values gracefully", () => {
    const json = JSON.stringify({
      analysis: "Test",
      hypotheses: [{ id: "novel-1", description: "Test", targetDefense: "Test", rationale: "Test", confidence: "very high" }],
    });
    const result = parseReasonerResponse(json);
    expect(result.hypotheses[0].confidence).toBe("low"); // defaults to "low" for invalid values
  });
});

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("your-"))(
  "reasoner — live Claude API",
  () => {
    it("produces hypotheses from real attack results", { timeout: 30000 }, async () => {
      const result = await analyzeResults(SAMPLE_RESULTS, 1);

      expect(result.analysis).toBeTruthy();
      expect(result.analysis.length).toBeGreaterThan(50);
      expect(result.hypotheses.length).toBeGreaterThanOrEqual(1);

      for (const h of result.hypotheses) {
        expect(typeof h.id).toBe("string");
        expect(typeof h.description).toBe("string");
        expect(typeof h.targetDefense).toBe("string");
        expect(typeof h.rationale).toBe("string");
        expect(["low", "medium", "high"]).toContain(h.confidence);
      }
    });
  },
);
