// Tests for the report generator — unit test + live Claude API integration

import "dotenv/config";
import { describe, it, expect } from "vitest";
import { generateReport, type RecursiveRoundData, type TeamRoundData } from "../src/reporter";
import type { AttackResult } from "../src/log";
import type { StrategyResponse } from "../src/strategist";

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

const fakeNovelResult: AttackResult = {
  scenarioId: "novel-1",
  scenarioName: "Test bond at exact TTL boundary of 1 second",
  category: "Novel Attack",
  expectedOutcome: "Probing: TTL enforcement",
  actualOutcome: "CAUGHT: TTL of 1s was rejected",
  caught: true,
  details: "Hypothesis: minimum TTL boundary might not be enforced. Result: TTL of 1s rejected.",
};

const fakeStrategies: StrategyResponse[] = [
  {
    round: 1,
    strategy: "Broad recon — testing replay and signature defenses",
    attacks: [
      { id: "1.1", reasoning: "Baseline replay test" },
      { id: "3.2", reasoning: "Probe signature validation" },
    ],
  },
];

const fakeRecursiveData: RecursiveRoundData[] = [
  {
    roundNumber: 1,
    hypotheses: [
      {
        id: "novel-1",
        description: "Test bond at exact TTL boundary of 1 second",
        targetDefense: "TTL enforcement",
        rationale: "Nobody tested the minimum TTL boundary",
        confidence: "medium",
      },
    ],
    generationOutcomes: [
      {
        success: true,
        attack: {
          hypothesis: {
            id: "novel-1",
            description: "Test bond at exact TTL boundary of 1 second",
            targetDefense: "TTL enforcement",
            rationale: "Nobody tested the minimum TTL boundary",
            confidence: "medium",
          },
          code: 'async function novelAttack(toolkit) { toolkit.log("testing"); return { caught: true, reason: "TTL rejected" }; }',
          validationResult: { valid: true },
        },
      },
    ],
    novelResults: [fakeNovelResult],
  },
];

const fakeTeamData: TeamRoundData[] = [
  {
    roundNumber: 1,
    perPersonaResults: new Map([
      ["shadow", [fakeResults[0]]],
      ["whale", [fakeResults[1]]],
      ["chaos", []],
    ]),
    coordinatedOpResults: [
      {
        op: {
          type: "handoff",
          personas: ["shadow", "whale"],
          attackRefs: ["1.1", "2.1"],
          targetDefense: "Per-identity rate limiting",
          expectedSignal: "Enforcement inconsistency under cross-identity load",
          whyMultiIdentity: "Rate limit is per-identity — need two identities",
        },
        results: [fakeResults[0], fakeResults[1]],
        intel: "Rate limit triggers at 10 per 60s",
      },
    ],
    hypotheses: [
      {
        id: "novel-t1",
        description: "Test cross-identity bond capacity aggregation",
        targetDefense: "Bond capacity isolation",
        rationale: "Per-identity capacity might leak across identities",
        confidence: "medium",
        targetPersona: "whale",
      },
    ],
    generationOutcomes: [
      {
        success: true,
        attack: {
          hypothesis: {
            id: "novel-t1",
            description: "Test cross-identity bond capacity aggregation",
            targetDefense: "Bond capacity isolation",
            rationale: "Per-identity capacity might leak",
            confidence: "medium",
            targetPersona: "whale",
          },
          code: 'async function novelAttack(toolkit) { return { caught: true, reason: "isolated" }; }',
          validationResult: { valid: true },
        },
      },
    ],
    novelResults: [fakeNovelResult],
  },
];

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

  it("throws if ANTHROPIC_API_KEY is missing with strategies", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      await expect(generateReport(fakeResults, fakeStrategies)).rejects.toThrow("ANTHROPIC_API_KEY not set");
    } finally {
      process.env.ANTHROPIC_API_KEY = saved;
    }
  });

  it("throws if ANTHROPIC_API_KEY is missing with recursive data", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      await expect(
        generateReport([...fakeResults, fakeNovelResult], undefined, fakeRecursiveData),
      ).rejects.toThrow("ANTHROPIC_API_KEY not set");
    } finally {
      process.env.ANTHROPIC_API_KEY = saved;
    }
  });

  it("throws if ANTHROPIC_API_KEY is missing with team data", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      await expect(
        generateReport([...fakeResults, fakeNovelResult], undefined, undefined, fakeTeamData),
      ).rejects.toThrow("ANTHROPIC_API_KEY not set");
    } finally {
      process.env.ANTHROPIC_API_KEY = saved;
    }
  });
});

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("your-"))(
  "reporter — live Claude API",
  () => {
    it("generates a report from static results", { timeout: 30000 }, async () => {
      const report = await generateReport(fakeResults);
      expect(report).toBeTruthy();
      expect(report.length).toBeGreaterThan(50);
      expect(report).toContain("AgentGate");
    });

    it("generates a report with strategy reasoning", { timeout: 30000 }, async () => {
      const report = await generateReport(fakeResults, fakeStrategies);
      expect(report).toBeTruthy();
      expect(report.length).toBeGreaterThan(50);
      expect(report).toContain("AgentGate");
    });

    it("generates a report with recursive data", { timeout: 30000 }, async () => {
      const report = await generateReport(
        [...fakeResults, fakeNovelResult],
        undefined,
        fakeRecursiveData,
      );
      expect(report).toBeTruthy();
      expect(report.length).toBeGreaterThan(50);
      expect(report).toContain("AgentGate");
    });

    it("generates a report with team data", { timeout: 30000 }, async () => {
      const report = await generateReport(
        [...fakeResults, fakeNovelResult],
        undefined,
        undefined,
        fakeTeamData,
      );
      expect(report).toBeTruthy();
      expect(report.length).toBeGreaterThan(100);
      expect(report).toContain("AgentGate");
    });
  },
);
