// Tests for Campaign Coordinator (Stage 5)

import { describe, it, expect, beforeEach, vi } from "vitest";
import { IntelLog } from "../src/intel-log";
import type { AttackResult } from "../src/log";
import type { RoundResultEntry, CoordinatorConfig } from "../src/coordinator";
import {
  synthesizeIntelligence,
  buildCoordinatorUserMessage,
  parseSynthesisResponse,
  COORDINATOR_SYSTEM_PROMPT,
} from "../src/coordinator";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(overrides: Partial<AttackResult> = {}): AttackResult {
  return {
    scenarioId: "1.1",
    scenarioName: "Test Scenario",
    category: "recon",
    expectedOutcome: "caught",
    actualOutcome: "403 Forbidden",
    caught: true,
    details: "Request blocked",
    ...overrides,
  };
}

function makeRoundResult(overrides: Partial<RoundResultEntry> = {}): RoundResultEntry {
  return {
    team: "alpha",
    agentId: "alpha-1",
    result: makeResult(),
    ...overrides,
  };
}

function makeConfig(overrides: Partial<CoordinatorConfig> = {}): CoordinatorConfig {
  return {
    intelLog: new IntelLog(),
    completedRound: 1,
    roundResults: [makeRoundResult()],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// System prompt structure
// ---------------------------------------------------------------------------

describe("coordinator — system prompt", () => {
  it("identifies role as neutral intelligence analyst", () => {
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("neutral intelligence analyst");
  });

  it("explicitly says coordinator does NOT assign attacks", () => {
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("do NOT");
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("Assign attacks");
  });

  it("explicitly says coordinator does NOT suggest priorities", () => {
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("Suggest priorities");
  });

  it("requests 3-6 observations", () => {
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("3-6");
  });

  it("describes coordinator as signal amplifier, not commander", () => {
    expect(COORDINATOR_SYSTEM_PROMPT).toContain("signal amplifier, not a commander");
  });
});

// ---------------------------------------------------------------------------
// User message construction
// ---------------------------------------------------------------------------

describe("coordinator — buildCoordinatorUserMessage", () => {
  it("includes the completed round number", () => {
    const config = makeConfig({ completedRound: 3 });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).toContain("Round 3");
  });

  it("includes round results with team/agent attribution", () => {
    const config = makeConfig({
      roundResults: [
        makeRoundResult({
          team: "beta",
          agentId: "beta-2",
          result: makeResult({ scenarioId: "3.1", scenarioName: "Bond Exploit", caught: false, details: "Slipped through" }),
        }),
      ],
    });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).toContain("[beta/beta-2]");
    expect(msg).toContain("[3.1]");
    expect(msg).toContain("Bond Exploit");
    expect(msg).toContain("UNCAUGHT");
  });

  it("includes prior intel from the log when available", () => {
    const log = new IntelLog();
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "recon", content: "Found open endpoint", targetHint: null });
    const config = makeConfig({ intelLog: log, completedRound: 2, roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).toContain("PRIOR INTELLIGENCE");
    expect(msg).toContain("Found open endpoint");
  });

  it("excludes prior intel section when none available", () => {
    const config = makeConfig({ completedRound: 1, roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).not.toContain("PRIOR INTELLIGENCE");
  });

  it("includes team intel entries from the completed round", () => {
    const log = new IntelLog();
    log.addEntry({ round: 2, team: "gamma", type: "question", subject: "rate-limit", content: "Does it reset per identity?", targetHint: "/v1/actions/execute" });
    const config = makeConfig({ intelLog: log, completedRound: 2, roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).toContain("TEAM INTEL FROM ROUND 2");
    expect(msg).toContain("[gamma]");
    expect(msg).toContain("Does it reset per identity?");
  });

  it("shows 'No results this round.' when roundResults is empty", () => {
    const config = makeConfig({ roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).toContain("No results this round.");
  });
});

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

describe("coordinator — parseSynthesisResponse", () => {
  it("parses valid JSON with observations", () => {
    const json = JSON.stringify({
      observations: [
        { subject: "rate-limit gap", content: "Alpha and Beta both hit 429 at different thresholds", targetHint: "/v1/actions/execute" },
        { subject: "bond refund timing", content: "Refunds arrive within 2s for small bonds", targetHint: null },
      ],
    });
    const result = parseSynthesisResponse(json);
    expect(result).toHaveLength(2);
    expect(result[0].subject).toBe("rate-limit gap");
    expect(result[0].targetHint).toBe("/v1/actions/execute");
    expect(result[1].targetHint).toBeNull();
  });

  it("handles JSON wrapped in markdown fences", () => {
    const json = "```json\n" + JSON.stringify({ observations: [{ subject: "test", content: "works", targetHint: null }] }) + "\n```";
    const result = parseSynthesisResponse(json);
    expect(result).toHaveLength(1);
    expect(result[0].subject).toBe("test");
  });

  it("throws on invalid JSON", () => {
    expect(() => parseSynthesisResponse("not json")).toThrow("invalid JSON");
  });

  it("throws on missing observations array", () => {
    expect(() => parseSynthesisResponse(JSON.stringify({ wrong: true }))).toThrow("missing 'observations' array");
  });

  it("skips malformed observation entries", () => {
    const json = JSON.stringify({
      observations: [
        { subject: "valid", content: "good one", targetHint: null },
        { subject: 123, content: "bad subject" },
        "not an object",
        { subject: "also valid", content: "another", targetHint: "/v1/bonds" },
      ],
    });
    const result = parseSynthesisResponse(json);
    expect(result).toHaveLength(2);
    expect(result[0].subject).toBe("valid");
    expect(result[1].subject).toBe("also valid");
  });

  it("treats missing targetHint as null", () => {
    const json = JSON.stringify({
      observations: [{ subject: "test", content: "no hint" }],
    });
    const result = parseSynthesisResponse(json);
    expect(result[0].targetHint).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// synthesizeIntelligence — fallback behavior
// ---------------------------------------------------------------------------

describe("coordinator — fallback behavior", () => {
  const originalEnv = process.env.ANTHROPIC_API_KEY;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("adds fallback synthesis when ANTHROPIC_API_KEY is not set", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const config = makeConfig();

    await synthesizeIntelligence(config);

    const entries = config.intelLog.getAllEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].team).toBe("coordinator");
    expect(entries[0].type).toBe("synthesis");
    expect(entries[0].subject).toBe("round-summary");
    expect(entries[0].content).toContain("synthesis unavailable");

    // Restore
    if (originalEnv) process.env.ANTHROPIC_API_KEY = originalEnv;
  });

  it("fallback entry uses the correct round number", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const config = makeConfig({ completedRound: 3 });

    await synthesizeIntelligence(config);

    const entries = config.intelLog.getAllEntries();
    expect(entries[0].round).toBe(3);
    expect(entries[0].content).toContain("Round 3");

    if (originalEnv) process.env.ANTHROPIC_API_KEY = originalEnv;
  });

  it("fallback entry includes result count", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const config = makeConfig({
      roundResults: [makeRoundResult(), makeRoundResult(), makeRoundResult()],
    });

    await synthesizeIntelligence(config);

    const entries = config.intelLog.getAllEntries();
    expect(entries[0].content).toContain("3 attack results");

    if (originalEnv) process.env.ANTHROPIC_API_KEY = originalEnv;
  });
});

// ---------------------------------------------------------------------------
// synthesizeIntelligence — synthesis entries have correct fields
// ---------------------------------------------------------------------------

describe("coordinator — synthesis entry fields", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("all synthesis entries have team='coordinator' and type='synthesis'", async () => {
    // Mock the Anthropic SDK
    const mockResponse = {
      observations: [
        { subject: "pattern-1", content: "Cross-team correlation found", targetHint: null },
        { subject: "pattern-2", content: "Timing anomaly detected", targetHint: "/v1/bonds/lock" },
      ],
    };

    vi.mock("@anthropic-ai/sdk", () => ({
      default: class MockAnthropic {
        messages = {
          create: vi.fn().mockResolvedValue({
            content: [{ type: "text", text: JSON.stringify(mockResponse) }],
          }),
        };
      },
    }));

    // Re-import to get mocked version
    const { synthesizeIntelligence: synthMocked } = await import("../src/coordinator");

    const savedKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "test-key-for-mock";

    const config = makeConfig();
    await synthMocked(config);

    const entries = config.intelLog.getAllEntries();
    expect(entries.length).toBeGreaterThanOrEqual(1);
    for (const entry of entries) {
      expect(entry.team).toBe("coordinator");
      expect(entry.type).toBe("synthesis");
    }

    if (savedKey) process.env.ANTHROPIC_API_KEY = savedKey;
    else delete process.env.ANTHROPIC_API_KEY;

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// synthesizeIntelligence — only reads completed/prior rounds
// ---------------------------------------------------------------------------

describe("coordinator — round boundaries", () => {
  it("buildCoordinatorUserMessage only includes prior intel from rounds before completedRound", () => {
    const log = new IntelLog();
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "round 1 intel", targetHint: null });
    log.addEntry({ round: 2, team: "beta", type: "observation", subject: "b", content: "round 2 intel", targetHint: null });
    log.addEntry({ round: 3, team: "gamma", type: "observation", subject: "c", content: "round 3 intel", targetHint: null });

    // Coordinator is synthesizing round 2 — should see round 1 as prior, not round 2 or 3
    const config = makeConfig({ intelLog: log, completedRound: 2, roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);

    expect(msg).toContain("round 1 intel"); // prior round
    // Round 2 entries appear in TEAM INTEL section, not PRIOR INTELLIGENCE
    expect(msg).toContain("round 2 intel");
    expect(msg).not.toContain("round 3 intel"); // future round
  });

  it("round 1 synthesis has no prior intelligence section", () => {
    const config = makeConfig({ completedRound: 1, roundResults: [] });
    const msg = buildCoordinatorUserMessage(config);
    expect(msg).not.toContain("PRIOR INTELLIGENCE");
  });
});

// ---------------------------------------------------------------------------
// Live integration test (skippable)
// ---------------------------------------------------------------------------

describe.skipIf(!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY.includes("test-"))("coordinator — live Claude API", () => {
  it("synthesizes intelligence from real API call", { timeout: 30000 }, async () => {
    const log = new IntelLog();
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "rate-limit", content: "429 after 10 requests in 60s", targetHint: "/v1/actions/execute" });
    log.addEntry({ round: 1, team: "beta", type: "observation", subject: "bond-refund", content: "Refund arrived in 1.8s", targetHint: "/v1/bonds/lock" });
    log.addEntry({ round: 1, team: "gamma", type: "question", subject: "identity-linking", content: "Can AgentGate detect shared IP across identities?", targetHint: null });

    const config: CoordinatorConfig = {
      intelLog: log,
      completedRound: 1,
      roundResults: [
        makeRoundResult({ team: "alpha", agentId: "alpha-1", result: makeResult({ scenarioId: "1.1", caught: true, details: "Rate limited at 10/60s" }) }),
        makeRoundResult({ team: "beta", agentId: "beta-1", result: makeResult({ scenarioId: "3.2", caught: false, details: "Bond posted successfully", actualOutcome: "200 OK" }) }),
        makeRoundResult({ team: "gamma", agentId: "gamma-2", result: makeResult({ scenarioId: "5.1", caught: true, details: "Nonce rejected" }) }),
      ],
    };

    await synthesizeIntelligence(config);

    const syntheses = log.getSyntheses();
    expect(syntheses.length).toBeGreaterThanOrEqual(1);
    for (const entry of syntheses) {
      expect(entry.team).toBe("coordinator");
      expect(entry.type).toBe("synthesis");
      expect(entry.round).toBe(1);
      expect(entry.subject.length).toBeGreaterThan(0);
      expect(entry.content.length).toBeGreaterThan(0);
    }
  });
});
