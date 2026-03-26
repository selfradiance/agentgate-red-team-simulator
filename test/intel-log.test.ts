// Tests for shared intelligence log (Stage 5)

import { describe, it, expect, beforeEach } from "vitest";
import { IntelLog, type IntelEntry } from "../src/intel-log";

let log: IntelLog;

beforeEach(() => {
  log = new IntelLog();
});

describe("intel-log — add and retrieve entries", () => {
  it("addEntry returns a full entry with auto-generated id", () => {
    const entry = log.addEntry({
      round: 1,
      team: "alpha",
      type: "observation",
      subject: "/v1/identities",
      content: "Endpoint accepts unauthenticated GET requests",
      targetHint: null,
    });

    expect(entry.id).toBeTruthy();
    expect(entry.id.length).toBeGreaterThan(0);
    expect(entry.round).toBe(1);
    expect(entry.team).toBe("alpha");
    expect(entry.type).toBe("observation");
    expect(entry.subject).toBe("/v1/identities");
    expect(entry.content).toBe("Endpoint accepts unauthenticated GET requests");
    expect(entry.targetHint).toBeNull();
  });

  it("each entry gets a unique id", () => {
    const e1 = log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "test", content: "a", targetHint: null });
    const e2 = log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "test", content: "b", targetHint: null });
    expect(e1.id).not.toBe(e2.id);
  });

  it("getAllEntries returns all entries in chronological order", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "first", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "question", subject: "b", content: "second", targetHint: null });
    log.addEntry({ round: 2, team: "gamma", type: "observation", subject: "c", content: "third", targetHint: null });

    const all = log.getAllEntries();
    expect(all).toHaveLength(3);
    expect(all[0].content).toBe("first");
    expect(all[1].content).toBe("second");
    expect(all[2].content).toBe("third");
  });

  it("getAllEntries returns a copy (not the internal array)", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "x", targetHint: null });
    const all = log.getAllEntries();
    all.push({ id: "fake", round: 99, team: "alpha", type: "observation", subject: "fake", content: "injected", targetHint: null });
    expect(log.getAllEntries()).toHaveLength(1);
  });
});

describe("intel-log — filter by round", () => {
  it("getEntriesByRound returns only entries from that round", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "r1", targetHint: null });
    log.addEntry({ round: 2, team: "alpha", type: "observation", subject: "b", content: "r2", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "question", subject: "c", content: "r1-beta", targetHint: null });

    const round1 = log.getEntriesByRound(1);
    expect(round1).toHaveLength(2);
    expect(round1.every((e) => e.round === 1)).toBe(true);

    const round2 = log.getEntriesByRound(2);
    expect(round2).toHaveLength(1);
    expect(round2[0].content).toBe("r2");
  });

  it("getEntriesByRound returns empty array for nonexistent round", () => {
    expect(log.getEntriesByRound(99)).toHaveLength(0);
  });
});

describe("intel-log — filter by team", () => {
  it("getEntriesByTeam returns only entries from that team", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "alpha-1", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "observation", subject: "b", content: "beta-1", targetHint: null });
    log.addEntry({ round: 2, team: "alpha", type: "question", subject: "c", content: "alpha-2", targetHint: null });

    const alpha = log.getEntriesByTeam("alpha");
    expect(alpha).toHaveLength(2);
    expect(alpha.every((e) => e.team === "alpha")).toBe(true);
  });

  it("getEntriesByTeam includes coordinator entries", () => {
    log.addEntry({ round: 1, team: "coordinator", type: "synthesis", subject: "overview", content: "synth", targetHint: null });
    const coord = log.getEntriesByTeam("coordinator");
    expect(coord).toHaveLength(1);
    expect(coord[0].type).toBe("synthesis");
  });
});

describe("intel-log — filter by type", () => {
  it("getEntriesByType returns only entries of that type", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "obs", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "question", subject: "b", content: "q", targetHint: null });
    log.addEntry({ round: 1, team: "coordinator", type: "synthesis", subject: "c", content: "synth", targetHint: null });

    expect(log.getEntriesByType("observation")).toHaveLength(1);
    expect(log.getEntriesByType("question")).toHaveLength(1);
    expect(log.getEntriesByType("synthesis")).toHaveLength(1);
  });

  it("getSyntheses returns only coordinator synthesis entries", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "obs", targetHint: null });
    log.addEntry({ round: 1, team: "coordinator", type: "synthesis", subject: "b", content: "synth-1", targetHint: null });
    log.addEntry({ round: 2, team: "coordinator", type: "synthesis", subject: "c", content: "synth-2", targetHint: null });

    const syntheses = log.getSyntheses();
    expect(syntheses).toHaveLength(2);
    expect(syntheses.every((e) => e.type === "synthesis")).toBe(true);
  });
});

describe("intel-log — questions filtering", () => {
  it("getQuestionsForTeam excludes questions from the requesting team", () => {
    log.addEntry({ round: 1, team: "alpha", type: "question", subject: "rate-limit", content: "Does rate limit reset per identity?", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "question", subject: "bond-capacity", content: "What is the max bond?", targetHint: null });
    log.addEntry({ round: 1, team: "gamma", type: "question", subject: "/execute", content: "Is there a payload size limit?", targetHint: null });
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "timing", content: "Not a question", targetHint: null });

    const forAlpha = log.getQuestionsForTeam("alpha");
    expect(forAlpha).toHaveLength(2);
    expect(forAlpha.every((e) => e.team !== "alpha")).toBe(true);
    expect(forAlpha.every((e) => e.type === "question")).toBe(true);

    const forBeta = log.getQuestionsForTeam("beta");
    expect(forBeta).toHaveLength(2);
    expect(forBeta.every((e) => e.team !== "beta")).toBe(true);
  });

  it("getQuestionsForTeam returns empty array when no questions from other teams", () => {
    log.addEntry({ round: 1, team: "alpha", type: "question", subject: "a", content: "own question", targetHint: null });
    expect(log.getQuestionsForTeam("alpha")).toHaveLength(0);
  });
});

describe("intel-log — getSharedIntelForStrategist", () => {
  it("only includes entries from prior rounds, not current round", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "round 1 obs", targetHint: null });
    log.addEntry({ round: 2, team: "beta", type: "observation", subject: "b", content: "round 2 obs", targetHint: null });
    log.addEntry({ round: 3, team: "gamma", type: "observation", subject: "c", content: "round 3 obs", targetHint: null });

    const intel = log.getSharedIntelForStrategist("alpha", 3);
    expect(intel).toContain("round 1 obs");
    expect(intel).toContain("round 2 obs");
    expect(intel).not.toContain("round 3 obs");
  });

  it("returns 'No prior intelligence available.' for round 1", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "current round", targetHint: null });
    const intel = log.getSharedIntelForStrategist("alpha", 1);
    expect(intel).toBe("No prior intelligence available.");
  });

  it("includes entries from all teams and coordinator", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "alpha saw this", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "question", subject: "b", content: "beta asks this", targetHint: null });
    log.addEntry({ round: 1, team: "coordinator", type: "synthesis", subject: "c", content: "coordinator says this", targetHint: null });

    const intel = log.getSharedIntelForStrategist("gamma", 2);
    expect(intel).toContain("[alpha]");
    expect(intel).toContain("[beta]");
    expect(intel).toContain("[coordinator]");
    expect(intel).toContain("alpha saw this");
    expect(intel).toContain("beta asks this");
    expect(intel).toContain("coordinator says this");
  });

  it("includes targetHint when present", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "rate-limit", content: "10/60s per identity", targetHint: "/v1/actions/execute" });
    const intel = log.getSharedIntelForStrategist("beta", 2);
    expect(intel).toContain("[target: /v1/actions/execute]");
  });

  it("omits targetHint marker when null", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "rate-limit", content: "10/60s", targetHint: null });
    const intel = log.getSharedIntelForStrategist("beta", 2);
    expect(intel).not.toContain("[target:");
  });

  it("groups entries by round in output", () => {
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "r1", targetHint: null });
    log.addEntry({ round: 2, team: "beta", type: "observation", subject: "b", content: "r2", targetHint: null });

    const intel = log.getSharedIntelForStrategist("gamma", 3);
    expect(intel).toContain("--- Round 1 ---");
    expect(intel).toContain("--- Round 2 ---");
    // Round 1 header should appear before Round 2 header
    const r1Pos = intel.indexOf("--- Round 1 ---");
    const r2Pos = intel.indexOf("--- Round 2 ---");
    expect(r1Pos).toBeLessThan(r2Pos);
  });

  it("returns no prior intelligence when log is empty", () => {
    const intel = log.getSharedIntelForStrategist("alpha", 1);
    expect(intel).toBe("No prior intelligence available.");
  });
});

describe("intel-log — chronological ordering", () => {
  it("entries maintain insertion order across all queries", () => {
    log.addEntry({ round: 1, team: "gamma", type: "observation", subject: "z", content: "first", targetHint: null });
    log.addEntry({ round: 1, team: "alpha", type: "observation", subject: "a", content: "second", targetHint: null });
    log.addEntry({ round: 1, team: "beta", type: "observation", subject: "m", content: "third", targetHint: null });

    const all = log.getAllEntries();
    expect(all[0].content).toBe("first");
    expect(all[1].content).toBe("second");
    expect(all[2].content).toBe("third");

    const round1 = log.getEntriesByRound(1);
    expect(round1[0].content).toBe("first");
    expect(round1[1].content).toBe("second");
    expect(round1[2].content).toBe("third");
  });
});
