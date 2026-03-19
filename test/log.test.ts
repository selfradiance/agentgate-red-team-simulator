// Tests for AttackLog — recording and retrieving attack results

import { describe, it, expect } from "vitest";
import { AttackLog, type AttackResult } from "../src/log";

function makeResult(id: string): AttackResult {
  return {
    scenarioId: id,
    scenarioName: `Scenario ${id}`,
    category: "test",
    expectedOutcome: "rejected",
    actualOutcome: "rejected",
    caught: true,
    details: "test detail",
  };
}

describe("AttackLog", () => {
  it("starts with empty results", () => {
    const log = new AttackLog();
    expect(log.getResults()).toEqual([]);
  });

  it("records and retrieves attack results", () => {
    const log = new AttackLog();
    const r1 = makeResult("1.1");
    const r2 = makeResult("2.1");
    log.record(r1);
    log.record(r2);
    const results = log.getResults();
    expect(results).toHaveLength(2);
    expect(results[0].scenarioId).toBe("1.1");
    expect(results[1].scenarioId).toBe("2.1");
  });

  it("getResults returns a copy, not the internal array", () => {
    const log = new AttackLog();
    log.record(makeResult("1.1"));
    const results = log.getResults();
    results.push(makeResult("9.9"));
    expect(log.getResults()).toHaveLength(1);
  });
});
