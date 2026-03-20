// Tests for the parent-side sandbox executor

import { describe, it, expect } from "vitest";
import { executeInSandbox } from "../../src/sandbox/executor";
import fs from "node:fs";
import os from "node:os";

describe("sandbox executor", () => {
  it("executes simple function and returns result", { timeout: 15000 }, async () => {
    const result = await executeInSandbox(
      'async function novelAttack(toolkit) { return { caught: true, reason: "test attack" }; }',
    );
    expect(result.success).toBe(true);
    expect(result.result?.caught).toBe(true);
    expect(result.result?.reason).toBe("test attack");
    expect(result.timedOut).toBeFalsy();
    expect(result.durationMs).toBeGreaterThan(0);
  });

  it("handles syntax error in generated code", { timeout: 15000 }, async () => {
    const result = await executeInSandbox("this is not valid javascript }{}{");
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("kills child on timeout with infinite loop", { timeout: 30000 }, async () => {
    const result = await executeInSandbox(
      "async function novelAttack(toolkit) { while(true) {} }",
    );
    expect(result.success).toBe(false);
    expect(result.timedOut).toBe(true);
    expect(result.durationMs).toBeGreaterThanOrEqual(14000);
  });

  it("blocks filesystem write attempt", { timeout: 15000 }, async () => {
    const result = await executeInSandbox(
      `async function novelAttack(toolkit) {
        const r = require("fs");
        r.writeFileSync("/tmp/hacked.txt", "pwned");
        return { caught: false, reason: "should not reach" };
      }`,
    );
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("cleans up temp directory after execution", { timeout: 15000 }, async () => {
    const before = fs.readdirSync(os.tmpdir()).filter((d) => d.startsWith("agent-004-sandbox-"));

    await executeInSandbox(
      'async function novelAttack(toolkit) { return { caught: true, reason: "cleanup test" }; }',
    );

    const after = fs.readdirSync(os.tmpdir()).filter((d) => d.startsWith("agent-004-sandbox-"));
    expect(after.length).toBe(before.length);
  });

  it("collects logs from child", { timeout: 15000 }, async () => {
    const result = await executeInSandbox(
      `async function novelAttack(toolkit) {
        toolkit.log("hello from sandbox");
        return { caught: true, reason: "logged" };
      }`,
    );
    expect(result.success).toBe(true);
    expect(result.logs).toContain("hello from sandbox");
  });
});
