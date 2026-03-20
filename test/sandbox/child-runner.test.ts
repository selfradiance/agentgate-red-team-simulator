// Tests for the sandboxed child runner — verifies global nullification and toolkit behavior

import { describe, it, expect } from "vitest";
import { fork } from "node:child_process";
import path from "node:path";

const CHILD_RUNNER = path.resolve("src/sandbox/child-runner.js");

function runInChild(code: string, timeoutMs = 10000): Promise<{ type: string; result?: unknown; error?: string; logs: string[] }> {
  return new Promise((resolve, reject) => {
    const logs: string[] = [];
    let createCount = 0;
    const child = fork(CHILD_RUNNER, [], {
      env: { NODE_ENV: "sandbox" },
      stdio: ["pipe", "pipe", "pipe", "ipc"],
    });

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("Child runner timed out"));
    }, timeoutMs);

    child.on("message", (msg: any) => {
      if (msg.type === "log") {
        logs.push(msg.message);
        return;
      }

      // Handle toolkit IPC requests with stub responses
      if (msg.type === "toolkit-request") {
        const { id, method } = msg;
        try {
          let result: unknown;
          switch (method) {
            case "signedPost":
            case "rawPost":
            case "signedPostAs":
            case "rawGet":
              result = { status: 200, body: { stub: true } };
              break;
            case "createIdentity":
              createCount++;
              if (createCount > 3) throw new Error("createIdentity() cap exceeded: maximum 3 identities per attack execution");
              result = { identityId: `stub-id-${createCount}`, publicKey: `stub-key-${createCount}`, privateKey: `stub-priv-${createCount}` };
              break;
            case "getReputation":
              result = { score: 0 };
              break;
            case "getBondStatus":
              result = { status: "active" };
              break;
            case "getActionStatus":
              result = { status: "open" };
              break;
            case "checkDashboardForRawHtml":
              result = { foundRawHtml: false };
              break;
            default:
              child.send({ type: "toolkit-error", id, error: `Unknown method: ${method}` });
              return;
          }
          child.send({ type: "toolkit-response", id, result });
        } catch (err: any) {
          child.send({ type: "toolkit-error", id, error: err.message });
        }
        return;
      }

      // Result or error from execution
      clearTimeout(timer);
      child.kill();
      resolve({ ...msg, logs });
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Child exited with code ${code} without sending a result`));
    });

    child.send({ type: "execute", code });
  });
}

describe("child-runner sandbox", () => {
  it("returns result from simple function", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) { return { caught: true, reason: "test" }; }`,
    );
    expect(result.type).toBe("result");
    expect(result.result).toEqual({ caught: true, reason: "test" });
  });

  it("blocks fetch access", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) { await fetch("http://evil.com"); return { caught: false, reason: "should not reach" }; }`,
    );
    expect(result.type).toBe("error");
    expect(result.error).toMatch(/fetch.*not.*defined|fetch is not a function/i);
  });

  it("blocks require access", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) { const fs = require("fs"); return { caught: false, reason: "should not reach" }; }`,
    );
    expect(result.type).toBe("error");
    expect(result.error).toMatch(/require.*not.*defined|require is not a function/i);
  });

  it("blocks process access", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) { const key = process.env.ANTHROPIC_API_KEY; return { caught: false, reason: key }; }`,
    );
    expect(result.type).toBe("error");
    expect(result.error).toMatch(/process.*not.*defined|Cannot read/i);
  });

  it("enforces createIdentity cap at 3", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) {
        await toolkit.createIdentity();
        await toolkit.createIdentity();
        await toolkit.createIdentity();
        await toolkit.createIdentity();
        return { caught: false, reason: "should not reach" };
      }`,
    );
    expect(result.type).toBe("error");
    expect(result.error).toContain("cap exceeded");
  });

  it("toolkit is frozen", async () => {
    const result = await runInChild(
      `async function novelAttack(toolkit) {
        try {
          toolkit.signedPost = function() { return "hacked"; };
        } catch (e) {
          return { caught: true, reason: "frozen: " + e.message };
        }
        const r = await toolkit.signedPost("/test", {});
        if (r.body && r.body.stub === true) {
          return { caught: true, reason: "assignment silently failed, original stub still works" };
        }
        return { caught: false, reason: "toolkit was modified" };
      }`,
    );
    expect(result.type).toBe("result");
    expect(result.result).toHaveProperty("caught", true);
  });
});
