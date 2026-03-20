// Tests for the code validator — blocklist, structural checks, novelty gate

import { describe, it, expect } from "vitest";
import { validateGeneratedCode, checkNovelty } from "../../src/sandbox/validator";

const VALID_CODE = `async function novelAttack(toolkit) {
  const result = await toolkit.signedPost("/v1/bonds/lock", { amountCents: 100 });
  return { caught: result.status >= 400, reason: "tested bond lock" };
}`;

describe("validator — blocklist", () => {
  it("rejects code with require(", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { const fs = require('fs'); return { caught: false, reason: "bad" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("require(");
  });

  it("rejects code with fetch(", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { await fetch('http://evil.com'); return { caught: false, reason: "bad" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("fetch(");
  });

  it("rejects code with process.", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { const k = process.env.KEY; return { caught: false, reason: "bad" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("process.");
  });

  it("rejects code with eval(", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { eval('bad'); return { caught: false, reason: "bad" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("eval(");
  });

  it("rejects code with setTimeout", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { setTimeout(() => {}, 1000); return { caught: false, reason: "bad" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("setTimeout");
  });

  it("rejects code with fromCharCode", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { const s = String.fromCharCode(114); return { caught: false, reason: s }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("fromCharCode");
  });

  it("rejects code with atob(", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { const s = atob('cmVxdWlyZQ=='); return { caught: false, reason: s }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("atob(");
  });
});

describe("validator — structural checks", () => {
  it("accepts valid code", () => {
    const result = validateGeneratedCode(VALID_CODE);
    expect(result.valid).toBe(true);
  });

  it("rejects code exceeding 10KB", () => {
    const bigCode = `async function novelAttack(toolkit) { return { caught: true, reason: "${"x".repeat(10001)}" }; }`;
    const result = validateGeneratedCode(bigCode);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("10KB");
  });

  it("rejects missing function signature", () => {
    const result = validateGeneratedCode(
      `function doSomething() { return { caught: true, reason: "no sig" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Missing required function signature");
  });

  it("rejects multiple function definitions", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { return { caught: true, reason: "first" }; }
       async function novelAttack(toolkit) { return { caught: true, reason: "second" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Multiple function definitions");
  });

  it("rejects excessive nesting", () => {
    // 7 levels of braces: exceeds max of 6
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { if (true) { if (true) { if (true) { if (true) { if (true) { if (true) { return { caught: true, reason: "deep" }; } } } } } } }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("nesting depth");
  });

  it("rejects more than 20 toolkit calls", () => {
    const calls = Array.from({ length: 21 }, (_, i) =>
      `await toolkit.signedPost("/v1/test${i}", {});`,
    ).join("\n  ");
    const code = `async function novelAttack(toolkit) {\n  ${calls}\n  return { caught: true, reason: "many calls" };\n}`;
    const result = validateGeneratedCode(code);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("20 toolkit calls");
  });

  it("rejects unbounded while loop", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { while(true) { } return { caught: false, reason: "loop" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Unbounded loop");
  });

  it("rejects unbounded for loop", () => {
    const result = validateGeneratedCode(
      `async function novelAttack(toolkit) { for(;;) { } return { caught: false, reason: "loop" }; }`,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Unbounded loop");
  });
});

describe("validator — novelty gate", () => {
  it("passes when registry is null", () => {
    const result = checkNovelty("some code", "some description", null);
    expect(result.valid).toBe(true);
  });

  it("flags near-duplicate attack", () => {
    const registry = new Map([
      ["1.1", { name: "Exact duplicate request", description: "Replay an identical signed request with the same nonce" }],
    ]);
    const result = checkNovelty(
      "some code",
      "Replay an identical signed request with the same nonce to test duplicate detection",
      registry,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Too similar to existing attack");
    expect(result.reason).toContain("1.1");
  });

  it("passes for genuinely novel description", () => {
    const registry = new Map([
      ["1.1", { name: "Exact duplicate request", description: "Replay an identical signed request with the same nonce" }],
      ["3.1", { name: "Wrong private key", description: "Sign a request with a different keypair" }],
    ]);
    const result = checkNovelty(
      "some code",
      "Exploit race condition in WebSocket upgrade handshake to bypass authentication during connection establishment",
      registry,
    );
    expect(result.valid).toBe(true);
  });
});
