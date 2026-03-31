// Unit tests for scout probe modules — validates structure and exports.
// Integration tests (against live AgentGate) are separate.

import { describe, it, expect } from "vitest";

import { hypothesis as h4 } from "../../src/sleeper/scout/probe-error-leakage.js";
import { hypothesis as h6 } from "../../src/sleeper/scout/probe-endpoint-shape.js";
import { hypothesis as h7 } from "../../src/sleeper/scout/probe-timestamp-window.js";
import { hypothesis as h2 } from "../../src/sleeper/scout/probe-bond-capacity.js";
import { hypothesis as h1 } from "../../src/sleeper/scout/probe-rate-limit.js";
import { hypothesis as h3 } from "../../src/sleeper/scout/probe-tier-promotion.js";
import { hypothesis as h5 } from "../../src/sleeper/scout/probe-nonce-replay.js";
import { generateKeypair } from "../../src/sleeper/scout/scout-client.js";

describe("Scout probe hypotheses", () => {
  it("S1 has correct hypothesis", () => {
    expect(h1).toBe("rate_limit_exhaustion");
  });

  it("S2 has correct hypothesis", () => {
    expect(h2).toBe("bond_capacity_calibration");
  });

  it("S3 has correct hypothesis", () => {
    expect(h3).toBe("tier_advancement_farming");
  });

  it("S4 has correct hypothesis", () => {
    expect(h4).toBe("error_surface_exploitation");
  });

  it("S5 has correct hypothesis", () => {
    expect(h5).toBe("replay_timing_window");
  });

  it("S6 has correct hypothesis", () => {
    expect(h6).toBe("unauthenticated_reconnaissance");
  });

  it("S7 has correct hypothesis", () => {
    expect(h7).toBe("timestamp_window_exploitation");
  });
});

describe("Scout client utilities", () => {
  it("generates valid Ed25519 keypair", () => {
    const keys = generateKeypair();
    expect(keys.publicKey).toBeTruthy();
    expect(keys.privateKey).toBeTruthy();
    // Ed25519 keys are 32 bytes = 44 chars in base64
    expect(Buffer.from(keys.publicKey, "base64").length).toBe(32);
    expect(Buffer.from(keys.privateKey, "base64").length).toBe(32);
  });

  it("generates unique keypairs", () => {
    const k1 = generateKeypair();
    const k2 = generateKeypair();
    expect(k1.publicKey).not.toBe(k2.publicKey);
    expect(k1.privateKey).not.toBe(k2.privateKey);
  });
});
