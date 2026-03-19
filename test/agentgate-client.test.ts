// Tests for the AgentGate client — keypair generation, signing, and live integration

import "dotenv/config";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadOrCreateKeypair, createIdentity } from "../src/agentgate-client";
import { createHash, createPrivateKey, sign } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const IDENTITY_FILE = path.resolve("agent-identity.json");

function cleanup() {
  if (fs.existsSync(IDENTITY_FILE)) fs.unlinkSync(IDENTITY_FILE);
}

describe("agentgate-client — unit tests", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("generates Ed25519 keypair", () => {
    const keys = loadOrCreateKeypair();
    expect(keys.publicKey).toBeTruthy();
    expect(keys.privateKey).toBeTruthy();
    // Ed25519 public key is 32 bytes = 44 base64 chars (with padding)
    const pubBytes = Buffer.from(keys.publicKey, "base64");
    expect(pubBytes.length).toBe(32);
    // Ed25519 private key seed is 32 bytes
    const privBytes = Buffer.from(keys.privateKey, "base64");
    expect(privBytes.length).toBe(32);
  });

  it("signs a request deterministically", () => {
    const keys = loadOrCreateKeypair();

    // Reconstruct the private key in the same way agentgate-client does
    const publicKeyBytes = Buffer.from(keys.publicKey, "base64");
    const privateKeyBytes = Buffer.from(keys.privateKey, "base64");

    function toBase64Url(buffer: Buffer): string {
      return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    const privateKey = createPrivateKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: toBase64Url(publicKeyBytes),
        d: toBase64Url(privateKeyBytes),
      },
      format: "jwk",
    });

    // Sign the same message twice
    const message = createHash("sha256").update("testnoncePOST/v1/identities1234567890{}").digest();
    const sig1 = sign(null, message, privateKey);
    const sig2 = sign(null, message, privateKey);

    expect(sig1.toString("base64")).toBe(sig2.toString("base64"));
    // Ed25519 signatures are 64 bytes
    expect(sig1.length).toBe(64);
  });
});

describe.skipIf(!process.env.AGENTGATE_REST_KEY || process.env.AGENTGATE_REST_KEY.includes("your-"))(
  "agentgate-client — integration tests (live AgentGate)",
  () => {
    beforeEach(cleanup);
    afterEach(cleanup);

    it("creates identity on live AgentGate", async () => {
      const keys = loadOrCreateKeypair();
      const identityId = await createIdentity(keys);
      expect(identityId).toBeTruthy();
      expect(typeof identityId).toBe("string");
      expect(identityId.startsWith("id_")).toBe(true);
    });
  },
);
