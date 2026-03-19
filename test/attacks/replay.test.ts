// Integration tests for replay attack scenarios — requires live AgentGate

import "dotenv/config";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { randomUUID } from "node:crypto";
import { replayAttacks, type AttackClient } from "../../src/attacks/replay";
import { signRequest } from "../../src/agentgate-client";

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

describe.skipIf(!process.env.AGENTGATE_REST_KEY || process.env.AGENTGATE_REST_KEY.includes("your-"))(
  "replay attacks — live AgentGate",
  () => {
    let client: AttackClient;

    beforeAll(async () => {
      // Generate a fresh keypair (not from file — isolated for tests)
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const publicJwk = publicKey.export({ format: "jwk" });
      const privateJwk = privateKey.export({ format: "jwk" });

      const keys = {
        publicKey: base64UrlToBase64(publicJwk.x!),
        privateKey: base64UrlToBase64(privateJwk.d!),
      };

      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const apiKey = process.env.AGENTGATE_REST_KEY!;

      // Register identity
      const nonce = randomUUID();
      const timestamp = Date.now().toString();
      const apiPath = "/v1/identities";
      const body = { publicKey: keys.publicKey };
      const signature = signRequest(keys.publicKey, keys.privateKey, nonce, "POST", apiPath, timestamp, body);

      const response = await fetch(new URL(apiPath, agentGateUrl), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-nonce": nonce,
          "x-agentgate-key": apiKey,
          "x-agentgate-timestamp": timestamp,
          "x-agentgate-signature": signature,
        },
        body: JSON.stringify(body),
      });

      const data = await response.json() as Record<string, unknown>;
      if (!response.ok) {
        throw new Error(`Failed to create identity: ${JSON.stringify(data)}`);
      }

      client = {
        agentGateUrl,
        apiKey,
        keys,
        identityId: data.identityId as string,
      };
    });

    it("1.1 — exact duplicate request is rejected", async () => {
      const result = await replayAttacks[0].execute(client);
      expect(result.caught).toBe(true);
      expect(result.scenarioId).toBe("1.1");
    });

    it("1.2 — same signature with fresh nonce is rejected", async () => {
      const result = await replayAttacks[1].execute(client);
      expect(result.caught).toBe(true);
      expect(result.scenarioId).toBe("1.2");
    });

    it("1.3 — expired timestamp is rejected", async () => {
      const result = await replayAttacks[2].execute(client);
      expect(result.caught).toBe(true);
      expect(result.scenarioId).toBe("1.3");
    });
  },
);
