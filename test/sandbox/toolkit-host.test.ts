// Integration tests for the toolkit host — requires live AgentGate

import "dotenv/config";
import { describe, it, expect, beforeAll } from "vitest";
import { executeInSandbox } from "../../src/sandbox/executor";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { signRequest } from "../../src/agentgate-client";

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

describe.skipIf(!process.env.AGENTGATE_REST_KEY || process.env.AGENTGATE_REST_KEY.includes("your-"))(
  "toolkit-host — live AgentGate",
  () => {
    let agentIdentity: { identityId: string; publicKey: string; privateKey: string };
    let targetUrl: string;
    let restKey: string;

    beforeAll(async () => {
      targetUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      restKey = process.env.AGENTGATE_REST_KEY!;

      // Create a real identity
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const publicJwk = publicKey.export({ format: "jwk" });
      const privateJwk = privateKey.export({ format: "jwk" });
      const pub = base64UrlToBase64(publicJwk.x!);
      const priv = base64UrlToBase64(privateJwk.d!);

      const nonce = randomUUID();
      const timestamp = Date.now().toString();
      const apiPath = "/v1/identities";
      const body = { publicKey: pub };
      const signature = signRequest(pub, priv, nonce, "POST", apiPath, timestamp, body);

      const response = await fetch(new URL(apiPath, targetUrl), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-nonce": nonce,
          "x-agentgate-key": restKey,
          "x-agentgate-timestamp": timestamp,
          "x-agentgate-signature": signature,
        },
        body: JSON.stringify(body),
      });

      const data = await response.json() as Record<string, unknown>;
      if (!response.ok) throw new Error(`Failed to create identity: ${JSON.stringify(data)}`);

      agentIdentity = {
        identityId: data.identityId as string,
        publicKey: pub,
        privateKey: priv,
      };
    });

    it("toolkit.signedPost makes real HTTP call to AgentGate", { timeout: 20000 }, async () => {
      const result = await executeInSandbox(
        `async function novelAttack(toolkit) {
          const r = await toolkit.signedPost("/v1/bonds/lock", {
            identityId: "${agentIdentity.identityId}",
            amountCents: 100,
            currency: "USD",
            ttlSeconds: 300,
            reason: "sandbox-toolkit-test"
          });
          return { caught: true, reason: "got status " + r.status };
        }`,
        { targetUrl, agentIdentity, restKey },
      );

      expect(result.success).toBe(true);
      expect(result.result?.caught).toBe(true);
      expect(result.result?.reason).toMatch(/got status \d+/);
    });

    it("toolkit.createIdentity creates real identity on AgentGate", { timeout: 20000 }, async () => {
      const result = await executeInSandbox(
        `async function novelAttack(toolkit) {
          const id = await toolkit.createIdentity();
          return { caught: true, reason: "created " + id.identityId };
        }`,
        { targetUrl, agentIdentity, restKey },
      );

      expect(result.success).toBe(true);
      expect(result.result?.caught).toBe(true);
      expect(result.result?.reason).toMatch(/created id_/);
    });

    it("toolkit.createIdentity enforces cap at 3", { timeout: 20000 }, async () => {
      const result = await executeInSandbox(
        `async function novelAttack(toolkit) {
          await toolkit.createIdentity();
          await toolkit.createIdentity();
          await toolkit.createIdentity();
          await toolkit.createIdentity();
          return { caught: false, reason: "should not reach" };
        }`,
        { targetUrl, agentIdentity, restKey },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain("cap exceeded");
    });
  },
);
