// Integration test for the recursive runner — requires AgentGate + Claude API

import "dotenv/config";
import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { runRecursiveRound } from "../src/recursive-runner";
import { signRequest } from "../src/agentgate-client";
import type { AttackClient } from "../src/attacks/replay";

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

const canRun = process.env.AGENTGATE_REST_KEY
  && !process.env.AGENTGATE_REST_KEY.includes("your-")
  && process.env.ANTHROPIC_API_KEY
  && !process.env.ANTHROPIC_API_KEY.includes("your-");

describe.skipIf(!canRun)(
  "recursive runner — full round with library + novel attacks",
  () => {
    let client: AttackClient;
    let agentIdentity: { identityId: string; publicKey: string; privateKey: string };

    beforeAll(async () => {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const publicJwk = publicKey.export({ format: "jwk" });
      const privateJwk = privateKey.export({ format: "jwk" });
      const pub = base64UrlToBase64(publicJwk.x!);
      const priv = base64UrlToBase64(privateJwk.d!);

      const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
      const apiKey = process.env.AGENTGATE_REST_KEY!;

      // Register identity
      const nonce = randomUUID();
      const timestamp = Date.now().toString();
      const apiPath = "/v1/identities";
      const body = { publicKey: pub };
      const signature = signRequest(pub, priv, nonce, "POST", apiPath, timestamp, body);

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
      if (!response.ok) throw new Error(`Failed to create identity: ${JSON.stringify(data)}`);

      const identityId = data.identityId as string;

      client = { agentGateUrl, apiKey, keys: { publicKey: pub, privateKey: priv }, identityId };
      agentIdentity = { identityId, publicKey: pub, privateKey: priv };
    });

    it("completes a recursive round with library and novel attacks", { timeout: 120000 }, async () => {
      const result = await runRecursiveRound(1, 1, [], client, {
        targetUrl: client.agentGateUrl,
        agentIdentity,
        restKey: client.apiKey,
      });

      // Library attacks should have been selected and run
      expect(result.libraryResults.length).toBeGreaterThan(0);

      // Reasoner should have produced hypotheses
      expect(result.hypotheses.length).toBeGreaterThan(0);

      // Generation outcomes should exist for each hypothesis
      expect(result.generationOutcomes.length).toBe(result.hypotheses.length);

      // Function completed without crashing — that's the key assertion
      expect(result.libraryResults).toBeDefined();
      expect(result.novelResults).toBeDefined();
    });
  },
);
