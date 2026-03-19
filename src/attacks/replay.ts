// Replay attack scenarios — tests whether AgentGate rejects duplicate nonces and replayed requests

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest, type AgentKeys } from "../agentgate-client";

export interface AttackScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  expectedOutcome: string;
  execute: (client: AttackClient) => Promise<AttackResult>;
}

export interface AttackClient {
  agentGateUrl: string;
  apiKey: string;
  keys: AgentKeys;
  identityId: string;
}

const CATEGORY = "Replay Attacks";

// ---------------------------------------------------------------------------
// Helper — send a raw signed request (bypasses the high-level client so we
// can control nonce, timestamp, and signature independently)
// ---------------------------------------------------------------------------

async function rawPost(
  client: AttackClient,
  apiPath: string,
  body: unknown,
  opts: { nonce: string; timestamp: string; signature: string },
): Promise<{ status: number; data: Record<string, unknown> }> {
  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nonce": opts.nonce,
      "x-agentgate-key": client.apiKey,
      "x-agentgate-timestamp": opts.timestamp,
      "x-agentgate-signature": opts.signature,
    },
    body: JSON.stringify(body),
  });

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  return { status: response.status, data };
}

// Helper — make a properly signed request and return all the parts
function buildSignedRequest(client: AttackClient, apiPath: string, body: unknown, overrides?: { nonce?: string; timestamp?: string }) {
  const nonce = overrides?.nonce ?? randomUUID();
  const timestamp = overrides?.timestamp ?? Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, body);
  return { nonce, timestamp, signature };
}

// ---------------------------------------------------------------------------
// Attack 1.1: Exact duplicate request
// ---------------------------------------------------------------------------

async function attack1_1(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.1",
  };

  const req = buildSignedRequest(client, apiPath, body);

  // First request — should succeed
  const first = await rawPost(client, apiPath, body, req);
  if (first.status >= 300) {
    return {
      scenarioId: "1.1",
      scenarioName: "Exact duplicate request",
      category: CATEGORY,
      expectedOutcome: "First request succeeds (200), duplicate rejected (409 DUPLICATE_NONCE)",
      actualOutcome: `First request failed unexpectedly: ${first.status} ${JSON.stringify(first.data)}`,
      caught: false,
      details: "Could not complete test — first request did not succeed.",
    };
  }

  // Second request — exact same nonce, timestamp, signature, body
  const second = await rawPost(client, apiPath, body, req);

  const caught = second.status === 409;
  return {
    scenarioId: "1.1",
    scenarioName: "Exact duplicate request",
    category: CATEGORY,
    expectedOutcome: "Duplicate rejected with 409 DUPLICATE_NONCE",
    actualOutcome: `${second.status} ${JSON.stringify(second.data)}`,
    caught,
    details: caught
      ? "AgentGate correctly rejected the duplicate nonce."
      : `AgentGate accepted the duplicate request with status ${second.status} — replay protection may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 1.2: Same signature, fresh nonce
// ---------------------------------------------------------------------------

async function attack1_2(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.2",
  };

  // Sign with the original nonce
  const originalReq = buildSignedRequest(client, apiPath, body);

  // Send with a fresh nonce but the OLD signature (signature won't match the new nonce)
  const freshNonce = randomUUID();
  const result = await rawPost(client, apiPath, body, {
    nonce: freshNonce,
    timestamp: originalReq.timestamp,
    signature: originalReq.signature, // stale signature — signed against original nonce
  });

  // Should be rejected because the signature was computed with the original nonce,
  // not the fresh one. AgentGate verifies sha256(nonce + method + path + timestamp + body).
  const caught = result.status >= 400;
  return {
    scenarioId: "1.2",
    scenarioName: "Same signature, fresh nonce",
    category: CATEGORY,
    expectedOutcome: "Rejected — signature doesn't match the new nonce",
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the mismatched nonce/signature (${result.status}).`
      : `AgentGate accepted a request where the signature was computed with a different nonce — nonce is not bound into the signature verification.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 1.3: Expired timestamp
// ---------------------------------------------------------------------------

async function attack1_3(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.3",
  };

  // Timestamp 120 seconds in the past (well outside 60s window)
  const staleTimestamp = (Date.now() - 120_000).toString();
  const req = buildSignedRequest(client, apiPath, body, { timestamp: staleTimestamp });

  const result = await rawPost(client, apiPath, body, req);

  const caught = result.status >= 400;
  return {
    scenarioId: "1.3",
    scenarioName: "Expired timestamp",
    category: CATEGORY,
    expectedOutcome: "Rejected — timestamp 120s in the past exceeds the allowed window",
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the stale timestamp (${result.status}).`
      : `AgentGate accepted a request with a 120-second-old timestamp — replay window may be too large or timestamp validation is missing.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const replayAttacks: AttackScenario[] = [
  {
    id: "1.1",
    name: "Exact duplicate request",
    category: CATEGORY,
    description: "Replay an identical signed request with the same nonce",
    expectedOutcome: "rejected with 409 DUPLICATE_NONCE",
    execute: attack1_1,
  },
  {
    id: "1.2",
    name: "Same signature, fresh nonce",
    category: CATEGORY,
    description: "Send a request with a fresh nonce but reuse the old signature",
    expectedOutcome: "rejected — signature mismatch",
    execute: attack1_2,
  },
  {
    id: "1.3",
    name: "Expired timestamp",
    category: CATEGORY,
    description: "Send a signed request with a timestamp 120 seconds in the past",
    expectedOutcome: "rejected — stale timestamp",
    execute: attack1_3,
  },
];
