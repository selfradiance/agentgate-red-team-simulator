// Replay attack scenarios — tests whether AgentGate rejects duplicate nonces and replayed requests

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest, type AgentKeys } from "../agentgate-client";

export interface AttackParams {
  [key: string]: unknown;
}

export interface AttackScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  expectedOutcome: string;
  execute: (client: AttackClient, params?: AttackParams) => Promise<AttackResult>;
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

async function attack1_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const replayCount = (typeof params?.replay_count === "number" ? params.replay_count : 1);
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

  // Send duplicate(s) — exact same nonce, timestamp, signature, body
  let lastStatus = 0;
  let lastData: Record<string, unknown> = {};
  let allRejected = true;

  for (let i = 0; i < replayCount; i++) {
    const dup = await rawPost(client, apiPath, body, req);
    lastStatus = dup.status;
    lastData = dup.data;
    if (dup.status !== 409) allRejected = false;
  }

  const caught = allRejected;
  return {
    scenarioId: "1.1",
    scenarioName: "Exact duplicate request",
    category: CATEGORY,
    expectedOutcome: "Duplicate rejected with 409 DUPLICATE_NONCE",
    actualOutcome: `${lastStatus} ${JSON.stringify(lastData)} (${replayCount} duplicate(s) sent)`,
    caught,
    details: caught
      ? `AgentGate correctly rejected ${replayCount} duplicate nonce(s).`
      : `AgentGate accepted a duplicate request with status ${lastStatus} — replay protection may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 1.2: Same signature, fresh nonce
// ---------------------------------------------------------------------------

async function attack1_2(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
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

async function attack1_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const timestampAgeSeconds = (typeof params?.timestamp_age_seconds === "number" ? params.timestamp_age_seconds : 120);

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.3",
  };

  // Timestamp N seconds in the past
  const staleTimestamp = (Date.now() - timestampAgeSeconds * 1000).toString();
  const req = buildSignedRequest(client, apiPath, body, { timestamp: staleTimestamp });

  const result = await rawPost(client, apiPath, body, req);

  const caught = result.status >= 400;
  return {
    scenarioId: "1.3",
    scenarioName: "Expired timestamp",
    category: CATEGORY,
    expectedOutcome: `Rejected — timestamp ${timestampAgeSeconds}s in the past exceeds the allowed window`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the stale timestamp at ${timestampAgeSeconds}s age (${result.status}).`
      : `AgentGate accepted a request with a ${timestampAgeSeconds}-second-old timestamp — replay window may be too large or timestamp validation is missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 1.4: Timestamp at exact boundary
// ---------------------------------------------------------------------------

async function attack1_4(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const timestampAgeSeconds = (typeof params?.timestamp_age_seconds === "number" ? params.timestamp_age_seconds : 60);

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.4",
  };

  // Timestamp exactly at the boundary of the staleness window
  const boundaryTimestamp = (Date.now() - timestampAgeSeconds * 1000).toString();
  const req = buildSignedRequest(client, apiPath, body, { timestamp: boundaryTimestamp });

  const result = await rawPost(client, apiPath, body, req);

  // At exactly 60s, behavior depends on whether the check is < or <=.
  // Either outcome is informative — this is a boundary probe, not a strict pass/fail.
  // Both results are "caught" because the point is gathering data for the strategist.
  const rejected = result.status >= 400;
  return {
    scenarioId: "1.4",
    scenarioName: "Timestamp at exact boundary",
    category: CATEGORY,
    expectedOutcome: `Probing staleness boundary at ${timestampAgeSeconds}s — may accept or reject`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught: true,
    details: rejected
      ? `AgentGate rejected timestamp at ${timestampAgeSeconds}s age (${result.status}) — boundary is exclusive.`
      : `AgentGate accepted timestamp at ${timestampAgeSeconds}s age — boundary is inclusive (accepts at exactly ${timestampAgeSeconds}s).`,
  };
}

// ---------------------------------------------------------------------------
// Attack 1.5: Future timestamp
// ---------------------------------------------------------------------------

async function attack1_5(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const futureOffsetSeconds = (typeof params?.future_offset_seconds === "number" ? params.future_offset_seconds : 10);

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "replay-test-1.5",
  };

  // Timestamp N seconds in the future (AgentGate rejects >5s ahead per milestone 61)
  const futureTimestamp = (Date.now() + futureOffsetSeconds * 1000).toString();
  const req = buildSignedRequest(client, apiPath, body, { timestamp: futureTimestamp });

  const result = await rawPost(client, apiPath, body, req);

  const caught = result.status >= 400;
  return {
    scenarioId: "1.5",
    scenarioName: "Future timestamp",
    category: CATEGORY,
    expectedOutcome: `Rejected — timestamp ${futureOffsetSeconds}s in the future exceeds 5s tolerance`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the future timestamp at +${futureOffsetSeconds}s (${result.status}).`
      : `AgentGate accepted a request with a timestamp ${futureOffsetSeconds}s in the future — future timestamp validation may be missing or too lenient.`,
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
    execute: (client, params?) => attack1_1(client, params),
  },
  {
    id: "1.2",
    name: "Same signature, fresh nonce",
    category: CATEGORY,
    description: "Send a request with a fresh nonce but reuse the old signature",
    expectedOutcome: "rejected — signature mismatch",
    execute: (client, params?) => attack1_2(client, params),
  },
  {
    id: "1.3",
    name: "Expired timestamp",
    category: CATEGORY,
    description: "Send a signed request with a timestamp 120 seconds in the past",
    expectedOutcome: "rejected — stale timestamp",
    execute: (client, params?) => attack1_3(client, params),
  },
  {
    id: "1.4",
    name: "Timestamp at exact boundary",
    category: CATEGORY,
    description: "Send a signed request with a timestamp at the exact 60s staleness boundary",
    expectedOutcome: "probing boundary — may accept or reject",
    execute: (client, params?) => attack1_4(client, params),
  },
  {
    id: "1.5",
    name: "Future timestamp",
    category: CATEGORY,
    description: "Send a signed request with a timestamp 10s in the future (>5s tolerance)",
    expectedOutcome: "rejected — future timestamp",
    execute: (client, params?) => attack1_5(client, params),
  },
];
