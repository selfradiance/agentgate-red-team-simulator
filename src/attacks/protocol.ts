// Protocol abuse scenarios — tests whether AgentGate handles malformed HTTP requests correctly

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Protocol Abuse";

// ---------------------------------------------------------------------------
// Attack 8.1: Malformed request shape
// ---------------------------------------------------------------------------

async function attack8_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const variant = (typeof params?.variant === "string" ? params.variant : "get-to-post");

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "protocol-test-8.1",
  };

  let response: Response;

  if (variant === "get-to-post") {
    // Send a GET request to a POST-only endpoint
    response = await fetch(new URL(apiPath, client.agentGateUrl), {
      method: "GET",
      headers: {
        "x-agentgate-key": client.apiKey,
      },
    });
  } else {
    // POST with no body at all (not empty JSON — absent body)
    const nonce = randomUUID();
    const timestamp = Date.now().toString();
    // Sign with undefined body to match what we're sending
    const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, undefined);

    response = await fetch(new URL(apiPath, client.agentGateUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nonce": nonce,
        "x-agentgate-key": client.apiKey,
        "x-agentgate-timestamp": timestamp,
        "x-agentgate-signature": signature,
      },
      // No body
    });
  }

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  const caught = response.status >= 400;
  return {
    scenarioId: "8.1",
    scenarioName: "Malformed request shape",
    category: CATEGORY,
    expectedOutcome: `Rejected — ${variant === "get-to-post" ? "GET to POST-only endpoint" : "POST with absent body"}`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the ${variant} request (${response.status}).`
      : `AgentGate accepted a ${variant} request — protocol validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 8.2: Wrong Content-Type
// ---------------------------------------------------------------------------

async function attack8_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const contentType = (typeof params?.content_type === "string" ? params.content_type : "text/plain");

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "protocol-test-8.2",
  };

  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, body);

  // Send valid JSON body but with wrong Content-Type header
  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": contentType,
      "x-nonce": nonce,
      "x-agentgate-key": client.apiKey,
      "x-agentgate-timestamp": timestamp,
      "x-agentgate-signature": signature,
    },
    body: JSON.stringify(body),
  });

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  // Some frameworks parse JSON regardless of Content-Type, others reject it.
  // Both outcomes are informative.
  const rejected = response.status >= 400;
  return {
    scenarioId: "8.2",
    scenarioName: "Wrong Content-Type",
    category: CATEGORY,
    expectedOutcome: `Probing — valid JSON with Content-Type: ${contentType}`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught: true,
    details: rejected
      ? `AgentGate rejected the request with Content-Type: ${contentType} (${response.status}) — strict content-type validation.`
      : `AgentGate accepted JSON with Content-Type: ${contentType} — framework parses JSON regardless of content-type header.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const protocolAttacks: AttackScenario[] = [
  {
    id: "8.1",
    name: "Malformed request shape",
    category: CATEGORY,
    description: "GET to POST-only endpoint, or POST with absent body",
    expectedOutcome: "rejected — wrong method or missing body",
    execute: (client, params?) => attack8_1(client, params),
  },
  {
    id: "8.2",
    name: "Wrong Content-Type",
    category: CATEGORY,
    description: "Valid JSON body with Content-Type: text/plain or application/xml",
    expectedOutcome: "probing — may accept or reject depending on framework",
    execute: (client, params?) => attack8_2(client, params),
  },
];
