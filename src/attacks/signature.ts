// Signature attack scenarios — tests whether AgentGate rejects tampered or invalid signatures

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient } from "./replay";

const CATEGORY = "Signature Tampering";

// ---------------------------------------------------------------------------
// Attack 3.1: Wrong private key
// ---------------------------------------------------------------------------

async function attack3_1(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.1",
  };

  // Generate a completely different keypair
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const wrongPub = Buffer.from(publicJwk.x!, "base64url").toString("base64");
  const wrongPriv = Buffer.from(privateJwk.d!, "base64url").toString("base64");

  // Sign with the WRONG key but send to the registered identity
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(wrongPub, wrongPriv, nonce, "POST", apiPath, timestamp, body);

  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
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

  const caught = response.status >= 400;
  return {
    scenarioId: "3.1",
    scenarioName: "Wrong private key",
    category: CATEGORY,
    expectedOutcome: "Rejected — signature doesn't match registered identity's public key",
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the wrong-key signature (${response.status}).`
      : `AgentGate accepted a request signed with a different keypair — signature verification may not check against the registered public key.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 3.2: Malformed signature
// ---------------------------------------------------------------------------

async function attack3_2(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.2",
  };

  const nonce = randomUUID();
  const timestamp = Date.now().toString();

  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nonce": nonce,
      "x-agentgate-key": client.apiKey,
      "x-agentgate-timestamp": timestamp,
      "x-agentgate-signature": "not-a-real-signature-lol",
    },
    body: JSON.stringify(body),
  });

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  const caught = response.status >= 400;
  return {
    scenarioId: "3.2",
    scenarioName: "Malformed signature",
    category: CATEGORY,
    expectedOutcome: "Rejected — garbage signature cannot pass verification",
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the malformed signature (${response.status}).`
      : `AgentGate accepted a garbage signature string — signature verification may be bypassed or missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 3.3: Missing signature headers
// ---------------------------------------------------------------------------

async function attack3_3(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.3",
  };

  // Send with NO signature, timestamp, or nonce headers
  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agentgate-key": client.apiKey,
    },
    body: JSON.stringify(body),
  });

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  const caught = response.status >= 400;
  return {
    scenarioId: "3.3",
    scenarioName: "Missing signature headers",
    category: CATEGORY,
    expectedOutcome: "Rejected — missing x-agentgate-signature, x-agentgate-timestamp, x-nonce",
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the request with missing headers (${response.status}).`
      : `AgentGate accepted a request with no signature headers — header validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const signatureAttacks: AttackScenario[] = [
  {
    id: "3.1",
    name: "Wrong private key",
    category: CATEGORY,
    description: "Sign a request with a different keypair than the registered identity",
    expectedOutcome: "rejected — signature mismatch",
    execute: attack3_1,
  },
  {
    id: "3.2",
    name: "Malformed signature",
    category: CATEGORY,
    description: "Send a request with a garbage signature string",
    expectedOutcome: "rejected — invalid signature format",
    execute: attack3_2,
  },
  {
    id: "3.3",
    name: "Missing signature headers",
    category: CATEGORY,
    description: "Send a request with no signature, timestamp, or nonce headers",
    expectedOutcome: "rejected — missing required headers",
    execute: attack3_3,
  },
];
