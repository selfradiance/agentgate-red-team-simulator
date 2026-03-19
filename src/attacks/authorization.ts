// Authorization attack scenarios — tests whether AgentGate enforces identity boundaries and admin access

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient } from "./replay";

const CATEGORY = "Authorization Boundaries";

// ---------------------------------------------------------------------------
// Helper — send a properly signed POST request to AgentGate
// ---------------------------------------------------------------------------

async function signedPost(
  agentGateUrl: string,
  apiKey: string,
  publicKey: string,
  privateKey: string,
  apiPath: string,
  body: unknown,
): Promise<{ status: number; data: Record<string, unknown> }> {
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(publicKey, privateKey, nonce, "POST", apiPath, timestamp, body);

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

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  return { status: response.status, data };
}

// Helper — generate a fresh keypair as base64 strings
function freshKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  return {
    publicKey: Buffer.from(publicJwk.x!, "base64url").toString("base64"),
    privateKey: Buffer.from(privateJwk.d!, "base64url").toString("base64"),
  };
}

// Helper — register a new identity and return its ID
async function registerIdentity(
  agentGateUrl: string,
  apiKey: string,
  publicKey: string,
  privateKey: string,
): Promise<string> {
  const result = await signedPost(agentGateUrl, apiKey, publicKey, privateKey, "/v1/identities", {
    publicKey,
  });
  if (result.status >= 300) {
    throw new Error(`Failed to register identity: ${result.status} ${JSON.stringify(result.data)}`);
  }
  return result.data.identityId as string;
}

// ---------------------------------------------------------------------------
// Attack 4.1: Admin endpoint without admin key
// ---------------------------------------------------------------------------

async function attack4_1(client: AttackClient): Promise<AttackResult> {
  const apiPath = "/admin/ban-identity";
  const body = { identityId: client.identityId, reason: "auth-test-4.1" };

  // Send with the regular REST key, not the admin key
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, body);

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
    scenarioId: "4.1",
    scenarioName: "Admin endpoint without admin key",
    category: CATEGORY,
    expectedOutcome: "Rejected with 401 or 403 — non-admin key cannot access admin endpoints",
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the non-admin request to /admin/ban-identity (${response.status}).`
      : `AgentGate accepted a request to an admin endpoint using a regular REST key — admin access control may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 4.2: Resolve another identity's action
// ---------------------------------------------------------------------------

async function attack4_2(client: AttackClient): Promise<AttackResult> {
  // Identity A is the client's identity — lock a bond and execute an action
  const bondResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    client.keys.publicKey, client.keys.privateKey,
    "/v1/bonds/lock",
    {
      identityId: client.identityId,
      amountCents: 100,
      currency: "USD",
      ttlSeconds: 300,
      reason: "auth-test-4.2",
    },
  );

  if (bondResult.status >= 300) {
    return {
      scenarioId: "4.2",
      scenarioName: "Resolve another identity's action",
      category: CATEGORY,
      expectedOutcome: "Rejected — identity B cannot resolve identity A's action",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  const actionResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    client.keys.publicKey, client.keys.privateKey,
    "/v1/actions/execute",
    {
      identityId: client.identityId,
      bondId,
      actionType: "auth-test",
      payload: { test: "4.2" },
      exposure_cents: exposureCents,
    },
  );

  if (actionResult.status >= 300) {
    return {
      scenarioId: "4.2",
      scenarioName: "Resolve another identity's action",
      category: CATEGORY,
      expectedOutcome: "Rejected — identity B cannot resolve identity A's action",
      actualOutcome: `Action execute failed: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
      caught: false,
      details: "Could not complete test — action execute did not succeed.",
    };
  }

  const actionId = actionResult.data.actionId as string;

  // Create identity B — completely separate keypair
  const keysB = freshKeypair();
  await registerIdentity(client.agentGateUrl, client.apiKey, keysB.publicKey, keysB.privateKey);

  // Identity B tries to resolve identity A's action
  const resolveResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    keysB.publicKey, keysB.privateKey,
    `/v1/actions/${actionId}/resolve`,
    { outcome: "failed" },
  );

  const caught = resolveResult.status >= 400;
  return {
    scenarioId: "4.2",
    scenarioName: "Resolve another identity's action",
    category: CATEGORY,
    expectedOutcome: "Rejected — identity B cannot resolve identity A's action",
    actualOutcome: `${resolveResult.status} ${JSON.stringify(resolveResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected identity B's attempt to resolve identity A's action (${resolveResult.status}).`
      : `AgentGate allowed identity B to resolve identity A's action — cross-identity authorization may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const authorizationAttacks: AttackScenario[] = [
  {
    id: "4.1",
    name: "Admin endpoint without admin key",
    category: CATEGORY,
    description: "Access /admin/ban-identity with a regular REST key instead of admin key",
    expectedOutcome: "rejected with 401 or 403",
    execute: attack4_1,
  },
  {
    id: "4.2",
    name: "Resolve another identity's action",
    category: CATEGORY,
    description: "Identity B tries to resolve an action belonging to identity A",
    expectedOutcome: "rejected — cross-identity resolution not allowed",
    execute: attack4_2,
  },
];
