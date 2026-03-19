// Authorization attack scenarios — tests whether AgentGate enforces identity boundaries and admin access

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

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

async function attack4_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const adminEndpoint = (typeof params?.admin_endpoint === "string" ? params.admin_endpoint : "/admin/ban-identity");
  const apiPath = adminEndpoint;
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
      ? `AgentGate rejected the non-admin request to ${adminEndpoint} (${response.status}).`
      : `AgentGate accepted a request to ${adminEndpoint} using a regular REST key — admin access control may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 4.2: Resolve another identity's action
// ---------------------------------------------------------------------------

async function attack4_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const crossAction = (typeof params?.cross_action === "string" ? params.cross_action as "resolve" | "execute" : "resolve");
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

  // Identity B tries to act on identity A's action
  const crossResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    keysB.publicKey, keysB.privateKey,
    `/v1/actions/${actionId}/resolve`,
    { outcome: "failed" },
  );

  const caught = crossResult.status >= 400;
  return {
    scenarioId: "4.2",
    scenarioName: "Resolve another identity's action",
    category: CATEGORY,
    expectedOutcome: `Rejected — identity B cannot ${crossAction} identity A's action`,
    actualOutcome: `${crossResult.status} ${JSON.stringify(crossResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected identity B's attempt to ${crossAction} identity A's action (${crossResult.status}).`
      : `AgentGate allowed identity B to ${crossAction} identity A's action — cross-identity authorization may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 4.3: Execute action on another identity's bond
// ---------------------------------------------------------------------------

async function attack4_3(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
  // Identity A (the client) locks a bond
  const bondResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    client.keys.publicKey, client.keys.privateKey,
    "/v1/bonds/lock",
    {
      identityId: client.identityId,
      amountCents: 100,
      currency: "USD",
      ttlSeconds: 300,
      reason: "auth-test-4.3",
    },
  );

  if (bondResult.status >= 300) {
    return {
      scenarioId: "4.3",
      scenarioName: "Execute on another identity's bond",
      category: CATEGORY,
      expectedOutcome: "Rejected — identity B cannot execute on identity A's bond",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  // Create identity B
  const keysB = freshKeypair();
  const identityBId = await registerIdentity(client.agentGateUrl, client.apiKey, keysB.publicKey, keysB.privateKey);

  // Identity B tries to execute an action on identity A's bond
  const exposureCents = Math.floor(100 / 1.2);
  const executeResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    keysB.publicKey, keysB.privateKey,
    "/v1/actions/execute",
    {
      identityId: identityBId,
      bondId,
      actionType: "auth-test",
      payload: { test: "4.3" },
      exposure_cents: exposureCents,
    },
  );

  const caught = executeResult.status >= 400;
  return {
    scenarioId: "4.3",
    scenarioName: "Execute on another identity's bond",
    category: CATEGORY,
    expectedOutcome: "Rejected — identity B cannot execute on identity A's bond",
    actualOutcome: `${executeResult.status} ${JSON.stringify(executeResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected identity B's attempt to execute on identity A's bond (${executeResult.status}).`
      : `AgentGate allowed identity B to execute on identity A's bond — bond-to-identity binding may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 4.4: Register duplicate public key
// ---------------------------------------------------------------------------

async function attack4_4(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
  // Try to register a new identity using the same public key that's already registered
  const result = await signedPost(
    client.agentGateUrl, client.apiKey,
    client.keys.publicKey, client.keys.privateKey,
    "/v1/identities",
    { publicKey: client.keys.publicKey },
  );

  const caught = result.status === 409;
  return {
    scenarioId: "4.4",
    scenarioName: "Register duplicate public key",
    category: CATEGORY,
    expectedOutcome: "Rejected with 409 — UNIQUE constraint on public key",
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the duplicate public key registration (409).`
      : `AgentGate returned ${result.status} for duplicate key registration — ${result.status < 300 ? "UNIQUE constraint may be missing" : "rejected but with unexpected status code"}.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 4.5: Trigger auto-ban then try to act
// ---------------------------------------------------------------------------

async function attack4_5(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const maliciousCount = (typeof params?.malicious_count === "number" ? params.malicious_count : 3);

  // Create a fresh identity for this test (don't pollute the shared client identity)
  const keys = freshKeypair();
  const identityId = await registerIdentity(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey);

  // Accumulate malicious resolutions to trigger auto-ban (threshold is 3)
  for (let i = 0; i < maliciousCount; i++) {
    // Lock a bond
    const bondResult = await signedPost(
      client.agentGateUrl, client.apiKey,
      keys.publicKey, keys.privateKey,
      "/v1/bonds/lock",
      {
        identityId,
        amountCents: 100,
        currency: "USD",
        ttlSeconds: 300,
        reason: `auth-test-4.5-${i}`,
      },
    );

    if (bondResult.status >= 300) {
      return {
        scenarioId: "4.5",
        scenarioName: "Trigger auto-ban then try to act",
        category: CATEGORY,
        expectedOutcome: `After ${maliciousCount} malicious resolutions, identity is banned`,
        actualOutcome: `Bond lock failed at iteration ${i}: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
        caught: bondResult.status >= 400 && i >= maliciousCount,
        details: i < maliciousCount
          ? `Bond lock failed at iteration ${i} before reaching ${maliciousCount} malicious resolutions — ${bondResult.status >= 400 ? "identity may already be banned" : "could not complete test"}.`
          : `Identity was banned after ${i} malicious resolutions.`,
      };
    }

    const bondId = bondResult.data.bondId as string;
    const exposureCents = Math.floor(100 / 1.2);

    // Execute an action
    const actionResult = await signedPost(
      client.agentGateUrl, client.apiKey,
      keys.publicKey, keys.privateKey,
      "/v1/actions/execute",
      {
        identityId,
        bondId,
        actionType: "auth-test",
        payload: { test: "4.5", iteration: i },
        exposure_cents: exposureCents,
      },
    );

    if (actionResult.status >= 300) {
      return {
        scenarioId: "4.5",
        scenarioName: "Trigger auto-ban then try to act",
        category: CATEGORY,
        expectedOutcome: `After ${maliciousCount} malicious resolutions, identity is banned`,
        actualOutcome: `Action execute failed at iteration ${i}: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
        caught: actionResult.status >= 400 && i >= maliciousCount,
        details: i < maliciousCount
          ? `Action execute failed at iteration ${i} — identity may already be banned.`
          : `Identity was banned after ${i} malicious resolutions.`,
      };
    }

    const actionId = actionResult.data.actionId as string;

    // Resolve as malicious to accumulate strikes
    await signedPost(
      client.agentGateUrl, client.apiKey,
      keys.publicKey, keys.privateKey,
      `/v1/actions/${actionId}/resolve`,
      { outcome: "malicious" },
    );
  }

  // Now try to lock a new bond — should be rejected if identity is banned
  const postBanResult = await signedPost(
    client.agentGateUrl, client.apiKey,
    keys.publicKey, keys.privateKey,
    "/v1/bonds/lock",
    {
      identityId,
      amountCents: 100,
      currency: "USD",
      ttlSeconds: 300,
      reason: "auth-test-4.5-post-ban",
    },
  );

  const caught = postBanResult.status >= 400;
  return {
    scenarioId: "4.5",
    scenarioName: "Trigger auto-ban then try to act",
    category: CATEGORY,
    expectedOutcome: `After ${maliciousCount} malicious resolutions, identity is banned and cannot lock bonds`,
    actualOutcome: `${postBanResult.status} ${JSON.stringify(postBanResult.data)}`,
    caught,
    details: caught
      ? `AgentGate banned the identity after ${maliciousCount} malicious resolutions and rejected the post-ban bond lock (${postBanResult.status}).`
      : `AgentGate accepted a bond lock after ${maliciousCount} malicious resolutions — auto-ban may not be enforced.`,
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
    execute: (client, params?) => attack4_1(client, params),
  },
  {
    id: "4.2",
    name: "Resolve another identity's action",
    category: CATEGORY,
    description: "Identity B tries to resolve an action belonging to identity A",
    expectedOutcome: "rejected — cross-identity resolution not allowed",
    execute: (client, params?) => attack4_2(client, params),
  },
  {
    id: "4.3",
    name: "Execute on another identity's bond",
    category: CATEGORY,
    description: "Identity B tries to execute an action on a bond locked by identity A",
    expectedOutcome: "rejected — bond-to-identity binding",
    execute: (client, params?) => attack4_3(client, params),
  },
  {
    id: "4.4",
    name: "Register duplicate public key",
    category: CATEGORY,
    description: "Register a new identity using a public key that's already registered",
    expectedOutcome: "rejected with 409 — UNIQUE constraint",
    execute: (client, params?) => attack4_4(client, params),
  },
  {
    id: "4.5",
    name: "Trigger auto-ban then try to act",
    category: CATEGORY,
    description: "Accumulate malicious resolutions to trigger auto-ban, then try to lock a bond",
    expectedOutcome: "banned identity cannot lock bonds",
    execute: (client, params?) => attack4_5(client, params),
  },
];
