// Timing & race condition attack scenarios — tests AgentGate's behavior under concurrent and time-sensitive conditions

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Timing & Race Conditions";

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

function signedPostClient(client: AttackClient, apiPath: string, body: unknown) {
  return signedPost(client.agentGateUrl, client.apiKey, client.keys.publicKey, client.keys.privateKey, apiPath, body);
}

// ---------------------------------------------------------------------------
// Attack 7.1: Resolve just before sweeper auto-slashes
// ---------------------------------------------------------------------------

async function attack7_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const ttlSeconds = (typeof params?.ttl_seconds === "number" ? params.ttl_seconds : 5);
  const resolveAtSeconds = (typeof params?.resolve_at_seconds === "number" ? params.resolve_at_seconds : ttlSeconds - 1);

  // Create a fresh identity to avoid rate-limit interference
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const freshPub = Buffer.from(publicJwk.x!, "base64url").toString("base64");
  const freshPriv = Buffer.from(privateJwk.d!, "base64url").toString("base64");

  const idResult = await signedPost(client.agentGateUrl, client.apiKey, freshPub, freshPriv, "/v1/identities", { publicKey: freshPub });
  if (idResult.status >= 300) {
    return {
      scenarioId: "7.1",
      scenarioName: "Resolve just before sweeper auto-slashes",
      category: CATEGORY,
      expectedOutcome: `Resolve at ${resolveAtSeconds}s on ${ttlSeconds}s TTL bond`,
      actualOutcome: `Identity creation failed: ${idResult.status} ${JSON.stringify(idResult.data)}`,
      caught: false,
      details: "Could not complete test — fresh identity creation did not succeed.",
    };
  }

  const freshId = idResult.data.identityId as string;

  // Lock a bond with short TTL using fresh identity
  const bondResult = await signedPost(client.agentGateUrl, client.apiKey, freshPub, freshPriv, "/v1/bonds/lock", {
    identityId: freshId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds,
    reason: "timing-test-7.1",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "7.1",
      scenarioName: "Resolve just before sweeper auto-slashes",
      category: CATEGORY,
      expectedOutcome: `Resolve at ${resolveAtSeconds}s on ${ttlSeconds}s TTL bond`,
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  // Execute an action using fresh identity
  const actionResult = await signedPost(client.agentGateUrl, client.apiKey, freshPub, freshPriv, "/v1/actions/execute", {
    identityId: freshId,
    bondId,
    actionType: "timing-test",
    payload: { test: "7.1" },
    exposure_cents: exposureCents,
  });

  if (actionResult.status >= 300) {
    return {
      scenarioId: "7.1",
      scenarioName: "Resolve just before sweeper auto-slashes",
      category: CATEGORY,
      expectedOutcome: `Resolve at ${resolveAtSeconds}s on ${ttlSeconds}s TTL bond`,
      actualOutcome: `Action execute failed: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
      caught: false,
      details: "Could not complete test — action execute did not succeed.",
    };
  }

  const actionId = actionResult.data.actionId as string;

  // Wait until just before TTL expiry
  await new Promise((resolve) => setTimeout(resolve, resolveAtSeconds * 1000));

  // Try to resolve — racing the sweeper, using fresh identity
  const resolveResult = await signedPost(client.agentGateUrl, client.apiKey, freshPub, freshPriv, `/v1/actions/${actionId}/resolve`, {
    outcome: "success",
  });

  // Either outcome is informative for the strategist
  const resolved = resolveResult.status < 300;
  return {
    scenarioId: "7.1",
    scenarioName: "Resolve just before sweeper auto-slashes",
    category: CATEGORY,
    expectedOutcome: `Resolve at ${resolveAtSeconds}s on ${ttlSeconds}s TTL — race with sweeper`,
    actualOutcome: `${resolveResult.status} ${JSON.stringify(resolveResult.data)}`,
    caught: true,
    details: resolved
      ? `Resolution succeeded at ${resolveAtSeconds}s into ${ttlSeconds}s TTL — agent beat the sweeper.`
      : `Resolution failed at ${resolveAtSeconds}s into ${ttlSeconds}s TTL (${resolveResult.status}) — sweeper may have already slashed, or bond expired.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 7.2: Parallel resolve attempts
// ---------------------------------------------------------------------------

async function attack7_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const parallelCount = (typeof params?.parallel_count === "number" ? params.parallel_count : 5);
  const delayBetweenMs = (typeof params?.delay_between_ms === "number" ? params.delay_between_ms : 0);

  // Use a fresh identity to avoid rate limit interference from earlier attacks
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const pub = Buffer.from(publicJwk.x!, "base64url").toString("base64");
  const priv = Buffer.from(privateJwk.d!, "base64url").toString("base64");

  const idResult = await signedPost(client.agentGateUrl, client.apiKey, pub, priv, "/v1/identities", { publicKey: pub });
  if (idResult.status >= 300) {
    return {
      scenarioId: "7.2",
      scenarioName: "Parallel resolve attempts",
      category: CATEGORY,
      expectedOutcome: "Only one resolve succeeds, rest rejected",
      actualOutcome: `Identity creation failed: ${idResult.status} ${JSON.stringify(idResult.data)}`,
      caught: false,
      details: "Could not complete test — identity creation did not succeed.",
    };
  }

  const freshIdentityId = idResult.data.identityId as string;

  // Lock a bond with the fresh identity
  const bondResult = await signedPost(client.agentGateUrl, client.apiKey, pub, priv, "/v1/bonds/lock", {
    identityId: freshIdentityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "timing-test-7.2",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "7.2",
      scenarioName: "Parallel resolve attempts",
      category: CATEGORY,
      expectedOutcome: "Only one resolve succeeds, rest rejected",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  const actionResult = await signedPost(client.agentGateUrl, client.apiKey, pub, priv, "/v1/actions/execute", {
    identityId: freshIdentityId,
    bondId,
    actionType: "timing-test",
    payload: { test: "7.2" },
    exposure_cents: exposureCents,
  });

  if (actionResult.status >= 300) {
    return {
      scenarioId: "7.2",
      scenarioName: "Parallel resolve attempts",
      category: CATEGORY,
      expectedOutcome: "Only one resolve succeeds, rest rejected",
      actualOutcome: `Action execute failed: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
      caught: false,
      details: "Could not complete test — action execute did not succeed.",
    };
  }

  const actionId = actionResult.data.actionId as string;

  // Fire parallel resolve attempts using the fresh identity's keys
  const resolvePromises: Promise<{ status: number; data: Record<string, unknown> }>[] = [];
  for (let i = 0; i < parallelCount; i++) {
    if (delayBetweenMs > 0 && i > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayBetweenMs));
    }
    resolvePromises.push(
      signedPost(client.agentGateUrl, client.apiKey, pub, priv, `/v1/actions/${actionId}/resolve`, {
        outcome: i % 2 === 0 ? "success" : "failed",
      }),
    );
  }

  const results = await Promise.all(resolvePromises);
  const succeeded = results.filter((r) => r.status < 300).length;
  const rejected = results.filter((r) => r.status >= 400).length;

  // Exactly one should succeed, rest should be rejected
  const caught = succeeded <= 1;
  return {
    scenarioId: "7.2",
    scenarioName: "Parallel resolve attempts",
    category: CATEGORY,
    expectedOutcome: `${parallelCount} parallel resolves — only 1 should succeed`,
    actualOutcome: `${succeeded} succeeded, ${rejected} rejected out of ${parallelCount} parallel attempts`,
    caught,
    details: caught
      ? `AgentGate correctly allowed only ${succeeded} resolution(s) out of ${parallelCount} parallel attempts — WHERE status='open' guard is working.`
      : `AgentGate allowed ${succeeded} resolutions out of ${parallelCount} parallel attempts — race condition in resolution handling.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 7.3: Rapid identity creation (Sybil flood)
// ---------------------------------------------------------------------------

async function attack7_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const identityCount = (typeof params?.identity_count === "number" ? params.identity_count : 20);

  const results: { index: number; status: number }[] = [];

  for (let i = 0; i < identityCount; i++) {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const privateJwk = privateKey.export({ format: "jwk" });
    const pub = Buffer.from(publicJwk.x!, "base64url").toString("base64");
    const priv = Buffer.from(privateJwk.d!, "base64url").toString("base64");

    const result = await signedPost(
      client.agentGateUrl, client.apiKey,
      pub, priv,
      "/v1/identities",
      { publicKey: pub },
    );
    results.push({ index: i + 1, status: result.status });
  }

  const succeeded = results.filter((r) => r.status < 300).length;
  const rateLimited = results.filter((r) => r.status === 429).length;
  const otherFailures = results.filter((r) => r.status >= 400 && r.status !== 429).length;

  // If all succeeded, identity creation is not rate-limited (known design limitation)
  return {
    scenarioId: "7.3",
    scenarioName: "Rapid identity creation (Sybil flood)",
    category: CATEGORY,
    expectedOutcome: `Probing whether ${identityCount} rapid identity creations are rate-limited`,
    actualOutcome: `${succeeded} succeeded, ${rateLimited} rate-limited, ${otherFailures} other failures`,
    caught: true,
    details: rateLimited > 0
      ? `AgentGate rate-limited identity creation after ${succeeded} successes (${rateLimited} rejected with 429).`
      : `All ${succeeded} identity creations succeeded — identity creation is not rate-limited. This is a known Sybil vector (no PoW on identity creation).`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const timingAttacks: AttackScenario[] = [
  {
    id: "7.1",
    name: "Resolve just before sweeper auto-slashes",
    category: CATEGORY,
    description: "Race the sweeper — resolve an action just before bond TTL expires",
    expectedOutcome: "probing — race between agent and sweeper",
    execute: (client, params?) => attack7_1(client, params),
  },
  {
    id: "7.2",
    name: "Parallel resolve attempts",
    category: CATEGORY,
    description: "Fire multiple simultaneous resolve requests on the same action",
    expectedOutcome: "only one resolve succeeds",
    execute: (client, params?) => attack7_2(client, params),
  },
  {
    id: "7.3",
    name: "Rapid identity creation (Sybil flood)",
    category: CATEGORY,
    description: "Create many identities in rapid succession to test for rate limiting",
    expectedOutcome: "probing — is identity creation rate-limited?",
    execute: (client, params?) => attack7_3(client, params),
  },
];
