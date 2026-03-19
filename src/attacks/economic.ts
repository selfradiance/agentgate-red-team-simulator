// Economic & reputation attack scenarios — tests AgentGate's resilience to economic manipulation

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Economic & Reputation";

// ---------------------------------------------------------------------------
// Helper — send a properly signed POST request
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

function freshKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  return {
    publicKey: Buffer.from(publicJwk.x!, "base64url").toString("base64"),
    privateKey: Buffer.from(privateJwk.d!, "base64url").toString("base64"),
  };
}

// ---------------------------------------------------------------------------
// Attack 11.1: Reputation pumping
// ---------------------------------------------------------------------------

async function attack11_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const pumpCount = (typeof params?.pump_count === "number" ? params.pump_count : 10);
  const bondAmountCents = (typeof params?.bond_amount_cents === "number" ? params.bond_amount_cents : 1);

  // Use a fresh identity so we start with a clean reputation
  const keys = freshKeypair();
  const idResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/identities", { publicKey: keys.publicKey });
  if (idResult.status >= 300) {
    return {
      scenarioId: "11.1",
      scenarioName: "Reputation pumping",
      category: CATEGORY,
      expectedOutcome: `Pump ${pumpCount} cheap successes then attempt high-value action`,
      actualOutcome: `Identity creation failed: ${idResult.status} ${JSON.stringify(idResult.data)}`,
      caught: false,
      details: "Could not complete test — identity creation did not succeed.",
    };
  }

  const identityId = idResult.data.identityId as string;

  // Pump: lock tiny bonds, execute, resolve as success
  let successCount = 0;
  for (let i = 0; i < pumpCount; i++) {
    const bondResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/bonds/lock", {
      identityId,
      amountCents: bondAmountCents,
      currency: "USD",
      ttlSeconds: 300,
      reason: `pump-${i}`,
    });
    if (bondResult.status >= 300) continue;

    const bondId = bondResult.data.bondId as string;
    const exposureCents = 1;

    const actionResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/actions/execute", {
      identityId,
      bondId,
      actionType: "reputation-pump",
      payload: { pump: i },
      exposure_cents: exposureCents,
    });
    if (actionResult.status >= 300) continue;

    const actionId = actionResult.data.actionId as string;
    const resolveResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, `/v1/actions/${actionId}/resolve`, {
      outcome: "success",
    });
    if (resolveResult.status < 300) successCount++;
  }

  // Now attempt a high-value action with the pumped reputation
  const highBondResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/bonds/lock", {
    identityId,
    amountCents: 1000,
    currency: "USD",
    ttlSeconds: 300,
    reason: "post-pump-high-value",
  });

  const highBondAccepted = highBondResult.status < 300;

  return {
    scenarioId: "11.1",
    scenarioName: "Reputation pumping",
    category: CATEGORY,
    expectedOutcome: `Pump ${pumpCount} cheap successes (${bondAmountCents}¢ each), then attempt 1000¢ bond`,
    actualOutcome: `${successCount} pumps succeeded. High-value bond: ${highBondResult.status} ${JSON.stringify(highBondResult.data)}`,
    caught: true,
    details: highBondAccepted
      ? `After ${successCount} cheap successes (${bondAmountCents}¢ each), a 1000¢ bond was accepted. Reputation pumping is possible — AgentGate doesn't weight bond amounts in reputation scoring.`
      : `After ${successCount} cheap successes, the 1000¢ bond was rejected (${highBondResult.status}). AgentGate may have reputation-based bond limits.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 11.2: Sybil campaign chain
// ---------------------------------------------------------------------------

async function attack11_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const identityCount = (typeof params?.identity_count === "number" ? params.identity_count : 5);
  const actionsPerIdentity = (typeof params?.actions_per_identity === "number" ? params.actions_per_identity : 5);

  // Create N fresh identities
  const identities: { publicKey: string; privateKey: string; identityId: string }[] = [];

  for (let i = 0; i < identityCount; i++) {
    const keys = freshKeypair();
    const idResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/identities", { publicKey: keys.publicKey });
    if (idResult.status >= 300) continue;
    identities.push({ ...keys, identityId: idResult.data.identityId as string });
  }

  if (identities.length === 0) {
    return {
      scenarioId: "11.2",
      scenarioName: "Sybil campaign chain",
      category: CATEGORY,
      expectedOutcome: `${identityCount} identities × ${actionsPerIdentity} actions each`,
      actualOutcome: "No identities could be created",
      caught: false,
      details: "Could not complete test — identity creation failed for all attempts.",
    };
  }

  // Each identity locks a bond and executes actions — staying under per-identity rate limit
  let totalActions = 0;
  let totalRateLimited = 0;

  for (const id of identities) {
    const bondResult = await signedPost(client.agentGateUrl, client.apiKey, id.publicKey, id.privateKey, "/v1/bonds/lock", {
      identityId: id.identityId,
      amountCents: 500,
      currency: "USD",
      ttlSeconds: 300,
      reason: "sybil-campaign-11.2",
    });
    if (bondResult.status >= 300) continue;

    const bondId = bondResult.data.bondId as string;

    for (let j = 0; j < actionsPerIdentity; j++) {
      const result = await signedPost(client.agentGateUrl, client.apiKey, id.publicKey, id.privateKey, "/v1/actions/execute", {
        identityId: id.identityId,
        bondId,
        actionType: "sybil-campaign",
        payload: { identity: id.identityId.slice(0, 8), action: j },
        exposure_cents: 10,
      });
      if (result.status < 300) totalActions++;
      if (result.status === 429) totalRateLimited++;
    }
  }

  const totalAttempted = identities.length * actionsPerIdentity;
  return {
    scenarioId: "11.2",
    scenarioName: "Sybil campaign chain",
    category: CATEGORY,
    expectedOutcome: `${identities.length} identities × ${actionsPerIdentity} actions = ${totalAttempted} total`,
    actualOutcome: `${totalActions} actions succeeded, ${totalRateLimited} rate-limited, across ${identities.length} Sybil identities`,
    caught: true,
    details: totalRateLimited > 0
      ? `Some form of aggregate or cross-identity rate limiting detected (${totalRateLimited} rate-limited).`
      : `All ${totalActions} actions succeeded across ${identities.length} Sybil identities — rate limiting is per-identity only. Sybil campaigns can multiply throughput linearly. This is a known design limitation.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 11.3: Resource exhaustion via long-TTL open actions
// ---------------------------------------------------------------------------

async function attack11_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const identityCount = (typeof params?.identity_count === "number" ? params.identity_count : 5);
  const ttlSeconds = (typeof params?.ttl_seconds === "number" ? params.ttl_seconds : 3600);

  // Create identities, each locks a bond with long TTL, executes, never resolves
  let openActions = 0;
  let failedSetups = 0;

  for (let i = 0; i < identityCount; i++) {
    const keys = freshKeypair();
    const idResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/identities", { publicKey: keys.publicKey });
    if (idResult.status >= 300) { failedSetups++; continue; }

    const identityId = idResult.data.identityId as string;

    const bondResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/bonds/lock", {
      identityId,
      amountCents: 100,
      currency: "USD",
      ttlSeconds,
      reason: "resource-exhaustion-11.3",
    });
    if (bondResult.status >= 300) { failedSetups++; continue; }

    const bondId = bondResult.data.bondId as string;
    const exposureCents = Math.floor(100 / 1.2);

    const actionResult = await signedPost(client.agentGateUrl, client.apiKey, keys.publicKey, keys.privateKey, "/v1/actions/execute", {
      identityId,
      bondId,
      actionType: "resource-exhaustion",
      payload: { identity: i, purpose: "clog-dashboard" },
      exposure_cents: exposureCents,
    });

    if (actionResult.status < 300) openActions++;
    else failedSetups++;
    // Intentionally never resolve — actions sit open until sweeper slashes after TTL
  }

  return {
    scenarioId: "11.3",
    scenarioName: "Resource exhaustion via long-TTL open actions",
    category: CATEGORY,
    expectedOutcome: `${identityCount} identities create open actions with ${ttlSeconds}s TTL — never resolved`,
    actualOutcome: `${openActions} open actions created (${failedSetups} setup failures), TTL=${ttlSeconds}s`,
    caught: true,
    details: openActions > 0
      ? `${openActions} actions left intentionally open with ${ttlSeconds}s TTL. These will sit in the dashboard and DB until the sweeper slashes them. At scale, this could clog monitoring and slow queries.`
      : `No open actions were created — all setups failed. Cannot test resource exhaustion.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const economicAttacks: AttackScenario[] = [
  {
    id: "11.1",
    name: "Reputation pumping",
    category: CATEGORY,
    description: "Pump reputation with cheap successes, then attempt high-value action",
    expectedOutcome: "probing — does pumped reputation unlock higher bond limits?",
    execute: (client, params?) => attack11_1(client, params),
  },
  {
    id: "11.2",
    name: "Sybil campaign chain",
    category: CATEGORY,
    description: "Create many identities, distribute execute pressure across all to bypass rate limits",
    expectedOutcome: "probing — Sybil multiplies throughput linearly",
    execute: (client, params?) => attack11_2(client, params),
  },
  {
    id: "11.3",
    name: "Resource exhaustion via long-TTL open actions",
    category: CATEGORY,
    description: "Create identities, lock bonds, execute actions, never resolve — clog dashboard and DB",
    expectedOutcome: "probing — open actions accumulate until sweeper slashes",
    execute: (client, params?) => attack11_3(client, params),
  },
];
