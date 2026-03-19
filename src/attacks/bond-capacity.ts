// Bond capacity attack scenarios — tests whether AgentGate enforces bond limits correctly

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Bond Capacity";

// ---------------------------------------------------------------------------
// Helper — send a properly signed POST request to AgentGate
// ---------------------------------------------------------------------------

async function signedPost(
  client: AttackClient,
  apiPath: string,
  body: unknown,
): Promise<{ status: number; data: Record<string, unknown> }> {
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

  return { status: response.status, data };
}

// ---------------------------------------------------------------------------
// Attack 2.1: Over-commit exposure
// ---------------------------------------------------------------------------

async function attack2_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const bondAmountCents = (typeof params?.bond_amount_cents === "number" ? params.bond_amount_cents : 100);
  const exposureCents = (typeof params?.exposure_cents === "number" ? params.exposure_cents : 100);

  // Lock a bond
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: bondAmountCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.1",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.1",
      scenarioName: "Over-commit exposure",
      category: CATEGORY,
      expectedOutcome: "Action rejected with INSUFFICIENT_BOND_CAPACITY",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  // Try to execute with exposure that exceeds bond capacity after 1.2x multiplier
  const actionResult = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.1" },
    exposure_cents: exposureCents,
  });

  const caught = actionResult.status >= 400;
  return {
    scenarioId: "2.1",
    scenarioName: "Over-commit exposure",
    category: CATEGORY,
    expectedOutcome: `Rejected with INSUFFICIENT_BOND_CAPACITY (exposure=${exposureCents} on ${bondAmountCents}-cent bond)`,
    actualOutcome: `${actionResult.status} ${JSON.stringify(actionResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the over-committed exposure (${actionResult.status}).`
      : `AgentGate accepted exposure_cents=${exposureCents} on a ${bondAmountCents}-cent bond — the 1.2x capacity multiplier may not be enforced.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 2.2: Double-resolve
// ---------------------------------------------------------------------------

async function attack2_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const secondOutcome = (typeof params?.second_outcome === "string" ? params.second_outcome as "success" | "failed" : "failed");
  // Lock a bond
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.2",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.2",
      scenarioName: "Double-resolve",
      category: CATEGORY,
      expectedOutcome: "Second resolution rejected",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  // Execute an action with safe exposure (within capacity)
  const exposureCents = Math.floor(100 / 1.2);
  const actionResult = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.2" },
    exposure_cents: exposureCents,
  });

  if (actionResult.status >= 300) {
    return {
      scenarioId: "2.2",
      scenarioName: "Double-resolve",
      category: CATEGORY,
      expectedOutcome: "Second resolution rejected",
      actualOutcome: `Action execute failed: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
      caught: false,
      details: "Could not complete test — action execute did not succeed.",
    };
  }

  const actionId = actionResult.data.actionId as string;

  // First resolve — should succeed
  const firstResolve = await signedPost(client, `/v1/actions/${actionId}/resolve`, {
    outcome: "success",
  });

  if (firstResolve.status >= 300) {
    return {
      scenarioId: "2.2",
      scenarioName: "Double-resolve",
      category: CATEGORY,
      expectedOutcome: "Second resolution rejected",
      actualOutcome: `First resolve failed: ${firstResolve.status} ${JSON.stringify(firstResolve.data)}`,
      caught: false,
      details: "Could not complete test — first resolve did not succeed.",
    };
  }

  // Second resolve — should be rejected
  const secondResolve = await signedPost(client, `/v1/actions/${actionId}/resolve`, {
    outcome: secondOutcome,
  });

  const caught = secondResolve.status >= 400;
  return {
    scenarioId: "2.2",
    scenarioName: "Double-resolve",
    category: CATEGORY,
    expectedOutcome: "Second resolution rejected — action already resolved",
    actualOutcome: `${secondResolve.status} ${JSON.stringify(secondResolve.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the double-resolve (${secondResolve.status}).`
      : `AgentGate accepted a second resolution on an already-resolved action — double-resolve protection may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 2.3: Act on expired bond
// ---------------------------------------------------------------------------

async function attack2_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const ttlSeconds = (typeof params?.ttl_seconds === "number" ? params.ttl_seconds : 5);
  const waitMs = (typeof params?.wait_ms === "number" ? params.wait_ms : (ttlSeconds + 2) * 1000);

  // Lock a bond with a short TTL
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds,
    reason: "bond-capacity-test-2.3",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.3",
      scenarioName: "Act on expired bond",
      category: CATEGORY,
      expectedOutcome: "Action rejected — bond has expired",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  // Wait for the bond to expire
  await new Promise((resolve) => setTimeout(resolve, waitMs));

  // Try to execute against the expired bond
  const exposureCents = Math.floor(100 / 1.2);
  const actionResult = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.3" },
    exposure_cents: exposureCents,
  });

  const caught = actionResult.status >= 400;
  return {
    scenarioId: "2.3",
    scenarioName: "Act on expired bond",
    category: CATEGORY,
    expectedOutcome: `Rejected — bond has expired after ${ttlSeconds}s TTL`,
    actualOutcome: `${actionResult.status} ${JSON.stringify(actionResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the action on an expired bond (${actionResult.status}).`
      : `AgentGate accepted an action on a bond that expired ${Math.round(waitMs / 1000)}s ago — TTL enforcement may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const bondCapacityAttacks: AttackScenario[] = [
  {
    id: "2.1",
    name: "Over-commit exposure",
    category: CATEGORY,
    description: "Execute an action with exposure exceeding bond capacity (1.2x multiplier)",
    expectedOutcome: "rejected with INSUFFICIENT_BOND_CAPACITY",
    execute: (client, params?) => attack2_1(client, params),
  },
  {
    id: "2.2",
    name: "Double-resolve",
    category: CATEGORY,
    description: "Resolve an already-resolved action a second time",
    expectedOutcome: "rejected — action already resolved",
    execute: (client, params?) => attack2_2(client, params),
  },
  {
    id: "2.3",
    name: "Act on expired bond",
    category: CATEGORY,
    description: "Execute an action against a bond after its TTL has expired",
    expectedOutcome: "rejected — bond expired",
    execute: (client, params?) => attack2_3(client, params),
  },
];
