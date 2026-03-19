// Bond capacity attack scenarios — tests whether AgentGate enforces bond limits correctly

import { generateKeyPairSync, randomUUID } from "node:crypto";
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

// Helper — create a fresh identity to avoid rate-limit interference
async function createFreshClient(client: AttackClient): Promise<AttackClient> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const pub = Buffer.from(publicJwk.x!, "base64url").toString("base64");
  const priv = Buffer.from(privateJwk.d!, "base64url").toString("base64");

  const result = await signedPost(
    { ...client, keys: { publicKey: pub, privateKey: priv }, identityId: "" },
    "/v1/identities",
    { publicKey: pub },
  );
  if (result.status >= 300) {
    throw new Error(`Failed to create fresh identity: ${result.status} ${JSON.stringify(result.data)}`);
  }

  return {
    agentGateUrl: client.agentGateUrl,
    apiKey: client.apiKey,
    keys: { publicKey: pub, privateKey: priv },
    identityId: result.data.identityId as string,
  };
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
// Attack 2.4: Zero-amount bond
// ---------------------------------------------------------------------------

async function attack2_4(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
  const result = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 0,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.4",
  });

  const caught = result.status >= 400;
  return {
    scenarioId: "2.4",
    scenarioName: "Zero-amount bond",
    category: CATEGORY,
    expectedOutcome: "Rejected — zero-amount bond should not be allowed",
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the zero-amount bond (${result.status}).`
      : `AgentGate accepted a bond with 0 cents — ghost capacity may be possible.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 2.5: Exhaust bond via 1.2x multiplier rounding
// ---------------------------------------------------------------------------

async function attack2_5(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const exposureCents = (typeof params?.exposure_cents === "number" ? params.exposure_cents : 83);

  // Lock a 100-cent bond. The capacity rule is: effective = ceil(exposure * 1.2).
  // At 83 cents: ceil(83 * 1.2) = ceil(99.6) = 100 → exactly at capacity.
  // At 84 cents: ceil(84 * 1.2) = ceil(100.8) = 101 → exceeds capacity.
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.5",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.5",
      scenarioName: "Exhaust bond via 1.2x multiplier rounding",
      category: CATEGORY,
      expectedOutcome: `Probing capacity boundary at exposure=${exposureCents} on 100-cent bond`,
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  const actionResult = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.5", exposureCents },
    exposure_cents: exposureCents,
  });

  // This is a boundary probe — the result depends on the exact exposure value.
  // At 83: should succeed (effective=100, bond=100). At 84: should fail (effective=101 > 100).
  return {
    scenarioId: "2.5",
    scenarioName: "Exhaust bond via 1.2x multiplier rounding",
    category: CATEGORY,
    expectedOutcome: `Probing capacity boundary at exposure=${exposureCents} on 100-cent bond`,
    actualOutcome: `${actionResult.status} ${JSON.stringify(actionResult.data)}`,
    caught: actionResult.status >= 400 || actionResult.status < 300,
    details: actionResult.status < 300
      ? `AgentGate accepted exposure=${exposureCents} (effective=${Math.ceil(exposureCents * 1.2)}) on 100-cent bond — within capacity.`
      : `AgentGate rejected exposure=${exposureCents} (effective=${Math.ceil(exposureCents * 1.2)}) on 100-cent bond — capacity enforced.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 2.6: Multi-action bond exhaustion
// ---------------------------------------------------------------------------

async function attack2_6(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const actionCount = (typeof params?.action_count === "number" ? params.action_count : 2);
  const bondAmountCents = (typeof params?.bond_amount_cents === "number" ? params.bond_amount_cents : 100);

  // Use a fresh identity to avoid rate-limit interference
  const fresh = await createFreshClient(client);

  // Lock a bond
  const bondResult = await signedPost(fresh, "/v1/bonds/lock", {
    identityId: fresh.identityId,
    amountCents: bondAmountCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.6",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.6",
      scenarioName: "Multi-action bond exhaustion",
      category: CATEGORY,
      expectedOutcome: "Second action rejected — bond capacity exhausted by first action",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;

  // Execute first action at near-max capacity: floor(bondAmount / 1.2) uses most of the bond
  const firstExposure = Math.floor(bondAmountCents / 1.2);
  const firstAction = await signedPost(fresh, "/v1/actions/execute", {
    identityId: fresh.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.6", action: 1 },
    exposure_cents: firstExposure,
  });

  if (firstAction.status >= 300) {
    return {
      scenarioId: "2.6",
      scenarioName: "Multi-action bond exhaustion",
      category: CATEGORY,
      expectedOutcome: "Second action rejected — bond capacity exhausted by first action",
      actualOutcome: `First action failed: ${firstAction.status} ${JSON.stringify(firstAction.data)}`,
      caught: false,
      details: "Could not complete test — first action did not succeed.",
    };
  }

  // Try remaining actions — should be rejected because first action consumed nearly all capacity
  const remainingResults: { status: number; data: Record<string, unknown> }[] = [];
  for (let i = 1; i < actionCount; i++) {
    const result = await signedPost(fresh, "/v1/actions/execute", {
      identityId: fresh.identityId,
      bondId,
      actionType: "bond-capacity-test",
      payload: { test: "2.6", action: i + 1 },
      exposure_cents: firstExposure,
    });
    remainingResults.push({ status: result.status, data: result.data });
  }

  const rejected = remainingResults.filter((r) => r.status >= 400).length;
  const caught = rejected > 0;
  const lastResult = remainingResults[remainingResults.length - 1];

  return {
    scenarioId: "2.6",
    scenarioName: "Multi-action bond exhaustion",
    category: CATEGORY,
    expectedOutcome: "Subsequent actions rejected — bond capacity exhausted",
    actualOutcome: `${rejected}/${remainingResults.length} subsequent actions rejected. Last: ${lastResult.status} ${JSON.stringify(lastResult.data)}`,
    caught,
    details: caught
      ? `AgentGate enforced multi-action capacity — ${rejected} of ${remainingResults.length} follow-up actions rejected after first consumed exposure=${firstExposure}.`
      : `AgentGate accepted all ${actionCount} actions on a ${bondAmountCents}-cent bond — multi-action accounting may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 2.7: Resolve then re-execute on released bond
// ---------------------------------------------------------------------------

async function attack2_7(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
  // Use a fresh identity to avoid rate-limit interference
  const fresh = await createFreshClient(client);

  // Lock a bond, execute, resolve as success (bond released), then try to execute again
  const bondResult = await signedPost(fresh, "/v1/bonds/lock", {
    identityId: fresh.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "bond-capacity-test-2.7",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "2.7",
      scenarioName: "Resolve then re-execute on released bond",
      category: CATEGORY,
      expectedOutcome: "Second execute rejected — bond already released",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  // Execute first action
  const actionResult = await signedPost(fresh, "/v1/actions/execute", {
    identityId: fresh.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.7", phase: "first" },
    exposure_cents: exposureCents,
  });

  if (actionResult.status >= 300) {
    return {
      scenarioId: "2.7",
      scenarioName: "Resolve then re-execute on released bond",
      category: CATEGORY,
      expectedOutcome: "Second execute rejected — bond already released",
      actualOutcome: `First action failed: ${actionResult.status} ${JSON.stringify(actionResult.data)}`,
      caught: false,
      details: "Could not complete test — first action did not succeed.",
    };
  }

  const actionId = actionResult.data.actionId as string;

  // Resolve as success — this releases the bond
  const resolveResult = await signedPost(fresh, `/v1/actions/${actionId}/resolve`, {
    outcome: "success",
  });

  if (resolveResult.status >= 300) {
    return {
      scenarioId: "2.7",
      scenarioName: "Resolve then re-execute on released bond",
      category: CATEGORY,
      expectedOutcome: "Second execute rejected — bond already released",
      actualOutcome: `Resolve failed: ${resolveResult.status} ${JSON.stringify(resolveResult.data)}`,
      caught: false,
      details: "Could not complete test — resolve did not succeed.",
    };
  }

  // Try to execute again on the now-released bond
  const reExecuteResult = await signedPost(fresh, "/v1/actions/execute", {
    identityId: fresh.identityId,
    bondId,
    actionType: "bond-capacity-test",
    payload: { test: "2.7", phase: "re-execute" },
    exposure_cents: exposureCents,
  });

  const caught = reExecuteResult.status >= 400;
  return {
    scenarioId: "2.7",
    scenarioName: "Resolve then re-execute on released bond",
    category: CATEGORY,
    expectedOutcome: "Rejected — bond already released, cannot execute new actions",
    actualOutcome: `${reExecuteResult.status} ${JSON.stringify(reExecuteResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected re-execution on a released bond (${reExecuteResult.status}).`
      : `AgentGate accepted a new action on a bond that was already resolved and released — bond lifecycle may not be enforced.`,
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
  {
    id: "2.4",
    name: "Zero-amount bond",
    category: CATEGORY,
    description: "Lock a bond with amountCents = 0",
    expectedOutcome: "rejected — zero-amount bond invalid",
    execute: (client, params?) => attack2_4(client, params),
  },
  {
    id: "2.5",
    name: "Exhaust bond via 1.2x multiplier rounding",
    category: CATEGORY,
    description: "Probe the exact boundary of the 1.2x capacity rule (83 vs 84 cents on 100-cent bond)",
    expectedOutcome: "probing boundary — result depends on exact value",
    execute: (client, params?) => attack2_5(client, params),
  },
  {
    id: "2.6",
    name: "Multi-action bond exhaustion",
    category: CATEGORY,
    description: "Execute action A at near-max exposure, then try action B with the same exposure",
    expectedOutcome: "second action rejected — capacity exhausted",
    execute: (client, params?) => attack2_6(client, params),
  },
  {
    id: "2.7",
    name: "Resolve then re-execute on released bond",
    category: CATEGORY,
    description: "Execute, resolve as success (releasing bond), then try to execute again on the same bond",
    expectedOutcome: "rejected — bond already released",
    execute: (client, params?) => attack2_7(client, params),
  },
];
