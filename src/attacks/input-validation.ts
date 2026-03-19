// Input validation attack scenarios — tests whether AgentGate rejects malformed or extreme inputs

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Input Validation";

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
// Attack 5.1: Oversized payload
// ---------------------------------------------------------------------------

async function attack5_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const payloadBytes = (typeof params?.payload_bytes === "number" ? params.payload_bytes : 5000);

  // Lock a bond first
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "input-validation-test-5.1",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "5.1",
      scenarioName: "Oversized payload",
      category: CATEGORY,
      expectedOutcome: "Rejected with 400 PAYLOAD_TOO_LARGE",
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  const oversizedPayload = "X".repeat(payloadBytes);

  const actionResult = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "input-validation-test",
    payload: { data: oversizedPayload },
    exposure_cents: exposureCents,
  });

  const caught = actionResult.status >= 400;
  return {
    scenarioId: "5.1",
    scenarioName: "Oversized payload",
    category: CATEGORY,
    expectedOutcome: `Rejected with 400 PAYLOAD_TOO_LARGE (${payloadBytes} bytes)`,
    actualOutcome: `${actionResult.status} ${JSON.stringify(actionResult.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the ${payloadBytes}-byte payload (${actionResult.status}).`
      : `AgentGate accepted a ${payloadBytes}-byte payload — payload size validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 5.2: TTL exceeding cap
// ---------------------------------------------------------------------------

async function attack5_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const ttlSeconds = (typeof params?.ttl_seconds === "number" ? params.ttl_seconds : 100000);

  const result = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds,
    reason: "input-validation-test-5.2",
  });

  const caught = result.status >= 400;
  return {
    scenarioId: "5.2",
    scenarioName: "TTL exceeding cap",
    category: CATEGORY,
    expectedOutcome: `Rejected with 400 TTL_TOO_LONG (ttl=${ttlSeconds}s)`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected TTL of ${ttlSeconds}s (${result.status}).`
      : `AgentGate accepted a TTL of ${ttlSeconds} seconds — TTL cap validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 5.3: Negative bond amount
// ---------------------------------------------------------------------------

async function attack5_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const amountCents = (typeof params?.amount_cents === "number" ? params.amount_cents : -100);

  const result = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "input-validation-test-5.3",
  });

  const caught = result.status >= 400;
  return {
    scenarioId: "5.3",
    scenarioName: "Negative bond amount",
    category: CATEGORY,
    expectedOutcome: `Rejected — ${amountCents} cents is invalid`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the bond amount of ${amountCents} cents (${result.status}).`
      : `AgentGate accepted a bond with ${amountCents} cents — amount validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 5.4: Type coercion — string where number expected
// ---------------------------------------------------------------------------

async function attack5_4(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const coercionValue = (typeof params?.coercion_value === "string" ? params.coercion_value : "abc");

  // Send a string where amountCents (number) is expected.
  // AgentGate uses z.coerce.number() — test how it handles non-numeric strings.
  const result = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: coercionValue as unknown,
    currency: "USD",
    ttlSeconds: 300,
    reason: "input-validation-test-5.4",
  });

  const caught = result.status >= 400;
  return {
    scenarioId: "5.4",
    scenarioName: "Type coercion — string where number expected",
    category: CATEGORY,
    expectedOutcome: `Rejected — "${coercionValue}" is not a valid number for amountCents`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught,
    details: caught
      ? `AgentGate rejected coercion value "${coercionValue}" for amountCents (${result.status}).`
      : `AgentGate accepted "${coercionValue}" as amountCents — type coercion may convert unexpected strings to numbers.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 5.5: String fields at max-length boundary
// ---------------------------------------------------------------------------

async function attack5_5(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const field = (typeof params?.field === "string" ? params.field : "actionType");
  const length = (typeof params?.length === "number" ? params.length : 129);

  // AgentGate max-lengths: actionType(128), agentName(64), identityId(64), bondId(64)
  const oversizedValue = "A".repeat(length);

  // We need a bond to test actionType length
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "input-validation-test-5.5",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "5.5",
      scenarioName: "String fields at max-length boundary",
      category: CATEGORY,
      expectedOutcome: `Rejected — ${field} at ${length} chars exceeds max length`,
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  // Build the request with the oversized field
  const actionBody: Record<string, unknown> = {
    identityId: client.identityId,
    bondId,
    actionType: field === "actionType" ? oversizedValue : "input-validation-test",
    payload: { test: "5.5" },
    exposure_cents: exposureCents,
  };

  const result = await signedPost(client, "/v1/actions/execute", actionBody);

  // At exactly the max (128 for actionType), it should succeed. At 129, it should fail.
  const rejected = result.status >= 400;
  return {
    scenarioId: "5.5",
    scenarioName: "String fields at max-length boundary",
    category: CATEGORY,
    expectedOutcome: `Probing ${field} at ${length} chars (max is 128)`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught: true,
    details: rejected
      ? `AgentGate rejected ${field} at ${length} chars (${result.status}) — max-length enforced.`
      : `AgentGate accepted ${field} at ${length} chars — within or at the max-length boundary.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 5.6: Payload at 4096-byte boundary with multi-byte UTF-8
// ---------------------------------------------------------------------------

async function attack5_6(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const targetBytes = (typeof params?.target_bytes === "number" ? params.target_bytes : 4097);

  // Lock a bond
  const bondResult = await signedPost(client, "/v1/bonds/lock", {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "input-validation-test-5.6",
  });

  if (bondResult.status >= 300) {
    return {
      scenarioId: "5.6",
      scenarioName: "Payload at 4096-byte boundary with multi-byte UTF-8",
      category: CATEGORY,
      expectedOutcome: `Probing payload boundary at ${targetBytes} bytes with emoji characters`,
      actualOutcome: `Bond lock failed: ${bondResult.status} ${JSON.stringify(bondResult.data)}`,
      caught: false,
      details: "Could not complete test — bond lock did not succeed.",
    };
  }

  const bondId = bondResult.data.bondId as string;
  const exposureCents = Math.floor(100 / 1.2);

  // Build a payload using emoji (4 bytes each in UTF-8).
  // This tests whether AgentGate checks Buffer.byteLength vs string.length.
  // Each emoji is 1 char but 4 bytes. So targetBytes/4 emojis = targetBytes bytes.
  const emojiCount = Math.ceil(targetBytes / 4);
  const emojiPayload = "\u{1F4A5}".repeat(emojiCount); // 💥
  const actualBytes = Buffer.byteLength(JSON.stringify({ data: emojiPayload }), "utf8");

  const result = await signedPost(client, "/v1/actions/execute", {
    identityId: client.identityId,
    bondId,
    actionType: "input-validation-test",
    payload: { data: emojiPayload },
    exposure_cents: exposureCents,
  });

  const rejected = result.status >= 400;
  return {
    scenarioId: "5.6",
    scenarioName: "Payload at 4096-byte boundary with multi-byte UTF-8",
    category: CATEGORY,
    expectedOutcome: `Probing payload at ~${actualBytes} bytes (${emojiPayload.length} chars) with multi-byte UTF-8`,
    actualOutcome: `${result.status} ${JSON.stringify(result.data)}`,
    caught: true,
    details: rejected
      ? `AgentGate rejected the ${actualBytes}-byte emoji payload (${result.status}) — byte-length validation works with multi-byte chars.`
      : `AgentGate accepted the ${actualBytes}-byte emoji payload (${emojiPayload.length} chars) — ${actualBytes > 4096 ? "byte-length check may use char count instead of Buffer.byteLength" : "payload is within the 4096-byte limit"}.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const inputValidationAttacks: AttackScenario[] = [
  {
    id: "5.1",
    name: "Oversized payload",
    category: CATEGORY,
    description: "Execute a bonded action with a payload string over 4096 bytes",
    expectedOutcome: "rejected with 400 PAYLOAD_TOO_LARGE",
    execute: (client, params?) => attack5_1(client, params),
  },
  {
    id: "5.2",
    name: "TTL exceeding cap",
    category: CATEGORY,
    description: "Lock a bond with ttlSeconds = 100000 (exceeds 86400s cap)",
    expectedOutcome: "rejected with 400 TTL_TOO_LONG",
    execute: (client, params?) => attack5_2(client, params),
  },
  {
    id: "5.3",
    name: "Negative bond amount",
    category: CATEGORY,
    description: "Lock a bond with amountCents = -100",
    expectedOutcome: "rejected — negative amount invalid",
    execute: (client, params?) => attack5_3(client, params),
  },
  {
    id: "5.4",
    name: "Type coercion — string where number expected",
    category: CATEGORY,
    description: "Send a string like 'abc' where amountCents (number) is expected",
    expectedOutcome: "rejected — invalid type",
    execute: (client, params?) => attack5_4(client, params),
  },
  {
    id: "5.5",
    name: "String fields at max-length boundary",
    category: CATEGORY,
    description: "Send actionType at 128/129 chars to probe max-length enforcement",
    expectedOutcome: "probing boundary",
    execute: (client, params?) => attack5_5(client, params),
  },
  {
    id: "5.6",
    name: "Payload at 4096-byte boundary with multi-byte UTF-8",
    category: CATEGORY,
    description: "Payload of emoji chars near 4096 bytes — tests Buffer.byteLength vs char count",
    expectedOutcome: "probing boundary with multi-byte chars",
    execute: (client, params?) => attack5_6(client, params),
  },
];
