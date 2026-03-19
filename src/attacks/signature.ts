// Signature attack scenarios — tests whether AgentGate rejects tampered or invalid signatures

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import { signRequest } from "../agentgate-client";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "Signature Tampering";

// ---------------------------------------------------------------------------
// Attack 3.1: Wrong private key
// ---------------------------------------------------------------------------

async function attack3_1(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const targetEndpoint = (typeof params?.target_endpoint === "string" ? params.target_endpoint : "/v1/bonds/lock");
  const apiPath = targetEndpoint;
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

async function attack3_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const signatureValue = (typeof params?.signature_value === "string" ? params.signature_value : "not-a-real-signature-lol");
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
      "x-agentgate-signature": signatureValue,
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

async function attack3_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  // omit_headers: which headers to leave out. Default: all three (signature, timestamp, nonce).
  const omitHeaders = (Array.isArray(params?.omit_headers) ? params.omit_headers as string[] : ["signature", "timestamp", "nonce"]);
  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.3",
  };

  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, body);

  // Build headers, selectively omitting the ones specified
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-agentgate-key": client.apiKey,
  };
  if (!omitHeaders.includes("nonce")) headers["x-nonce"] = nonce;
  if (!omitHeaders.includes("timestamp")) headers["x-agentgate-timestamp"] = timestamp;
  if (!omitHeaders.includes("signature")) headers["x-agentgate-signature"] = signature;

  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers,
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
    expectedOutcome: `Rejected — missing headers: ${omitHeaders.join(", ")}`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the request with missing ${omitHeaders.join(", ")} header(s) (${response.status}).`
      : `AgentGate accepted a request missing ${omitHeaders.join(", ")} header(s) — header validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 3.4: Valid signature for different endpoint
// ---------------------------------------------------------------------------

async function attack3_4(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const signForPath = (typeof params?.sign_for_path === "string" ? params.sign_for_path : "/v1/bonds/lock");
  const sendToPath = (typeof params?.send_to_path === "string" ? params.send_to_path : "/v1/actions/execute");

  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.4",
  };

  // Sign for one endpoint but send to a different one.
  // The path is bound into the signed message: sha256(nonce + method + PATH + timestamp + body).
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", signForPath, timestamp, body);

  const response = await fetch(new URL(sendToPath, client.agentGateUrl), {
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
    scenarioId: "3.4",
    scenarioName: "Valid signature for different endpoint",
    category: CATEGORY,
    expectedOutcome: `Rejected — signature was for ${signForPath} but sent to ${sendToPath}`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `AgentGate rejected the cross-endpoint signature (${response.status}) — path is bound into signature verification.`
      : `AgentGate accepted a signature computed for ${signForPath} when sent to ${sendToPath} — path may not be bound into the signed message.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 3.5: Header canonicalization abuse
// ---------------------------------------------------------------------------

async function attack3_5(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const abuseType = (typeof params?.abuse_type === "string" ? params.abuse_type : "duplicate");

  const apiPath = "/v1/bonds/lock";
  const body = {
    identityId: client.identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "signature-test-3.5",
  };

  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(client.keys.publicKey, client.keys.privateKey, nonce, "POST", apiPath, timestamp, body);

  // Build headers with the specified abuse type
  let headers: [string, string][];

  if (abuseType === "duplicate") {
    // Send duplicate x-agentgate-signature headers (second one is garbage)
    headers = [
      ["content-type", "application/json"],
      ["x-nonce", nonce],
      ["x-agentgate-key", client.apiKey],
      ["x-agentgate-timestamp", timestamp],
      ["x-agentgate-signature", signature],
      ["x-agentgate-signature", "garbage-duplicate-value"],
    ];
  } else if (abuseType === "whitespace") {
    // Whitespace-padded header values
    headers = [
      ["content-type", "application/json"],
      ["x-nonce", `  ${nonce}  `],
      ["x-agentgate-key", `  ${client.apiKey}  `],
      ["x-agentgate-timestamp", `  ${timestamp}  `],
      ["x-agentgate-signature", `  ${signature}  `],
    ];
  } else {
    // Mixed-case header names (HTTP headers are case-insensitive per spec,
    // but server code might do case-sensitive lookups)
    headers = [
      ["content-type", "application/json"],
      ["X-Nonce", nonce],
      ["X-AgentGate-Key", client.apiKey],
      ["X-AgentGate-Timestamp", timestamp],
      ["X-AgentGate-Signature", signature],
    ];
  }

  const response = await fetch(new URL(apiPath, client.agentGateUrl), {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    data = { error: "UNPARSEABLE_RESPONSE" };
  }

  // For "duplicate" and "whitespace" abuse, we expect rejection.
  // For "mixed-case", HTTP spec says headers are case-insensitive, so acceptance is correct behavior.
  const rejected = response.status >= 400;
  const isProbe = abuseType === "mixed-case";

  return {
    scenarioId: "3.5",
    scenarioName: "Header canonicalization abuse",
    category: CATEGORY,
    expectedOutcome: `Probing header handling with ${abuseType} abuse`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught: isProbe ? true : rejected,
    details: rejected
      ? `AgentGate rejected the ${abuseType} header abuse (${response.status}).`
      : `AgentGate accepted the ${abuseType} header abuse — ${abuseType === "mixed-case" ? "correct per HTTP spec (case-insensitive)." : "header canonicalization may not be strict enough."}`,
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
    execute: (client, params?) => attack3_1(client, params),
  },
  {
    id: "3.2",
    name: "Malformed signature",
    category: CATEGORY,
    description: "Send a request with a garbage signature string",
    expectedOutcome: "rejected — invalid signature format",
    execute: (client, params?) => attack3_2(client, params),
  },
  {
    id: "3.3",
    name: "Missing signature headers",
    category: CATEGORY,
    description: "Send a request with no signature, timestamp, or nonce headers",
    expectedOutcome: "rejected — missing required headers",
    execute: (client, params?) => attack3_3(client, params),
  },
  {
    id: "3.4",
    name: "Valid signature for different endpoint",
    category: CATEGORY,
    description: "Sign a request for /v1/bonds/lock but send it to /v1/actions/execute",
    expectedOutcome: "rejected — path bound into signature",
    execute: (client, params?) => attack3_4(client, params),
  },
  {
    id: "3.5",
    name: "Header canonicalization abuse",
    category: CATEGORY,
    description: "Duplicate x-signature headers, whitespace-padded values, or mixed-case header names",
    expectedOutcome: "probing header handling",
    execute: (client, params?) => attack3_5(client, params),
  },
];
