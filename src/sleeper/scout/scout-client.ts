// Lightweight AgentGate client for scout probes.
// Uses the same signing protocol as agentgate-client.ts but allows
// arbitrary keypairs without touching the singleton identity file.

import { createHash, createPrivateKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";

export interface ScoutKeys {
  publicKey: string; // base64
  privateKey: string; // base64
}

export interface ScoutIdentity {
  keys: ScoutKeys;
  identityId: string;
}

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

export function generateKeypair(): ScoutKeys {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  if (!publicJwk.x || !privateJwk.d) throw new Error("Failed to export Ed25519 keypair");
  return {
    publicKey: base64UrlToBase64(publicJwk.x),
    privateKey: base64UrlToBase64(privateJwk.d),
  };
}

function signRequest(
  keys: ScoutKeys,
  nonce: string,
  method: string,
  apiPath: string,
  timestamp: string,
  body: unknown,
): string {
  const publicKeyBytes = Buffer.from(keys.publicKey, "base64");
  const privateKeyBytes = Buffer.from(keys.privateKey, "base64");
  const pk = createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", x: toBase64Url(publicKeyBytes), d: toBase64Url(privateKeyBytes) },
    format: "jwk",
  });
  const message = createHash("sha256")
    .update(`${nonce}${method}${apiPath}${timestamp}${JSON.stringify(body)}`)
    .digest();
  return sign(null, message, pk).toString("base64");
}

const REQUEST_TIMEOUT_MS = 10_000;

export interface RawResponse {
  status: number;
  data: Record<string, unknown>;
}

export async function signedPost(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  apiPath: string,
  body: unknown,
): Promise<RawResponse> {
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(keys, nonce, "POST", apiPath, timestamp, body);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(apiPath, targetUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nonce": nonce,
        "x-agentgate-key": apiKey,
        "x-agentgate-timestamp": timestamp,
        "x-agentgate-signature": signature,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function signedPostWithCustomHeaders(
  targetUrl: string,
  apiPath: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<RawResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(apiPath, targetUrl), {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function postRawBody(
  targetUrl: string,
  apiPath: string,
  rawBody: string,
  headers: Record<string, string>,
): Promise<RawResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(apiPath, targetUrl), {
      method: "POST",
      headers,
      body: rawBody,
      signal: controller.signal,
    });

    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function signedPostWithTimestamp(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  apiPath: string,
  body: unknown,
  timestampMs: number,
): Promise<RawResponse> {
  const nonce = randomUUID();
  const timestamp = timestampMs.toString();
  const signature = signRequest(keys, nonce, "POST", apiPath, timestamp, body);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(apiPath, targetUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nonce": nonce,
        "x-agentgate-key": apiKey,
        "x-agentgate-timestamp": timestamp,
        "x-agentgate-signature": signature,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function signedPostWithNonce(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  apiPath: string,
  body: unknown,
  nonce: string,
): Promise<RawResponse> {
  const timestamp = Date.now().toString();
  const signature = signRequest(keys, nonce, "POST", apiPath, timestamp, body);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(apiPath, targetUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nonce": nonce,
        "x-agentgate-key": apiKey,
        "x-agentgate-timestamp": timestamp,
        "x-agentgate-signature": signature,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function rawGet(targetUrl: string, path: string): Promise<RawResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(path, targetUrl), { signal: controller.signal });
    let data: Record<string, unknown>;
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      data = { error: "UNPARSEABLE_RESPONSE", message: await response.text().catch(() => "(empty)") };
    }
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export async function createScoutIdentity(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
): Promise<string> {
  const result = await signedPost(targetUrl, apiKey, keys, "/v1/identities", {
    publicKey: keys.publicKey,
  });

  if (result.status === 409) {
    // Already registered — need to find the ID via the response
    const id = result.data.identityId;
    if (typeof id === "string") return id;
    throw new Error(`Identity already registered but no identityId in 409 response: ${JSON.stringify(result.data)}`);
  }

  if (result.status !== 200 && result.status !== 201) {
    throw new Error(`createIdentity failed (${result.status}): ${JSON.stringify(result.data)}`);
  }

  const id = result.data.identityId;
  if (typeof id !== "string") {
    throw new Error(`No identityId returned: ${JSON.stringify(result.data)}`);
  }
  return id;
}

export async function lockBond(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  identityId: string,
  amountCents: number,
  ttlSeconds: number = 300,
  reason: string = "scout-probe",
): Promise<RawResponse> {
  return signedPost(targetUrl, apiKey, keys, "/v1/bonds/lock", {
    identityId,
    amountCents,
    currency: "USD",
    ttlSeconds,
    reason,
  });
}

export async function executeAction(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  identityId: string,
  bondId: string,
  exposureCents: number,
): Promise<RawResponse> {
  return signedPost(targetUrl, apiKey, keys, "/v1/actions/execute", {
    identityId,
    bondId,
    actionType: "data_retrieval",
    payload: { type: "scout-probe" },
    exposure_cents: exposureCents,
  });
}

export async function resolveAction(
  targetUrl: string,
  apiKey: string,
  keys: ScoutKeys,
  resolverIdentityId: string,
  actionId: string,
): Promise<RawResponse> {
  return signedPost(targetUrl, apiKey, keys, `/v1/actions/${actionId}/resolve`, {
    outcome: "success",
    resolverId: resolverIdentityId,
  });
}
