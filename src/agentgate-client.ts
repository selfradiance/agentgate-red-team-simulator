// Handles all communication with the AgentGate REST API — identity creation,
// bond posting, action execution, and resolution. Uses Ed25519 signed requests.
// Signing format: sha256(nonce + method + path + timestamp + JSON.stringify(body))

import { createHash, createPrivateKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// Ed25519 signing helpers (matches AgentGate's signing protocol)
// ---------------------------------------------------------------------------

export function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

export function buildSignedMessage(nonce: string, method: string, apiPath: string, timestamp: string, body: unknown): Buffer {
  return createHash("sha256").update(`${nonce}${method}${apiPath}${timestamp}${JSON.stringify(body)}`).digest();
}

export function signRequest(
  publicKeyBase64: string,
  privateKeyBase64: string,
  nonce: string,
  method: string,
  apiPath: string,
  timestamp: string,
  body: unknown,
): string {
  const publicKeyBytes = Buffer.from(publicKeyBase64, "base64");
  const privateKeyBytes = Buffer.from(privateKeyBase64, "base64");

  const privateKey = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: toBase64Url(publicKeyBytes),
      d: toBase64Url(privateKeyBytes),
    },
    format: "jwk",
  });

  const signature = sign(null, buildSignedMessage(nonce, method, apiPath, timestamp, body), privateKey);
  return signature.toString("base64");
}

// ---------------------------------------------------------------------------
// Keypair management — generate once, persist to agent-identity.json
// ---------------------------------------------------------------------------

export interface AgentKeys {
  publicKey: string;
  privateKey: string;
}

const IDENTITY_FILE = path.resolve("agent-identity.json");

interface SavedIdentity {
  publicKey: string;
  privateKey: string;
  identityId?: string;
}

export function loadOrCreateKeypair(): AgentKeys {
  if (fs.existsSync(IDENTITY_FILE)) {
    const data: SavedIdentity = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));
    if (data.publicKey && data.privateKey) {
      return { publicKey: data.publicKey, privateKey: data.privateKey };
    }
  }

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });

  if (!publicJwk.x || !privateJwk.d) {
    throw new Error("Failed to export Ed25519 keypair as JWK");
  }

  const keys: AgentKeys = {
    publicKey: base64UrlToBase64(publicJwk.x),
    privateKey: base64UrlToBase64(privateJwk.d),
  };

  fs.writeFileSync(IDENTITY_FILE, JSON.stringify(keys, null, 2), "utf8");
  return keys;
}

export function getSavedIdentityId(): string | undefined {
  if (!fs.existsSync(IDENTITY_FILE)) return undefined;
  const data: SavedIdentity = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));
  return data.identityId;
}

function saveIdentityId(identityId: string): void {
  const data: SavedIdentity = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));
  data.identityId = identityId;
  fs.writeFileSync(IDENTITY_FILE, JSON.stringify(data, null, 2), "utf8");
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 10_000;

function getConfig() {
  const agentGateUrl = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
  const apiKey = process.env.AGENTGATE_REST_KEY;
  if (!apiKey) {
    throw new Error("AGENTGATE_REST_KEY not set in environment");
  }
  return { agentGateUrl, apiKey };
}

async function parseResponse(response: Response): Promise<Record<string, unknown>> {
  try {
    return await response.json() as Record<string, unknown>;
  } catch {
    const text = await response.text().catch(() => "(empty)");
    return { error: "UNPARSEABLE_RESPONSE", message: text };
  }
}

async function signedPost(
  apiPath: string,
  body: unknown,
  keys: AgentKeys,
): Promise<Record<string, unknown>> {
  const { agentGateUrl, apiKey } = getConfig();
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(keys.publicKey, keys.privateKey, nonce, "POST", apiPath, timestamp, body);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(new URL(apiPath, agentGateUrl), {
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
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`AgentGate request timed out after ${REQUEST_TIMEOUT_MS / 1000}s: ${apiPath}`);
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  const data = await parseResponse(response);

  if (!response.ok) {
    throw new Error(`AgentGate ${apiPath} failed (${response.status}): ${JSON.stringify(data)}`);
  }

  return data;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function createIdentity(keys: AgentKeys): Promise<string> {
  // If we already have a saved identity ID from a previous run, use it
  const savedId = getSavedIdentityId();
  if (savedId) {
    return savedId;
  }

  try {
    const data = await signedPost(
      "/v1/identities",
      { publicKey: keys.publicKey },
      keys,
    );

    const identityId = data.identityId;
    if (typeof identityId !== "string") {
      throw new Error(`No identityId returned: ${JSON.stringify(data)}`);
    }

    // Save the identity ID for subsequent runs
    saveIdentityId(identityId);
    return identityId;
  } catch (err) {
    // 409 means this keypair is already registered — that's fine
    if (err instanceof Error && err.message.includes("(409)")) {
      throw new Error(
        "Identity already registered but ID not saved locally. Delete agent-identity.json and try again.",
      );
    }
    throw err;
  }
}

export async function postBond(
  keys: AgentKeys,
  identityId: string,
  amountCents: number,
  ttlSeconds: number,
  reason: string,
): Promise<Record<string, unknown>> {
  const data = await signedPost(
    "/v1/bonds/lock",
    { identityId, amountCents, currency: "USD", ttlSeconds, reason },
    keys,
  );

  if (typeof data.bondId !== "string") {
    throw new Error(`No bondId returned: ${JSON.stringify(data)}`);
  }

  return data;
}

export async function executeBondedAction(
  keys: AgentKeys,
  identityId: string,
  bondId: string,
  actionType: string,
  payload: unknown,
  exposureCents: number,
): Promise<Record<string, unknown>> {
  const data = await signedPost(
    "/v1/actions/execute",
    { identityId, bondId, actionType, payload, exposure_cents: exposureCents },
    keys,
  );

  if (typeof data.actionId !== "string") {
    throw new Error(`No actionId returned: ${JSON.stringify(data)}`);
  }

  return data;
}

export async function resolveAction(
  keys: AgentKeys,
  actionId: string,
  outcome: "success" | "failed",
): Promise<Record<string, unknown>> {
  return signedPost(
    `/v1/actions/${actionId}/resolve`,
    { outcome },
    keys,
  );
}
