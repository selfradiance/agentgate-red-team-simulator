// Parent-side toolkit host — handles IPC requests from the sandboxed child
// process and executes the real HTTP calls. The child is logic-only; this
// module owns all network access.

import type { ChildProcess } from "node:child_process";
import { randomUUID, generateKeyPairSync, createHash, createPrivateKey, sign } from "node:crypto";
import { signRequest } from "../agentgate-client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ToolkitHostOptions {
  targetUrl: string;
  agentIdentity: {
    identityId: string;
    publicKey: string;
    privateKey: string;
  };
  restKey: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HTTP_TIMEOUT_MS = 5_000;
const RESPONSE_BODY_CAP = 4096;
const MAX_CREATE_IDENTITY = 3;

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    let body: Record<string, unknown>;
    try {
      const text = await response.text();
      const truncated = text.slice(0, RESPONSE_BODY_CAP);
      body = JSON.parse(truncated);
    } catch {
      body = { _raw: "unparseable or truncated" };
    }
    return Object.freeze({ status: response.status, body: Object.freeze(body) }) as { status: number; body: Record<string, unknown> };
  } finally {
    clearTimeout(timer);
  }
}

function makeSignedHeaders(
  publicKey: string,
  privateKey: string,
  restKey: string,
  method: string,
  apiPath: string,
  body: unknown,
): Record<string, string> {
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const signature = signRequest(publicKey, privateKey, nonce, method, apiPath, timestamp, body);
  return {
    "content-type": "application/json",
    "x-nonce": nonce,
    "x-agentgate-key": restKey,
    "x-agentgate-timestamp": timestamp,
    "x-agentgate-signature": signature,
  };
}

// ---------------------------------------------------------------------------
// Path validation — prevents SSRF via absolute URLs in toolkit calls
// ---------------------------------------------------------------------------

function validatePath(apiPath: string): void {
  if (typeof apiPath !== "string" || !apiPath.startsWith("/")) {
    throw new Error(`Invalid API path: must start with '/'. Got: ${String(apiPath).slice(0, 50)}`);
  }
}

// ---------------------------------------------------------------------------
// Method handlers
// ---------------------------------------------------------------------------

type MethodHandler = (args: unknown[], options: ToolkitHostOptions, state: HostState) => Promise<unknown>;

interface HostState {
  createIdentityCount: number;
}

const handlers: Record<string, MethodHandler> = {
  async signedPost(args, options) {
    const [apiPath, body] = args as [string, unknown];
    validatePath(apiPath);
    const headers = makeSignedHeaders(
      options.agentIdentity.publicKey, options.agentIdentity.privateKey,
      options.restKey, "POST", apiPath, body,
    );
    return fetchWithTimeout(new URL(apiPath, options.targetUrl).toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
  },

  async rawPost(args, options) {
    const [apiPath, body, customHeaders] = args as [string, unknown, Record<string, string> | undefined];
    validatePath(apiPath);
    return fetchWithTimeout(new URL(apiPath, options.targetUrl).toString(), {
      method: "POST",
      headers: { "content-type": "application/json", ...customHeaders },
      body: JSON.stringify(body),
    });
  },

  async rawGet(args, options) {
    const [apiPath] = args as [string];
    validatePath(apiPath);
    return fetchWithTimeout(new URL(apiPath, options.targetUrl).toString(), {
      method: "GET",
    });
  },

  async createIdentity(_args, options, state) {
    state.createIdentityCount++;
    if (state.createIdentityCount > MAX_CREATE_IDENTITY) {
      throw new Error("createIdentity() cap exceeded: maximum 3 identities per attack execution (parent enforcement)");
    }

    // Generate a fresh keypair
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const privateJwk = privateKey.export({ format: "jwk" });
    const pub = base64UrlToBase64(publicJwk.x!);
    const priv = base64UrlToBase64(privateJwk.d!);

    // Register with AgentGate
    const apiPath = "/v1/identities";
    const body = { publicKey: pub };
    const headers = makeSignedHeaders(pub, priv, options.restKey, "POST", apiPath, body);

    const result = await fetchWithTimeout(new URL(apiPath, options.targetUrl).toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (result.status >= 300) {
      throw new Error(`Identity creation failed: ${result.status} ${JSON.stringify(result.body)}`);
    }

    return Object.freeze({
      identityId: result.body.identityId as string,
      publicKey: pub,
      privateKey: priv,
    });
  },

  async signedPostAs(args, options) {
    const [identity, apiPath, body] = args as [{ publicKey: string; privateKey: string }, string, unknown];
    validatePath(apiPath);
    const headers = makeSignedHeaders(
      identity.publicKey, identity.privateKey,
      options.restKey, "POST", apiPath, body,
    );
    return fetchWithTimeout(new URL(apiPath, options.targetUrl).toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
  },

  async getReputation(args, options) {
    const [identityId] = args as [string];
    try {
      const result = await fetchWithTimeout(
        new URL(`/v1/identities/${identityId}`, options.targetUrl).toString(),
        { method: "GET" },
      );
      const score = typeof result.body.reputationScore === "number" ? result.body.reputationScore
        : typeof result.body.reputation === "number" ? result.body.reputation
        : typeof result.body.score === "number" ? result.body.score
        : null;
      return Object.freeze({ score });
    } catch {
      return Object.freeze({ score: null });
    }
  },

  async getBondStatus(args, options) {
    const [bondId] = args as [string];
    try {
      const result = await fetchWithTimeout(
        new URL(`/v1/bonds/${bondId}`, options.targetUrl).toString(),
        { method: "GET", headers: { "x-agentgate-key": options.restKey } },
      );
      return Object.freeze({
        status: typeof result.body.status === "string" ? result.body.status : null,
      });
    } catch {
      return Object.freeze({ status: null });
    }
  },

  async getActionStatus(args, options) {
    const [actionId] = args as [string];
    try {
      const result = await fetchWithTimeout(
        new URL(`/v1/actions/${actionId}`, options.targetUrl).toString(),
        { method: "GET", headers: { "x-agentgate-key": options.restKey } },
      );
      return Object.freeze({
        status: typeof result.body.status === "string" ? result.body.status : null,
      });
    } catch {
      return Object.freeze({ status: null });
    }
  },

  async checkDashboardForRawHtml(_args, options) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
      try {
        const response = await fetch(new URL("/dashboard", options.targetUrl).toString(), {
          method: "GET",
          signal: controller.signal,
        });
        if (response.status >= 300) {
          return Object.freeze({ foundRawHtml: false, details: `Dashboard returned ${response.status}` });
        }
        const html = await response.text();
        const suspicious = ["<script>", "<img onerror", "javascript:", "<iframe"].some(
          (pattern) => html.includes(pattern),
        );
        return Object.freeze({
          foundRawHtml: suspicious,
          details: suspicious ? "Found unescaped HTML patterns in dashboard" : "Dashboard HTML appears properly escaped",
        });
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return Object.freeze({ foundRawHtml: false, details: "Dashboard unreachable" });
    }
  },
};

// ---------------------------------------------------------------------------
// Attach to child process
// ---------------------------------------------------------------------------

export function attachToolkitHost(child: ChildProcess, options: ToolkitHostOptions): void {
  const state: HostState = { createIdentityCount: 0 };

  child.on("message", async (msg: unknown) => {
    const m = msg as Record<string, unknown>;
    if (!m || typeof m !== "object" || m.type !== "toolkit-request") return;

    const id = m.id as number;
    const method = m.method as string;
    const args = m.args as unknown[];

    const handler = handlers[method];
    if (!handler) {
      child.send({ type: "toolkit-error", id, error: `Unknown toolkit method: ${method}` });
      return;
    }

    try {
      const result = await handler(args, options, state);
      child.send({ type: "toolkit-response", id, result });
    } catch (err) {
      child.send({ type: "toolkit-error", id, error: err instanceof Error ? err.message : String(err) });
    }
  });
}

// ---------------------------------------------------------------------------
// Stub host — responds with mock data for unit tests (no real HTTP)
// ---------------------------------------------------------------------------

export function attachStubToolkitHost(child: ChildProcess): void {
  let createCount = 0;

  child.on("message", async (msg: unknown) => {
    const m = msg as Record<string, unknown>;
    if (!m || typeof m !== "object" || m.type !== "toolkit-request") return;

    const id = m.id as number;
    const method = m.method as string;

    try {
      let result: unknown;

      switch (method) {
        case "signedPost":
        case "rawPost":
        case "signedPostAs":
          result = { status: 200, body: { stub: true } };
          break;
        case "rawGet":
          result = { status: 200, body: { stub: true } };
          break;
        case "createIdentity":
          createCount++;
          if (createCount > 3) throw new Error("createIdentity() cap exceeded: maximum 3 identities per attack execution");
          result = { identityId: `stub-id-${createCount}`, publicKey: `stub-key-${createCount}`, privateKey: `stub-priv-${createCount}` };
          break;
        case "getReputation":
          result = { score: 0 };
          break;
        case "getBondStatus":
          result = { status: "active" };
          break;
        case "getActionStatus":
          result = { status: "open" };
          break;
        case "checkDashboardForRawHtml":
          result = { foundRawHtml: false };
          break;
        default:
          throw new Error(`Unknown toolkit method: ${method}`);
      }

      child.send({ type: "toolkit-response", id, result });
    } catch (err) {
      child.send({ type: "toolkit-error", id, error: err instanceof Error ? err.message : String(err) });
    }
  });
}
