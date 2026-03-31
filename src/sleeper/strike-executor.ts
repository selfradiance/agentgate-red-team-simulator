import { executeInSandbox } from "../sandbox/executor.js";
import { validateGeneratedCode } from "../sandbox/validator.js";
import type { ScoutKeys } from "./scout/scout-client.js";
import type { AttackOutcome, StrikeAttack } from "./strike-strategist.js";

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_RATE_LIMIT_REQUESTS = 20;
const MAX_PUBLIC_ENDPOINTS = 10;
const MAX_ATTACK_JSON_CHARS = 4_000;

export interface PreparedStrikeAttack extends StrikeAttack {
  estimatedExposure: number;
  timeoutMs: number;
}

export interface StrikeExecutionContext {
  targetUrl: string;
  apiKey: string;
  strikeKeys: ScoutKeys;
  strikeIdentityId: string;
  resolverKeys: ScoutKeys;
  resolverIdentityId: string;
}

type PreparationResult =
  | { ready: true; attack: PreparedStrikeAttack }
  | { ready: false; reason: string };

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function normalizeApiPath(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//") || trimmed.includes("..")) return fallback;
  return trimmed;
}

function cloneJsonValue<T>(value: unknown, fallback: T): T {
  try {
    const json = JSON.stringify(value);
    if (!json || json.length > MAX_ATTACK_JSON_CHARS) {
      return fallback;
    }
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function normalizeHeaders(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  const normalized: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value)) {
    if (typeof headerValue !== "string") continue;
    normalized[key] = headerValue;
  }
  return normalized;
}

function withIdentityId(payload: unknown, identityId: string): unknown {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return payload;
  }

  const cloned = { ...(payload as Record<string, unknown>) };
  if (cloned.identityId === undefined) {
    cloned.identityId = identityId;
  }
  return cloned;
}

function withFallbackExposure(payload: unknown): number {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return 0;
  }

  const value = (payload as Record<string, unknown>).exposure_cents;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.trunc(value));
}

export function prepareStrikeAttack(
  attack: StrikeAttack,
  budgetRemaining: number,
): PreparationResult {
  switch (attack.objective_id) {
    case "T1": {
      const exposureCents = clampInt(attack.params.exposure_cents, 5, 1, 100);
      const requestedBurst = clampInt(attack.params.burst_count, 11, 1, MAX_RATE_LIMIT_REQUESTS);
      const maxBurstByBudget = Math.floor(budgetRemaining / exposureCents);
      if (maxBurstByBudget < 1) {
        return { ready: false, reason: `Budget remaining (${budgetRemaining}¢) is below one T1 action (${exposureCents}¢).` };
      }

      const burstCount = Math.min(requestedBurst, maxBurstByBudget);
      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            bond_cents: clampInt(attack.params.bond_cents, 100, exposureCents, 500),
            burst_count: burstCount,
            delay_ms: clampInt(attack.params.delay_ms, 0, 0, 500),
            exposure_cents: exposureCents,
          },
          estimatedExposure: burstCount * exposureCents,
          timeoutMs: Math.max(
            DEFAULT_TIMEOUT_MS,
            10_000 + burstCount * (clampInt(attack.params.delay_ms, 0, 0, 500) + 500),
          ),
        },
      };
    }

    case "T2": {
      const exposureCents = clampInt(attack.params.exposure_cents, 85, 1, 2_000);
      if (exposureCents > budgetRemaining) {
        return { ready: false, reason: `T2 requested ${exposureCents}¢ exposure with only ${budgetRemaining}¢ remaining.` };
      }

      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            bond_cents: clampInt(attack.params.bond_cents, 100, 1, 500),
            exposure_cents: exposureCents,
          },
          estimatedExposure: exposureCents,
          timeoutMs: DEFAULT_TIMEOUT_MS,
        },
      };
    }

    case "T3":
      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            bond_cents: clampInt(attack.params.bond_cents, 500, 1, 2_000),
          },
          estimatedExposure: 0,
          timeoutMs: DEFAULT_TIMEOUT_MS,
        },
      };

    case "T4": {
      const waitSeconds = clampInt(attack.params.wait_seconds, 0, 0, 420);
      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            wait_seconds: waitSeconds,
          },
          estimatedExposure: 0,
          timeoutMs: Math.max(20_000, waitSeconds * 1000 + 15_000),
        },
      };
    }

    case "T5": {
      const endpoint = normalizeApiPath(attack.params.endpoint, "/v1/bonds/lock");
      const signed = attack.params.signed !== false;
      const defaultPayload = endpoint === "/v1/bonds/lock"
        ? {
            identityId: "__STRIKE_IDENTITY__",
            amountCents: -100,
            currency: "USD",
            ttlSeconds: 300,
            reason: "strike-t5",
          }
        : { identityId: "__STRIKE_IDENTITY__" };
      const payloadCandidate = cloneJsonValue<unknown>(attack.params.payload, defaultPayload);
      const payload = signed && (!payloadCandidate || typeof payloadCandidate !== "object" || Array.isArray(payloadCandidate))
        ? defaultPayload
        : payloadCandidate;
      const estimatedExposure = Math.min(withFallbackExposure(payload), 2_000);
      if (estimatedExposure > budgetRemaining) {
        return { ready: false, reason: `T5 requested ${estimatedExposure}¢ exposure with only ${budgetRemaining}¢ remaining.` };
      }

      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            endpoint,
            headers: normalizeHeaders(attack.params.headers),
            payload,
            signed,
          },
          estimatedExposure,
          timeoutMs: DEFAULT_TIMEOUT_MS,
        },
      };
    }

    case "T6": {
      const endpoints = Array.isArray(attack.params.endpoints)
        ? attack.params.endpoints
            .filter((value): value is string => typeof value === "string")
            .map((value) => normalizeApiPath(value, ""))
            .filter(Boolean)
            .slice(0, MAX_PUBLIC_ENDPOINTS)
        : [];

      return {
        ready: true,
        attack: {
          ...attack,
          params: {
            endpoints: endpoints.length > 0 ? endpoints : ["/health", "/v1/stats"],
          },
          estimatedExposure: 0,
          timeoutMs: DEFAULT_TIMEOUT_MS,
        },
      };
    }

    default:
      return { ready: false, reason: `Unknown objective: ${attack.objective_id}` };
  }
}

/** @internal Exported for testing only. */
export function buildStrikeCode(
  attack: PreparedStrikeAttack,
  ctx: StrikeExecutionContext,
): string {
  const identityId = JSON.stringify(ctx.strikeIdentityId);
  const resolverIdentityId = JSON.stringify(ctx.resolverIdentityId);

  switch (attack.objective_id) {
    case "T1":
      return `async function novelAttack(toolkit) {
  var identityId = ${identityId};
  var resolverIdentityId = ${resolverIdentityId};
  var bondCents = ${JSON.stringify(attack.params.bond_cents)};
  var burstCount = ${JSON.stringify(attack.params.burst_count)};
  var delayMs = ${JSON.stringify(attack.params.delay_ms)};
  var exposureCents = ${JSON.stringify(attack.params.exposure_cents)};
  var exposureUsed = 0;
  var requestCount = 0;
  var lastStatus = 0;
  var lastErrorCode = "";
  var successes = 0;
  var bond = await toolkit.signedPost("/v1/bonds/lock", {
    identityId: identityId,
    amountCents: bondCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "strike-rate-limit"
  });
  requestCount++;
  lastStatus = bond.status;
  lastErrorCode = String((bond.body && (bond.body.code || bond.body.error)) || "");
  if (bond.status < 200 || bond.status >= 300) {
    return {
      caught: true,
      reason: "Bond lock failed: " + bond.status,
      sideEffects: { responseStatus: bond.status, errorCode: lastErrorCode, exposureUsed: exposureUsed, requestCount: requestCount }
    };
  }
  for (var i = 0; i < burstCount; i++) {
    var result = await toolkit.signedPost("/v1/actions/execute", {
      identityId: identityId,
      bondId: bond.body.bondId,
      actionType: "data_retrieval",
      payload: { type: "strike-rate-limit" },
      exposure_cents: exposureCents
    });
    requestCount++;
    lastStatus = result.status;
    lastErrorCode = String((result.body && (result.body.code || result.body.error)) || "");
    if (result.status >= 200 && result.status < 300) {
      successes++;
      exposureUsed += exposureCents;
      var resolveResult = await toolkit.signedPostAsResolver(
        "/v1/actions/" + result.body.actionId + "/resolve",
        { outcome: "success", resolverId: resolverIdentityId }
      );
      requestCount++;
      if (resolveResult.status >= 300) {
        return {
          caught: true,
          reason: "Resolver failed after action creation",
          sideEffects: { responseStatus: resolveResult.status, errorCode: String((resolveResult.body && (resolveResult.body.code || resolveResult.body.error)) || ""), exposureUsed: exposureUsed, requestCount: requestCount }
        };
      }
    }
    if (result.status === 429) {
      break;
    }
    if (delayMs > 0) {
      await toolkit.sleep(delayMs);
    }
  }
  var bypassed = successes > 10;
  return {
    caught: !bypassed,
    reason: bypassed ? "Rate limit bypassed with " + successes + " successes" : "Rate limit held after " + successes + " successes",
    sideEffects: { responseStatus: lastStatus, errorCode: lastErrorCode, exposureUsed: exposureUsed, requestCount: requestCount }
  };
}`;

    case "T2":
      return `async function novelAttack(toolkit) {
  var identityId = ${identityId};
  var resolverIdentityId = ${resolverIdentityId};
  var bondCents = ${JSON.stringify(attack.params.bond_cents)};
  var exposureCents = ${JSON.stringify(attack.params.exposure_cents)};
  var exposureUsed = 0;
  var requestCount = 0;
  var bond = await toolkit.signedPost("/v1/bonds/lock", {
    identityId: identityId,
    amountCents: bondCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "strike-capacity"
  });
  requestCount++;
  if (bond.status < 200 || bond.status >= 300) {
    return {
      caught: true,
      reason: "Bond lock failed: " + bond.status,
      sideEffects: { responseStatus: bond.status, errorCode: String((bond.body && (bond.body.code || bond.body.error)) || ""), exposureUsed: 0, requestCount: requestCount }
    };
  }
  var result = await toolkit.signedPost("/v1/actions/execute", {
    identityId: identityId,
    bondId: bond.body.bondId,
    actionType: "data_retrieval",
    payload: { type: "strike-capacity" },
    exposure_cents: exposureCents
  });
  requestCount++;
  var overflowSucceeded = result.status >= 200 && result.status < 300;
  if (overflowSucceeded) {
    exposureUsed = exposureCents;
    var resolveResult = await toolkit.signedPostAsResolver(
      "/v1/actions/" + result.body.actionId + "/resolve",
      { outcome: "success", resolverId: resolverIdentityId }
    );
    requestCount++;
    if (resolveResult.status >= 300) {
      return {
        caught: true,
        reason: "Resolver failed after overflow action",
        sideEffects: { responseStatus: resolveResult.status, errorCode: String((resolveResult.body && (resolveResult.body.code || resolveResult.body.error)) || ""), exposureUsed: exposureUsed, requestCount: requestCount }
      };
    }
  }
  return {
    caught: !overflowSucceeded,
    reason: overflowSucceeded ? "Bond capacity overflow succeeded" : "Bond capacity held",
    sideEffects: { responseStatus: result.status, errorCode: String((result.body && (result.body.code || result.body.error)) || ""), exposureUsed: exposureUsed, requestCount: requestCount }
  };
}`;

    case "T3":
      return `async function novelAttack(toolkit) {
  var identityId = ${identityId};
  var bondCents = ${JSON.stringify(attack.params.bond_cents)};
  var result = await toolkit.signedPost("/v1/bonds/lock", {
    identityId: identityId,
    amountCents: bondCents,
    currency: "USD",
    ttlSeconds: 300,
    reason: "strike-tier-cap"
  });
  var evaded = result.status >= 200 && result.status < 300;
  return {
    caught: !evaded,
    reason: evaded ? "Tier cap evasion succeeded" : "Tier cap held",
    sideEffects: { responseStatus: result.status, errorCode: String((result.body && (result.body.code || result.body.error)) || ""), exposureUsed: 0, requestCount: 1 }
  };
}`;

    case "T4":
      return `async function novelAttack(toolkit) {
  var identityId = ${identityId};
  var waitSeconds = ${JSON.stringify(attack.params.wait_seconds)};
  var nonce = "strike-replay-" + Date.now();
  var body = {
    identityId: identityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 900,
    reason: "strike-replay"
  };
  var first = await toolkit.signedPostWithControl("/v1/bonds/lock", body, { nonce: nonce });
  var duplicate = await toolkit.signedPostWithControl("/v1/bonds/lock", body, { nonce: nonce });
  if (waitSeconds > 0) {
    await toolkit.sleep(waitSeconds * 1000);
  }
  var replay = await toolkit.signedPostWithControl("/v1/bonds/lock", body, { nonce: nonce });
  var replaySucceeded = replay.status >= 200 && replay.status < 300;
  return {
    caught: !replaySucceeded,
    reason: replaySucceeded ? "Nonce replay succeeded after wait" : "Nonce replay rejected",
    sideEffects: {
      responseStatus: replay.status,
      errorCode: String((replay.body && (replay.body.code || replay.body.error)) || ""),
      exposureUsed: 0,
      requestCount: 3,
      duplicateStatus: duplicate.status,
      firstStatus: first.status
    }
  };
}`;

    case "T5": {
      const payload = JSON.stringify(withIdentityId(attack.params.payload, ctx.strikeIdentityId));
      const endpoint = JSON.stringify(attack.params.endpoint);
      const headers = JSON.stringify(attack.params.headers);
      if (attack.params.signed === false) {
        return `async function novelAttack(toolkit) {
  var endpoint = ${endpoint};
  var payload = ${payload};
  var headers = ${headers};
  var result = await toolkit.rawPost(endpoint, payload, headers);
  var objectiveSucceeded = result.status >= 200 && result.status < 300;
  return {
    caught: !objectiveSucceeded,
    reason: objectiveSucceeded ? "Targeted raw probe succeeded" : "Targeted raw probe rejected",
    sideEffects: { responseStatus: result.status, errorCode: String((result.body && (result.body.code || result.body.error)) || ""), exposureUsed: 0, requestCount: 1 }
  };
}`;
      }

      return `async function novelAttack(toolkit) {
  var endpoint = ${endpoint};
  var payload = ${payload};
  var result = await toolkit.signedPost(endpoint, payload);
  var objectiveSucceeded = result.status >= 200 && result.status < 300;
  var exposureUsed = objectiveSucceeded ? ${JSON.stringify(attack.estimatedExposure)} : 0;
  return {
    caught: !objectiveSucceeded,
    reason: objectiveSucceeded ? "Targeted signed probe succeeded" : "Targeted signed probe rejected",
    sideEffects: {
      responseStatus: result.status,
      errorCode: String((result.body && (result.body.code || result.body.error)) || ""),
      exposureUsed: exposureUsed,
      requestCount: 1
    }
  };
}`;
    }

    case "T6":
      return `async function novelAttack(toolkit) {
  var endpoints = ${JSON.stringify(attack.params.endpoints)};
  var requestCount = 0;
  var extracted = 0;
  var lastStatus = 0;
  var findings = [];
  for (var i = 0; i < endpoints.length; i++) {
    var response = await toolkit.rawGet(endpoints[i]);
    requestCount++;
    lastStatus = response.status;
    if (response.status === 200 && response.body && typeof response.body === "object") {
      var keys = Object.keys(response.body);
      extracted += keys.length;
      findings.push(endpoints[i] + ":[" + keys.join(",") + "]");
    }
  }
  var success = extracted > 3;
  return {
    caught: !success,
    reason: success ? "Public data extraction succeeded" : "Public extraction remained limited",
    sideEffects: { responseStatus: lastStatus, errorCode: "", exposureUsed: 0, requestCount: requestCount, findings: findings.join("; ") }
  };
}`;

    default:
      throw new Error(`Unknown objective: ${attack.objective_id}`);
  }
}

export function makeSkippedAttackOutcome(
  attack: StrikeAttack,
  reason: string,
): AttackOutcome {
  return {
    objective_id: attack.objective_id,
    success: false,
    details: reason,
    exposure_used: 0,
    request_count: 0,
  };
}

export async function executePreparedStrikeAttack(
  attack: PreparedStrikeAttack,
  ctx: StrikeExecutionContext,
): Promise<AttackOutcome> {
  const code = buildStrikeCode(attack, ctx);
  const validation = validateGeneratedCode(code);
  if (!validation.valid) {
    return {
      objective_id: attack.objective_id,
      success: false,
      details: `Strike template failed sandbox validation: ${validation.reason}`,
      exposure_used: 0,
      request_count: 0,
    };
  }

  const sandboxResult = await executeInSandbox(code, {
    targetUrl: ctx.targetUrl,
    restKey: ctx.apiKey,
    timeoutMs: attack.timeoutMs,
    agentIdentity: {
      identityId: ctx.strikeIdentityId,
      publicKey: ctx.strikeKeys.publicKey,
      privateKey: ctx.strikeKeys.privateKey,
    },
    resolverIdentity: {
      identityId: ctx.resolverIdentityId,
      publicKey: ctx.resolverKeys.publicKey,
      privateKey: ctx.resolverKeys.privateKey,
    },
  });

  if (!sandboxResult.success || !sandboxResult.result) {
    return {
      objective_id: attack.objective_id,
      success: false,
      details: sandboxResult.error || "Sandbox execution failed",
      exposure_used: 0,
      request_count: 0,
    };
  }

  const sideEffects = (sandboxResult.result.sideEffects ?? {}) as Record<string, unknown>;
  const responseStatus = typeof sideEffects.responseStatus === "number" ? sideEffects.responseStatus : undefined;
  const errorCode = typeof sideEffects.errorCode === "string" ? sideEffects.errorCode : undefined;
  const exposureUsed = typeof sideEffects.exposureUsed === "number" ? sideEffects.exposureUsed : 0;
  const requestCount = typeof sideEffects.requestCount === "number" ? sideEffects.requestCount : 0;

  return {
    objective_id: attack.objective_id,
    success: !sandboxResult.result.caught,
    error_code: errorCode,
    response_status: responseStatus,
    details: sandboxResult.result.reason,
    exposure_used: exposureUsed,
    request_count: requestCount,
  };
}
