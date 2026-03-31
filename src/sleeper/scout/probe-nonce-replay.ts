// S5: Nonce and Replay Behavior
// Tests duplicate nonce rejection and nonce TTL cleanup.
// Sequence: valid request → duplicate (expect 409) → wait 6 min → retry same nonce.
// Only probe with time dependency.

import type { ReconFile } from "../recon-schema.js";
import { executeAction, lockBond, resolveAction, signedPostWithNonce, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "replay_timing_window";

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
  resolverKeys: ScoutKeys,
  resolverIdentityId: string,
  skipNonceTtl: boolean = false,
): Promise<ReconFile["nonce_behavior"]> {
  const testNonce = `scout-nonce-replay-${Date.now()}`;
  const bond = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 100, 900, "nonce-probe");
  if (bond.status < 200 || bond.status >= 300) {
    return {
      duplicate_error_code: String(bond.data.code ?? bond.data.error ?? "BOND_LOCK_FAILED"),
      ttl_seconds: 300,
      nonce_reuse_after_ttl: false,
    };
  }

  // Step 1: Send valid action request with known nonce.
  const body = {
    identityId: scoutIdentityId,
    bondId: bond.data.bondId,
    actionType: "data_retrieval",
    payload: { type: "nonce-probe" },
    exposure_cents: 5,
  };

  const r1 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/actions/execute", body, testNonce);
  const firstSucceeded = r1.status >= 200 && r1.status < 300;
  if (firstSucceeded && typeof r1.data.actionId === "string") {
    await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, r1.data.actionId);
  }

  // Step 2: Send duplicate with same nonce — expect 409
  const r2 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/actions/execute", body, testNonce);
  const duplicateErrorCode = String(r2.data.code ?? r2.data.error ?? "UNKNOWN");
  const duplicateRejected = r2.status === 409;

  // Step 3: Wait 6 minutes (past 5-minute TTL + cleanup cycle)
  let nonceReuseAfterTtl = false;
  if (!skipNonceTtl) {
    console.log("    S5: Waiting 6 minutes for nonce TTL to expire...");
    await new Promise((resolve) => setTimeout(resolve, 6 * 60 * 1000));

    // Retry with same nonce
    const r3 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/actions/execute", body, testNonce);
    nonceReuseAfterTtl = r3.status >= 200 && r3.status < 300;
    if (nonceReuseAfterTtl && typeof r3.data.actionId === "string") {
      await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, r3.data.actionId);
    }
  }

  return {
    duplicate_error_code: duplicateRejected ? duplicateErrorCode : `not_409_got_${r2.status}`,
    ttl_seconds: 300,
    nonce_reuse_after_ttl: nonceReuseAfterTtl,
  };
}
