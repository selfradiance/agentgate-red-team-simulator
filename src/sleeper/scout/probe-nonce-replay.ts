// S5: Nonce and Replay Behavior
// Tests duplicate nonce rejection and nonce TTL cleanup.
// Sequence: valid request → duplicate (expect 409) → wait 6 min → retry same nonce.
// Only probe with time dependency.

import type { ReconFile } from "../recon-schema.js";
import { signedPostWithNonce, lockBond, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "replay_timing_window";

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
  skipNonceTtl: boolean = false,
): Promise<ReconFile["nonce_behavior"]> {
  const testNonce = `scout-nonce-replay-${Date.now()}`;

  // Step 1: Send valid request with known nonce
  const body = {
    identityId: scoutIdentityId,
    amountCents: 100,
    currency: "USD",
    ttlSeconds: 300,
    reason: "nonce-probe",
  };

  const r1 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", body, testNonce);
  const firstSucceeded = r1.status >= 200 && r1.status < 300;

  // Step 2: Send duplicate with same nonce — expect 409
  const r2 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", body, testNonce);
  const duplicateErrorCode = String(r2.data.code ?? r2.data.error ?? "UNKNOWN");
  const duplicateRejected = r2.status === 409;

  // Step 3: Wait 6 minutes (past 5-minute TTL + cleanup cycle)
  let nonceReuseAfterTtl = false;
  if (!skipNonceTtl) {
    console.log("    S5: Waiting 6 minutes for nonce TTL to expire...");
    await new Promise((resolve) => setTimeout(resolve, 6 * 60 * 1000));

    // Retry with same nonce
    const r3 = await signedPostWithNonce(targetUrl, apiKey, scoutKeys, "/v1/bonds/lock", body, testNonce);
    nonceReuseAfterTtl = r3.status >= 200 && r3.status < 300;
  }

  return {
    duplicate_error_code: duplicateRejected ? duplicateErrorCode : `not_409_got_${r2.status}`,
    ttl_seconds: 300,
    nonce_reuse_after_ttl: nonceReuseAfterTtl,
  };
}
