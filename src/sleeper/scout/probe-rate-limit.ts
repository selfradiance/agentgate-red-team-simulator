// S1: Rate Limit Boundary
// Sends rapid execute_bonded_action requests, counts successes before 429.
// All actions resolved as "success" by Resolver Identity.
// Max 15 requests.

import type { ReconFile } from "../recon-schema.js";
import { lockBond, executeAction, resolveAction, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "rate_limit_exhaustion";

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
  resolverKeys: ScoutKeys,
  resolverIdentityId: string,
): Promise<ReconFile["rate_limit"]> {
  const MAX_REQUESTS = 15;
  let successesBeforeLimit = 0;
  let hitRateLimit = false;
  let recoveryObserved = false;
  const startTime = Date.now();

  // Lock a bond for the burst
  const bondResult = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 100);
  if (bondResult.status !== 200 && bondResult.status !== 201) {
    return { max_executes_before_429: 0, window_seconds: 60, recovery_observed: false };
  }
  const bondId = bondResult.data.bondId as string;

  // Send rapid requests
  for (let i = 0; i < MAX_REQUESTS; i++) {
    const result = await executeAction(targetUrl, apiKey, scoutKeys, scoutIdentityId, bondId, 10);

    if (result.status === 429) {
      hitRateLimit = true;
      break;
    }

    if (result.status >= 200 && result.status < 300) {
      successesBeforeLimit++;
      // Resolve action so scout stays compliant
      const actionId = result.data.actionId as string;
      await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
    }
  }

  const windowSeconds = Math.ceil((Date.now() - startTime) / 1000);

  // If we hit rate limit, wait for the window to clear and retry once
  if (hitRateLimit) {
    // Wait up to 65 seconds for rate limit window to clear
    const waitMs = Math.max(0, 61_000 - (Date.now() - startTime));
    if (waitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    // Lock a new bond for the recovery test
    const recoveryBond = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 100);
    if (recoveryBond.status >= 200 && recoveryBond.status < 300) {
      const recoveryBondId = recoveryBond.data.bondId as string;
      const recoveryResult = await executeAction(targetUrl, apiKey, scoutKeys, scoutIdentityId, recoveryBondId, 10);
      if (recoveryResult.status >= 200 && recoveryResult.status < 300) {
        recoveryObserved = true;
        const actionId = recoveryResult.data.actionId as string;
        await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
      }
    }
  }

  return {
    max_executes_before_429: successesBeforeLimit,
    window_seconds: hitRateLimit ? windowSeconds : 60,
    recovery_observed: recoveryObserved,
  };
}
