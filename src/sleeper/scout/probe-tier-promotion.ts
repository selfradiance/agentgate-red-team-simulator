// S3: Tier Promotion Observation
// Executes 5 qualifying actions (≥83¢ declared, resolved by Resolver as success).
// Checks reputation via GET /v1/identities/:id after each resolution.
// Records when/whether tier changes.

import type { ReconFile } from "../recon-schema.js";
import { lockBond, executeAction, resolveAction, rawGet, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "tier_advancement_farming";

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
  resolverKeys: ScoutKeys,
  resolverIdentityId: string,
): Promise<ReconFile["tier_promotion"]> {
  const QUALIFYING_ACTIONS = 5;
  let qualifyingSuccesses = 0;
  let tierChangedAt: number | null = null;
  let initialTier: number | null = null;
  let currentTier: number | null = null;
  let tier2BondCap: number | null = null;

  // Check initial reputation
  const initialRep = await rawGet(targetUrl, `/v1/identities/${scoutIdentityId}`);
  if (initialRep.status === 200) {
    initialTier = typeof initialRep.data.tier === "number" ? initialRep.data.tier : null;
    currentTier = initialTier;
  }

  for (let i = 0; i < QUALIFYING_ACTIONS; i++) {
    // Lock bond
    const bondResult = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 100);
    if (bondResult.status !== 200 && bondResult.status !== 201) continue;
    const bondId = bondResult.data.bondId as string;

    // Execute at ≥83¢ exposure
    const actionResult = await executeAction(targetUrl, apiKey, scoutKeys, scoutIdentityId, bondId, 83);
    if (actionResult.status < 200 || actionResult.status >= 300) continue;
    const actionId = actionResult.data.actionId as string;

    // Resolve as success
    await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
    qualifyingSuccesses++;

    // Check reputation after resolution
    const rep = await rawGet(targetUrl, `/v1/identities/${scoutIdentityId}`);
    if (rep.status === 200) {
      const newTier = typeof rep.data.tier === "number" ? rep.data.tier : null;
      if (newTier !== null && currentTier !== null && newTier > currentTier) {
        tierChangedAt = qualifyingSuccesses;
        currentTier = newTier;
      } else if (newTier !== null) {
        currentTier = newTier;
      }
    }
  }

  // After qualifying actions, try a 500¢ bond lock to test tier 2 cap
  if (currentTier !== null && currentTier >= 2) {
    const bigBond = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 500);
    if (bigBond.status >= 200 && bigBond.status < 300) {
      tier2BondCap = 500;
    }
  } else {
    // Try anyway to see what happens
    const bigBond = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, 500);
    if (bigBond.status >= 200 && bigBond.status < 300) {
      tier2BondCap = 500;
    }
  }

  const promotionTrigger = tierChangedAt
    ? `tier_promoted_after_${tierChangedAt}_successes`
    : `no_promotion_after_${qualifyingSuccesses}_successes_1_resolver`;

  return {
    qualifying_successes_to_tier_2: tierChangedAt ?? qualifyingSuccesses,
    distinct_resolvers_required: tierChangedAt ? 1 : 2,
    tier_2_bond_cap: tier2BondCap,
    promotion_trigger: promotionTrigger,
  };
}
