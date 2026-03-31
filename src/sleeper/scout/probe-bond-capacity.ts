// S2: Bond Capacity Boundaries
// Locks bonds at specific amounts and executes at various exposure levels
// to determine the risk multiplier and capacity boundaries.
// Needs Resolver Identity to resolve successful actions.

import type { ReconFile } from "../recon-schema.js";
import { lockBond, executeAction, resolveAction, type ScoutKeys } from "./scout-client.js";

export const hypothesis = "bond_capacity_calibration";

interface ProbeResult {
  bondCents: number;
  exposureCents: number;
  succeeded: boolean;
  errorCode?: string;
}

export async function probe(
  targetUrl: string,
  apiKey: string,
  scoutKeys: ScoutKeys,
  scoutIdentityId: string,
  resolverKeys: ScoutKeys,
  resolverIdentityId: string,
): Promise<ReconFile["bond_capacity"]> {
  const probes: { bondCents: number; exposureCents: number; expectSuccess: boolean }[] = [
    { bondCents: 100, exposureCents: 83, expectSuccess: true },
    { bondCents: 100, exposureCents: 84, expectSuccess: false },
    { bondCents: 50, exposureCents: 41, expectSuccess: true },
    { bondCents: 50, exposureCents: 42, expectSuccess: false },
  ];

  const results: ProbeResult[] = [];
  let boundaryErrorCode = "UNKNOWN";

  for (const p of probes) {
    // Lock bond
    const bondResult = await lockBond(targetUrl, apiKey, scoutKeys, scoutIdentityId, p.bondCents);
    if (bondResult.status !== 200 && bondResult.status !== 201) {
      results.push({ bondCents: p.bondCents, exposureCents: p.exposureCents, succeeded: false, errorCode: String(bondResult.data.code ?? bondResult.data.error ?? "BOND_LOCK_FAILED") });
      continue;
    }

    const bondId = bondResult.data.bondId as string;

    // Execute action
    const actionResult = await executeAction(targetUrl, apiKey, scoutKeys, scoutIdentityId, bondId, p.exposureCents);

    if (actionResult.status >= 200 && actionResult.status < 300) {
      // Action succeeded — resolve it via Resolver
      const actionId = actionResult.data.actionId as string;
      await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
      results.push({ bondCents: p.bondCents, exposureCents: p.exposureCents, succeeded: true });
    } else {
      const errorCode = String(actionResult.data.code ?? actionResult.data.error ?? "UNKNOWN");
      results.push({ bondCents: p.bondCents, exposureCents: p.exposureCents, succeeded: false, errorCode });
      if (!p.expectSuccess) {
        boundaryErrorCode = errorCode;
      }
    }
  }

  // Derive risk multiplier from results
  // 100¢ bond, 83¢ succeeds, 84¢ fails → max is 83/100 = 0.83 → multiplier = 1/0.83 ≈ 1.2
  const r100_83 = results.find((r) => r.bondCents === 100 && r.exposureCents === 83);
  const r100_84 = results.find((r) => r.bondCents === 100 && r.exposureCents === 84);

  let riskMultiplier = 1.2; // default
  let maxDeclared = 83;
  if (r100_83?.succeeded && r100_84 && !r100_84.succeeded) {
    riskMultiplier = 100 / 83;
    maxDeclared = 83;
  } else if (r100_84?.succeeded) {
    riskMultiplier = 100 / 84;
    maxDeclared = 84;
  }

  return {
    risk_multiplier: Math.round(riskMultiplier * 100) / 100,
    tier_1_cap: 100,
    max_declared_at_tier_1: maxDeclared,
    boundary_error_code: boundaryErrorCode,
  };
}
