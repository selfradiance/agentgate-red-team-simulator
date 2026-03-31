// Strike Runner — orchestrates the strike phase with 3-round adaptive loop.
// Loads recon file (or skips for blind), creates identities, executes attacks,
// calculates metrics, and appends results to campaign log.

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { ReconFileSchema, type ReconFile } from "./recon-schema.js";
import { generateKeypair, createScoutIdentity, lockBond, executeAction, resolveAction, rawGet, signedPostWithNonce, type ScoutKeys, type ScoutIdentity } from "./scout/scout-client.js";
import { planStrike, getDefaultStrategy, type StrikeStrategy, type StrikeAttack, type AttackOutcome } from "./strike-strategist.js";
import { appendRun, type CampaignRun } from "./campaign-log.js";

export interface StrikeOptions {
  targetUrl: string;
  apiKey: string;
  reconFile?: string;     // path to recon.json (omit for blind)
  identityMode: "same" | "fresh";
  scoutIdentityId?: string; // for "same" mode
  scoutKeys?: ScoutKeys;    // for "same" mode
  rounds?: number;
  campaignLogPath?: string;
}

interface StrikeMetrics {
  success_rate: number;
  cost_effective_exposure: number;
  probe_count: number;
  precision: number;
  recon_dependent_count: number;
  time_to_first_boundary: number;
}

async function loadRecon(path: string): Promise<ReconFile> {
  const raw = await readFile(path, "utf-8");
  const parsed = JSON.parse(raw);
  return ReconFileSchema.parse(parsed);
}

async function executeStrikeAttack(
  attack: StrikeAttack,
  targetUrl: string,
  apiKey: string,
  strikeKeys: ScoutKeys,
  strikeIdentityId: string,
  resolverKeys: ScoutKeys,
  resolverIdentityId: string,
): Promise<AttackOutcome> {
  const startTime = Date.now();

  try {
    switch (attack.objective_id) {
      case "T1": {
        // Rate Limit Bypass — burst execute_bonded_action requests
        const burstCount = (attack.params.burst_count as number) ?? 11;
        const bondResult = await lockBond(targetUrl, apiKey, strikeKeys, strikeIdentityId, 100);
        if (bondResult.status < 200 || bondResult.status >= 300) {
          return { objective_id: "T1", success: false, response_status: bondResult.status, details: "Bond lock failed" };
        }
        const bondId = bondResult.data.bondId as string;
        let successes = 0;
        let lastStatus = 0;
        for (let i = 0; i < burstCount; i++) {
          const r = await executeAction(targetUrl, apiKey, strikeKeys, strikeIdentityId, bondId, 5);
          lastStatus = r.status;
          if (r.status >= 200 && r.status < 300) {
            successes++;
            const actionId = r.data.actionId as string;
            await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
          }
          if (r.status === 429) break;
        }
        const bypassed = successes > 10;
        return { objective_id: "T1", success: bypassed, response_status: lastStatus, details: `${successes}/${burstCount} succeeded. ${bypassed ? "Bypassed rate limit" : "Rate limit held"}` };
      }

      case "T2": {
        // Bond Capacity Overflow
        const bondCents = (attack.params.bond_cents as number) ?? 100;
        const exposureCents = (attack.params.exposure_cents as number) ?? 85;
        const bondResult = await lockBond(targetUrl, apiKey, strikeKeys, strikeIdentityId, bondCents);
        if (bondResult.status < 200 || bondResult.status >= 300) {
          return { objective_id: "T2", success: false, response_status: bondResult.status, details: "Bond lock failed" };
        }
        const bondId = bondResult.data.bondId as string;
        const r = await executeAction(targetUrl, apiKey, strikeKeys, strikeIdentityId, bondId, exposureCents);
        const overflow = r.status >= 200 && r.status < 300;
        if (overflow) {
          const actionId = r.data.actionId as string;
          await resolveAction(targetUrl, apiKey, resolverKeys, resolverIdentityId, actionId);
        }
        return { objective_id: "T2", success: overflow, response_status: r.status, error_code: String(r.data.code ?? ""), details: `Bond ${bondCents}¢, exposure ${exposureCents}¢. ${overflow ? "Overflow succeeded" : "Blocked"}` };
      }

      case "T3": {
        // Tier Cap Evasion — try to lock bond exceeding tier cap
        const bondAmount = (attack.params.bond_cents as number) ?? 500;
        const r = await lockBond(targetUrl, apiKey, strikeKeys, strikeIdentityId, bondAmount);
        const evaded = r.status >= 200 && r.status < 300;
        return { objective_id: "T3", success: evaded, response_status: r.status, details: `Attempted ${bondAmount}¢ bond. ${evaded ? "Tier cap evaded" : "Blocked by tier cap"}` };
      }

      case "T4": {
        // Replay / Nonce Reuse
        const nonce = `strike-replay-${Date.now()}`;
        const body = { identityId: strikeIdentityId, amountCents: 100, currency: "USD", ttlSeconds: 300, reason: "strike" };
        // First request
        await signedPostWithNonce(targetUrl, apiKey, strikeKeys, "/v1/bonds/lock", body, nonce);
        // Wait for TTL if specified
        const waitMs = (attack.params.wait_seconds as number ?? 0) * 1000;
        if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
        // Replay
        const r = await signedPostWithNonce(targetUrl, apiKey, strikeKeys, "/v1/bonds/lock", body, nonce);
        const replayed = r.status >= 200 && r.status < 300;
        return { objective_id: "T4", success: replayed, response_status: r.status, details: `Nonce replay ${replayed ? "succeeded" : "rejected"}. Wait: ${(attack.params.wait_seconds as number) ?? 0}s` };
      }

      case "T5": {
        // Error-Informed Targeted Attack — probe weakest validation
        const endpoint = (attack.params.endpoint as string) ?? "/v1/bonds/lock";
        const payload = (attack.params.payload as Record<string, unknown>) ?? { identityId: strikeIdentityId };
        const r = await lockBond(targetUrl, apiKey, strikeKeys, strikeIdentityId, 100);
        const found = r.status >= 200 && r.status < 300;
        return { objective_id: "T5", success: found, response_status: r.status, details: `Targeted ${endpoint}. ${found ? "Found weakness" : "Validation held"}` };
      }

      case "T6": {
        // Unauthenticated State Extraction
        const endpoints = (attack.params.endpoints as string[]) ?? ["/health", "/v1/stats"];
        let extracted = 0;
        const findings: string[] = [];
        for (const ep of endpoints) {
          const r = await rawGet(targetUrl, ep);
          if (r.status === 200) {
            const keys = Object.keys(r.data);
            extracted += keys.length;
            findings.push(`${ep}: [${keys.join(",")}]`);
          }
        }
        return { objective_id: "T6", success: extracted > 3, response_status: 200, details: `Extracted ${extracted} fields. ${findings.join("; ")}` };
      }

      default:
        return { objective_id: attack.objective_id, success: false, details: `Unknown objective: ${attack.objective_id}` };
    }
  } catch (err) {
    return { objective_id: attack.objective_id, success: false, details: `Error: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function runStrike(options: StrikeOptions): Promise<CampaignRun> {
  const { targetUrl, apiKey, identityMode, rounds = 3 } = options;
  const isBlind = !options.reconFile;

  console.log("\n╔═══════════════════════════════════════════╗");
  console.log("║  Sleeper Agent — Strike Phase             ║");
  console.log(`║  Mode: ${(isBlind ? "blind" : "recon").padEnd(35)}║`);
  console.log(`║  Identity: ${identityMode.padEnd(31)}║`);
  console.log(`║  Target: ${targetUrl.padEnd(33)}║`);
  console.log("╚═══════════════════════════════════════════╝\n");

  // Load recon file if provided
  let recon: ReconFile | null = null;
  if (options.reconFile) {
    if (!existsSync(options.reconFile)) {
      throw new Error(`Recon file not found: ${options.reconFile}`);
    }
    recon = await loadRecon(options.reconFile);
    console.log(`  Recon loaded from: ${options.reconFile}`);
  } else {
    console.log("  Running blind — no recon intelligence.");
  }

  // Create strike identity
  let strikeKeys: ScoutKeys;
  let strikeIdentityId: string;

  if (identityMode === "same" && options.scoutKeys && options.scoutIdentityId) {
    strikeKeys = options.scoutKeys;
    strikeIdentityId = options.scoutIdentityId;
    console.log(`  Reusing scout identity: ${strikeIdentityId.slice(0, 20)}...`);
  } else {
    strikeKeys = generateKeypair();
    strikeIdentityId = await createScoutIdentity(targetUrl, apiKey, strikeKeys);
    console.log(`  Fresh strike identity: ${strikeIdentityId.slice(0, 20)}...`);
  }

  // Create resolver for strike actions
  const resolverKeys = generateKeypair();
  const resolverIdentityId = await createScoutIdentity(targetUrl, apiKey, resolverKeys);
  console.log(`  Strike resolver: ${resolverIdentityId.slice(0, 20)}...`);

  // 3-round adaptive loop
  const allOutcomes: AttackOutcome[] = [];
  const allAttackLogs: CampaignRun["attack_log"] = [];
  let totalExposure = 0;
  let totalProbes = 0;
  const BUDGET = 2000;
  const startTime = Date.now();
  let timeToFirstBoundary = 0;

  for (let round = 1; round <= rounds; round++) {
    console.log(`\n  ── Round ${round}/${rounds} ──`);
    const budgetRemaining = BUDGET - totalExposure;

    let strategy: StrikeStrategy;
    try {
      strategy = await planStrike(round, recon, allOutcomes, budgetRemaining);
    } catch (err) {
      console.log(`  Strategist failed: ${err instanceof Error ? err.message : String(err)}`);
      strategy = getDefaultStrategy(round, isBlind);
    }

    console.log(`  Strategy: ${strategy.strategy}`);
    console.log(`  Attacks: ${strategy.attacks.length}`);

    for (const attack of strategy.attacks) {
      console.log(`    [${attack.objective_id}] ${attack.reasoning.slice(0, 80)}`);
      const outcome = await executeStrikeAttack(
        attack, targetUrl, apiKey, strikeKeys, strikeIdentityId, resolverKeys, resolverIdentityId,
      );
      allOutcomes.push(outcome);
      totalProbes++;

      // Track exposure (rough estimate)
      const exposureEstimate = (attack.params.exposure_cents as number) ?? (attack.params.bond_cents as number) ?? 50;
      totalExposure += exposureEstimate;

      if (outcome.success && timeToFirstBoundary === 0) {
        timeToFirstBoundary = (Date.now() - startTime) / 1000;
      }

      allAttackLogs.push({
        objective_id: attack.objective_id,
        params: attack.params,
        reasoning: attack.reasoning,
        recon_dependency: attack.recon_dependency,
        success: outcome.success,
        error_code: outcome.error_code,
        response_status: outcome.response_status,
      });

      const status = outcome.success ? "SUCCESS" : "BLOCKED";
      console.log(`      → ${status}: ${outcome.details.slice(0, 100)}`);
    }
  }

  // Calculate metrics
  const successCount = allOutcomes.filter((o) => o.success).length;
  const boundaryEngagements = allOutcomes.filter((o) => o.response_status === 429 || o.response_status === 400 || o.success).length;
  const reconDependentCount = allAttackLogs.filter((a) => a.recon_dependency).length;

  const metrics: StrikeMetrics = {
    success_rate: allOutcomes.length > 0 ? successCount / allOutcomes.length : 0,
    cost_effective_exposure: totalExposure,
    probe_count: totalProbes,
    precision: allOutcomes.length > 0 ? boundaryEngagements / allOutcomes.length : 0,
    recon_dependent_count: reconDependentCount,
    time_to_first_boundary: timeToFirstBoundary,
  };

  // Build campaign run
  const run: CampaignRun = {
    run_id: `strike-${identityMode}-${isBlind ? "blind" : "recon"}-${Date.now()}`,
    mode: "strike",
    identity_mode: identityMode,
    recon_mode: isBlind ? "blind" : "recon",
    timestamp: new Date().toISOString(),
    metrics,
    attack_log: allAttackLogs,
  };

  // Append to campaign log
  const logPath = options.campaignLogPath ?? "temporal-campaign-log.json";
  await appendRun(logPath, run);
  console.log(`\n  Results appended to: ${logPath}`);

  // Print summary
  console.log("\n  ════════════════════════════════════════");
  console.log("  STRIKE SUMMARY");
  console.log("  ════════════════════════════════════════");
  console.log(`  Success rate:        ${(metrics.success_rate * 100).toFixed(1)}%`);
  console.log(`  Cost (exposure):     ${metrics.cost_effective_exposure}¢`);
  console.log(`  Total probes:        ${metrics.probe_count}`);
  console.log(`  Precision:           ${(metrics.precision * 100).toFixed(1)}%`);
  console.log(`  Recon-dependent:     ${metrics.recon_dependent_count}`);
  console.log(`  Time to boundary:    ${metrics.time_to_first_boundary.toFixed(1)}s`);
  console.log("  ════════════════════════════════════════\n");

  return run;
}
