// Strike Runner — orchestrates the strike phase with 3-round adaptive loop.
// Loads recon file (or skips for blind), creates identities, executes attacks,
// calculates metrics, and appends results to campaign log.

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { ReconFileSchema, type ReconFile } from "./recon-schema.js";
import { DEFAULT_SLEEPER_IDENTITY_PATH, loadSleeperIdentity } from "./identity-store.js";
import { generateKeypair, createScoutIdentity, type ScoutKeys } from "./scout/scout-client.js";
import { planStrike, getDefaultStrategy, type StrikeStrategy, type AttackOutcome } from "./strike-strategist.js";
import { executePreparedStrikeAttack, makeSkippedAttackOutcome, prepareStrikeAttack } from "./strike-executor.js";
import { appendRun, type CampaignRun } from "./campaign-log.js";

export interface StrikeOptions {
  targetUrl: string;
  apiKey: string;
  reconFile?: string;     // path to recon.json (omit for blind)
  identityFile?: string;
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
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse recon file ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return ReconFileSchema.parse(parsed);
}

export async function runStrike(options: StrikeOptions): Promise<CampaignRun> {
  const {
    targetUrl,
    apiKey,
    identityMode,
    rounds = 3,
    identityFile = DEFAULT_SLEEPER_IDENTITY_PATH,
  } = options;
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
  } else if (identityMode === "same") {
    const savedIdentity = await loadSleeperIdentity(identityFile);
    if (savedIdentity.target_url !== targetUrl) {
      throw new Error(
        `Sleeper identity file target mismatch: expected ${targetUrl}, found ${savedIdentity.target_url}`,
      );
    }
    strikeKeys = savedIdentity.keys;
    strikeIdentityId = savedIdentity.identity_id;
    console.log(`  Reusing sleeper identity from file: ${strikeIdentityId.slice(0, 20)}...`);
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
    if (totalExposure >= BUDGET) {
      console.log(`\n  Budget exhausted (${totalExposure}/${BUDGET}¢). Ending early at round ${round - 1}.`);
      break;
    }
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
      // Enforce budget
      if (totalExposure >= BUDGET) {
        console.log(`    Budget exhausted (${totalExposure}/${BUDGET}¢). Skipping remaining attacks.`);
        break;
      }

      console.log(`    [${attack.objective_id}] ${attack.reasoning.slice(0, 80)}`);
      const prepared = prepareStrikeAttack(attack, BUDGET - totalExposure);
      const outcome = !prepared.ready
        ? makeSkippedAttackOutcome(attack, prepared.reason)
        : await executePreparedStrikeAttack(prepared.attack, {
            targetUrl,
            apiKey,
            strikeKeys,
            strikeIdentityId,
            resolverKeys,
            resolverIdentityId,
          });
      allOutcomes.push(outcome);
      totalProbes += outcome.request_count ?? 0;
      totalExposure += outcome.exposure_used ?? 0;

      if (
        timeToFirstBoundary === 0 &&
        (outcome.success || outcome.response_status === 400 || outcome.response_status === 429)
      ) {
        timeToFirstBoundary = (Date.now() - startTime) / 1000;
      }

      allAttackLogs.push({
        objective_id: attack.objective_id,
        params: prepared.ready
          ? prepared.attack.params
          : { ...attack.params, skip_reason: prepared.reason },
        reasoning: attack.reasoning,
        recon_dependency: attack.recon_dependency,
        success: outcome.success,
        error_code: outcome.error_code,
        response_status: outcome.response_status,
      });

      const status = outcome.success ? "SUCCESS" : outcome.request_count === 0 ? "SKIPPED" : "BLOCKED";
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
