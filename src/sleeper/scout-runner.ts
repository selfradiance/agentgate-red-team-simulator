// Scout Runner — orchestrates all 7 probes in sequence, writes recon.json

import { writeFile } from "node:fs/promises";
import { ReconFileSchema, RECON_VERSION, type ReconFile } from "./recon-schema.js";
import { generateKeypair, createScoutIdentity, type ScoutIdentity } from "./scout/scout-client.js";
import { probe as probeEndpointShape } from "./scout/probe-endpoint-shape.js";
import { probe as probeErrorLeakage } from "./scout/probe-error-leakage.js";
import { probe as probeTimestampWindow } from "./scout/probe-timestamp-window.js";
import { probe as probeBondCapacity } from "./scout/probe-bond-capacity.js";
import { probe as probeRateLimit } from "./scout/probe-rate-limit.js";
import { probe as probeTierPromotion } from "./scout/probe-tier-promotion.js";
import { probe as probeNonceReplay } from "./scout/probe-nonce-replay.js";

export interface ScoutOptions {
  targetUrl: string;
  apiKey: string;
  skipNonceTtl?: boolean;
  outputPath?: string;
}

export async function runScout(options: ScoutOptions): Promise<ReconFile> {
  const { targetUrl, apiKey, skipNonceTtl = false, outputPath = "recon.json" } = options;

  console.log("\n╔═══════════════════════════════════════════╗");
  console.log("║  Sleeper Agent — Scout Phase              ║");
  console.log(`║  Target: ${targetUrl.padEnd(33)}║`);
  console.log("╚═══════════════════════════════════════════╝\n");

  // Step 1: Create Scout Identity
  console.log("  Creating Scout Identity...");
  const scoutKeys = generateKeypair();
  const scoutIdentityId = await createScoutIdentity(targetUrl, apiKey, scoutKeys);
  console.log(`  Scout Identity: ${scoutIdentityId.slice(0, 20)}...`);

  // Step 2: Create Resolver Identity
  console.log("  Creating Resolver Identity...");
  const resolverKeys = generateKeypair();
  const resolverIdentityId = await createScoutIdentity(targetUrl, apiKey, resolverKeys);
  console.log(`  Resolver Identity: ${resolverIdentityId.slice(0, 20)}...`);

  const recon: Partial<ReconFile> = {
    version: RECON_VERSION,
    scout_identity_id: scoutIdentityId,
    resolver_identity_id: resolverIdentityId,
    target_url: targetUrl,
    created_at: new Date().toISOString(),
  };

  // Step 3: S6 — Endpoint Shape (no dependencies)
  console.log("\n  ── S6: Endpoint Shape Discovery ──");
  try {
    recon.endpoint_shape = await probeEndpointShape(targetUrl, scoutIdentityId);
    console.log(`    Found ${recon.endpoint_shape?.endpoints.length} endpoints`);
  } catch (err) {
    console.log(`    S6 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 4: S4 — Error Leakage (no dependencies)
  console.log("\n  ── S4: Error Message Leakage ──");
  try {
    recon.error_surface = await probeErrorLeakage(targetUrl, apiKey, scoutKeys, scoutIdentityId);
    const leaks = recon.error_surface?.errors.filter((e) => e.leaks_internal_info).length ?? 0;
    console.log(`    Collected ${recon.error_surface?.errors.length} error responses, ${leaks} leak internal info`);
  } catch (err) {
    console.log(`    S4 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 5: S7 — Timestamp Window (no dependencies)
  console.log("\n  ── S7: Timestamp Window Boundary ──");
  try {
    recon.timestamp_window = await probeTimestampWindow(targetUrl, apiKey, scoutKeys, scoutIdentityId);
    console.log(`    Past limit: ${recon.timestamp_window?.past_limit_seconds}s, Future limit: ${recon.timestamp_window?.future_limit_seconds}s`);
  } catch (err) {
    console.log(`    S7 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 6: S2 — Bond Capacity (needs Resolver)
  console.log("\n  ── S2: Bond Capacity Boundaries ──");
  try {
    recon.bond_capacity = await probeBondCapacity(targetUrl, apiKey, scoutKeys, scoutIdentityId, resolverKeys, resolverIdentityId);
    console.log(`    Multiplier: ${recon.bond_capacity?.risk_multiplier}, Max declared at Tier 1: ${recon.bond_capacity?.max_declared_at_tier_1}¢`);
  } catch (err) {
    console.log(`    S2 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 7: S1 — Rate Limit (needs Resolver)
  console.log("\n  ── S1: Rate Limit Boundary ──");
  try {
    recon.rate_limit = await probeRateLimit(targetUrl, apiKey, scoutKeys, scoutIdentityId, resolverKeys, resolverIdentityId);
    console.log(`    Max executes before 429: ${recon.rate_limit?.max_executes_before_429}, Recovery: ${recon.rate_limit?.recovery_observed}`);
  } catch (err) {
    console.log(`    S1 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 8: S3 — Tier Promotion (needs Resolver)
  console.log("\n  ── S3: Tier Promotion Observation ──");
  try {
    recon.tier_promotion = await probeTierPromotion(targetUrl, apiKey, scoutKeys, scoutIdentityId, resolverKeys, resolverIdentityId);
    console.log(`    Promotion trigger: ${recon.tier_promotion?.promotion_trigger}`);
  } catch (err) {
    console.log(`    S3 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 9: S5 — Nonce/Replay (needs Resolver, has 6-min wait — run last)
  console.log("\n  ── S5: Nonce and Replay Behavior ──");
  try {
    recon.nonce_behavior = await probeNonceReplay(targetUrl, apiKey, scoutKeys, scoutIdentityId, skipNonceTtl);
    console.log(`    Duplicate error: ${recon.nonce_behavior?.duplicate_error_code}, Reuse after TTL: ${recon.nonce_behavior?.nonce_reuse_after_ttl}`);
  } catch (err) {
    console.log(`    S5 failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 10: Validate combined results
  const validated = ReconFileSchema.safeParse(recon);
  if (!validated.success) {
    console.log("\n  WARNING: Recon file failed schema validation.");
    console.log(`  Errors: ${JSON.stringify(validated.error.issues, null, 2)}`);
  }

  // Step 11: Write recon.json
  const reconFile = recon as ReconFile;
  await writeFile(outputPath, JSON.stringify(reconFile, null, 2), "utf-8");
  console.log(`\n  Recon file written to: ${outputPath}`);

  // Step 12: Print summary
  const sections = [
    recon.rate_limit ? "S1:rate_limit" : null,
    recon.bond_capacity ? "S2:bond_capacity" : null,
    recon.tier_promotion ? "S3:tier_promotion" : null,
    recon.error_surface ? "S4:error_surface" : null,
    recon.nonce_behavior ? "S5:nonce_behavior" : null,
    recon.endpoint_shape ? "S6:endpoint_shape" : null,
    recon.timestamp_window ? "S7:timestamp_window" : null,
  ].filter(Boolean);

  console.log("\n  ════════════════════════════════════════");
  console.log("  SCOUT SUMMARY");
  console.log("  ════════════════════════════════════════");
  console.log(`  Completed probes: ${sections.length}/7`);
  console.log(`  Sections: ${sections.join(", ")}`);
  console.log(`  Output: ${outputPath}`);
  console.log("  ════════════════════════════════════════\n");

  return reconFile;
}
