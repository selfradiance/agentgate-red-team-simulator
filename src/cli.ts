// Entry point — orchestrates full red team run

import "dotenv/config";
import { loadOrCreateKeypair, createIdentity } from "./agentgate-client";
import { runAttacks } from "./runner";
import { generateReport } from "./reporter";

async function main() {
  // Parse --target from CLI args
  const targetIndex = process.argv.indexOf("--target");
  const agentGateUrl =
    (targetIndex !== -1 && process.argv[targetIndex + 1]) ||
    process.env.AGENTGATE_URL ||
    "http://127.0.0.1:3000";

  // Verify required env vars
  if (!process.env.AGENTGATE_REST_KEY) {
    console.error("Error: AGENTGATE_REST_KEY not set in environment. Add it to .env or export it.");
    process.exit(1);
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("Error: ANTHROPIC_API_KEY not set in environment. Add it to .env or export it.");
    process.exit(1);
  }

  // Startup banner
  console.log("");
  console.log("╔══════════════════════════════════════╗");
  console.log("║  Agent 004: Red Team Simulator       ║");
  console.log(`║  Target: ${agentGateUrl.padEnd(28)}║`);
  console.log("╚══════════════════════════════════════╝");
  console.log("");

  // Create or load identity
  const keys = loadOrCreateKeypair();
  const identityId = await createIdentity(keys);
  console.log(`Identity ready: ${identityId.slice(0, 20)}...`);
  console.log("Running 15 attack scenarios...\n");

  // Run all attacks
  const log = await runAttacks({
    agentGateUrl,
    apiKey: process.env.AGENTGATE_REST_KEY,
    keys,
    identityId,
  });

  const results = log.getResults();
  const caught = results.filter((r) => r.caught).length;
  const uncaught = results.filter((r) => !r.caught).length;

  // Generate report
  console.log("\nAll attacks complete. Generating report...\n");
  const report = await generateReport(results);
  console.log(report);

  // Final summary
  console.log("");
  console.log("════════════════════════════════════════");
  console.log("  SUMMARY");
  console.log("════════════════════════════════════════");
  console.log(`  Total attacks: ${results.length}`);
  console.log(`  Caught:        ${caught} ✓`);
  console.log(`  Uncaught:      ${uncaught}`);
  console.log("════════════════════════════════════════");
  console.log("");

  process.exit(uncaught > 0 ? 1 : 0);
}

main();
