// Entry point — orchestrates full red team run (static, adaptive, or recursive mode)

import "dotenv/config";
import { loadOrCreateKeypair, createIdentity } from "./agentgate-client";
import { runAllAttacksStatic, runSelectedAttacks, printRoundHeader, printRoundSummary } from "./runner";
import { generateReport, type RecursiveRoundData } from "./reporter";
import { buildLibraryMenu, pickAttacks, getDefaultAttacks } from "./strategist";
import type { StrategyResponse } from "./strategist";
import type { AttackResult } from "./log";
import { getAllScenarios } from "./registry";
import { runRecursiveRound } from "./recursive-runner";

async function main() {
  // Parse CLI args
  const targetIndex = process.argv.indexOf("--target");
  const agentGateUrl =
    (targetIndex !== -1 && process.argv[targetIndex + 1]) ||
    process.env.AGENTGATE_URL ||
    "http://127.0.0.1:3000";

  const roundsIndex = process.argv.indexOf("--rounds");
  const roundsArg = roundsIndex !== -1 ? parseInt(process.argv[roundsIndex + 1], 10) : NaN;
  // Cap at 20 rounds to prevent runaway API costs.
  const rounds = Math.min(Number.isFinite(roundsArg) && roundsArg > 0 ? roundsArg : 3, 20);

  const isStatic = process.argv.includes("--static");
  const isRecursive = process.argv.includes("--recursive");

  // --static and --recursive are mutually exclusive
  if (isStatic && isRecursive) {
    console.error("Error: --static and --recursive are mutually exclusive. Use one or the other.");
    process.exit(1);
  }

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
  const scenarioCount = getAllScenarios().length;
  const modeText = isStatic
    ? `Static (${scenarioCount} scenarios)`
    : isRecursive
      ? `Recursive (${rounds} rounds)`
      : `Adaptive (${rounds} rounds)`;

  console.log("");
  console.log("╔═══════════════════════════════════════════╗");
  console.log("║  Agent 004: Red Team Simulator            ║");
  console.log(`║  Mode: ${modeText.padEnd(35)}║`);
  console.log(`║  Target: ${agentGateUrl.padEnd(33)}║`);
  console.log("╚═══════════════════════════════════════════╝");
  console.log("");

  // Create or load identity
  const keys = loadOrCreateKeypair();
  const identityId = await createIdentity(keys);
  console.log(`Identity ready: ${identityId.slice(0, 20)}...`);

  const client = {
    agentGateUrl,
    apiKey: process.env.AGENTGATE_REST_KEY,
    keys,
    identityId,
  };

  let allResults: AttackResult[];
  let allStrategies: StrategyResponse[] | undefined;

  if (isStatic) {
    // Static mode — run all attacks in fixed order (Stage 1 behavior)
    console.log(`Running ${scenarioCount} attack scenarios...\n`);
    allResults = await runAllAttacksStatic(client);

  } else if (isRecursive) {
    // Recursive mode — library attacks + novel attack generation
    allResults = [];
    const allRecursiveData: RecursiveRoundData[] = [];
    let totalNovel = 0;
    let totalNovelExecuted = 0;
    let totalNovelValidated = 0;

    for (let round = 1; round <= rounds; round++) {
      printRoundHeader(round, rounds, "Recursive: library + novel attack generation");

      const roundResult = await runRecursiveRound(
        round, rounds, allResults, client,
        {
          targetUrl: agentGateUrl,
          agentIdentity: {
            identityId,
            publicKey: keys.publicKey,
            privateKey: keys.privateKey,
          },
          restKey: process.env.AGENTGATE_REST_KEY,
        },
      );

      allResults.push(...roundResult.libraryResults, ...roundResult.novelResults);
      allRecursiveData.push({
        roundNumber: round,
        hypotheses: roundResult.hypotheses,
        generationOutcomes: roundResult.generationOutcomes,
        novelResults: roundResult.novelResults,
      });
      totalNovel += roundResult.hypotheses.length;
      totalNovelValidated += roundResult.generationOutcomes.filter((g) => g.success).length;
      totalNovelExecuted += roundResult.novelResults.length;

      // Round summary
      const libCaught = roundResult.libraryResults.filter((r) => r.caught).length;
      const novelCaught = roundResult.novelResults.filter((r) => r.caught).length;
      const allRoundResults = [...roundResult.libraryResults, ...roundResult.novelResults];
      const totalCaught = allRoundResults.filter((r) => r.caught).length;
      const totalUncaught = allRoundResults.filter((r) => !r.caught).length;

      console.log("");
      console.log("───────────────────────────────────────────");
      console.log(`  Round ${round} complete:`);
      console.log(`    Library: ${roundResult.libraryResults.length} attacks, ${libCaught} caught`);
      console.log(`    Novel:   ${roundResult.novelResults.length} executed, ${novelCaught} caught`);
      console.log(`    Total:   ${allRoundResults.length} attacks, ${totalCaught} caught, ${totalUncaught} uncaught`);
      console.log("───────────────────────────────────────────");
    }

    // Generate report with recursive data
    console.log("\nAll rounds complete. Generating report...\n");
    const report = await generateReport(allResults, undefined, allRecursiveData);
    console.log(report);

    // Final recursive summary
    const caught = allResults.filter((r) => r.caught).length;
    const uncaught = allResults.filter((r) => !r.caught).length;
    const libraryTotal = allResults.filter((r) => r.category !== "Novel Attack").length;
    const novelTotal = allResults.filter((r) => r.category === "Novel Attack").length;

    console.log("");
    console.log("════════════════════════════════════════");
    console.log("  RECURSIVE SUMMARY");
    console.log("════════════════════════════════════════");
    console.log(`  Library attacks:     ${libraryTotal}`);
    console.log(`  Novel hypotheses:    ${totalNovel}`);
    console.log(`  Novel validated:     ${totalNovelValidated}`);
    console.log(`  Novel executed:      ${totalNovelExecuted}`);
    console.log(`  Total attacks:       ${allResults.length}`);
    console.log(`  Caught:              ${caught} ✓`);
    console.log(`  Uncaught:            ${uncaught}`);
    console.log("════════════════════════════════════════");
    console.log("");

    process.exit(uncaught > 0 ? 1 : 0);
    return; // unreachable but makes control flow clear

  } else {
    // Adaptive mode — strategist picks attacks each round
    const library = buildLibraryMenu();
    allResults = [];
    allStrategies = [];

    for (let round = 1; round <= rounds; round++) {
      let strategy: StrategyResponse;

      try {
        strategy = await pickAttacks(library, round, rounds, allResults);
      } catch (err) {
        console.log(`\nStrategist API failed: ${err instanceof Error ? err.message : String(err)}`);
        console.log("Falling back to default attack selection.\n");
        strategy = getDefaultAttacks(library, round);
      }

      printRoundHeader(round, rounds, strategy.strategy);

      if (strategy.usedFallback) {
        console.log("  ⚠ Using fallback selection (Claude API unavailable)\n");
      }

      const roundResults = await runSelectedAttacks(strategy.attacks, client, round);
      allResults.push(...roundResults);
      allStrategies.push(strategy);

      printRoundSummary(round, roundResults);
    }
  }

  const caught = allResults.filter((r) => r.caught).length;
  const uncaught = allResults.filter((r) => !r.caught).length;

  // Generate report
  console.log("\nAll attacks complete. Generating report...\n");
  const report = await generateReport(allResults, allStrategies);
  console.log(report);

  // Final summary
  console.log("");
  console.log("════════════════════════════════════════");
  console.log("  SUMMARY");
  console.log("════════════════════════════════════════");
  console.log(`  Total attacks: ${allResults.length}`);
  console.log(`  Caught:        ${caught} ✓`);
  console.log(`  Uncaught:      ${uncaught}`);
  console.log("════════════════════════════════════════");
  console.log("");

  process.exit(uncaught > 0 ? 1 : 0);
}

main();
