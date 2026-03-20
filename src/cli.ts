// Entry point — orchestrates full red team run (static, adaptive, recursive, or team mode)

import "dotenv/config";
import { loadOrCreateKeypair, createIdentity } from "./agentgate-client";
import { runAllAttacksStatic, runSelectedAttacks, printRoundHeader, printRoundSummary, runPersonaAssignments, runCoordinatedOps, type CoordinatedOpResult } from "./runner";
import { generateReport, type RecursiveRoundData, type TeamRoundData } from "./reporter";
import { buildLibraryMenu, pickAttacks, getDefaultAttacks, pickTeamAttacks, getDefaultTeamAttacks } from "./strategist";
import type { StrategyResponse } from "./strategist";
import type { AttackResult } from "./log";
import type { GenerationResult } from "./generator";
import { generateAttack, type PersonaContext } from "./generator";
import { getAllScenarios, getScenario } from "./registry";
import { runRecursiveRound } from "./recursive-runner";
import { initializeTeam, ALL_PERSONAS, type PersonaIdentity } from "./personas";
import { analyzeTeamResults } from "./reasoner";
import { executeInSandbox } from "./sandbox/executor";

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
  const isTeam = process.argv.includes("--team");
  const isFreshTeam = process.argv.includes("--fresh-team");

  // --team implies --recursive
  const isRecursiveEffective = isRecursive || isTeam;

  // Mutual exclusivity checks
  if (isStatic && isRecursiveEffective) {
    console.error("Error: --static and --recursive/--team are mutually exclusive. Use one or the other.");
    process.exit(1);
  }
  if (isStatic && isTeam) {
    console.error("Error: --static and --team are mutually exclusive.");
    process.exit(1);
  }
  if (isFreshTeam && !isTeam) {
    console.error("Error: --fresh-team requires --team.");
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
    : isTeam
      ? `Team (${rounds} rounds, 3 personas)`
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

  // Create or load primary identity (used by all non-team modes)
  const keys = loadOrCreateKeypair();
  const identityId = await createIdentity(keys);
  console.log(`Identity ready: ${identityId.slice(0, 20)}...`);

  const client = {
    agentGateUrl,
    apiKey: process.env.AGENTGATE_REST_KEY,
    keys,
    identityId,
  };

  // Create team identities if --team mode
  let team: PersonaIdentity[] | undefined;
  if (isTeam) {
    console.log("");
    console.log("Initializing team personas...");
    if (isFreshTeam) {
      console.log("  --fresh-team: deleting existing persona identities");
    }
    team = await initializeTeam(agentGateUrl, process.env.AGENTGATE_REST_KEY, isFreshTeam);
    for (const persona of team) {
      console.log(`  ${persona.config.displayName} (${persona.config.specialty}): ${persona.identityId.slice(0, 20)}... [${persona.config.bondBudgetCents}¢ budget]`);
    }
    console.log("");
  }

  let allResults: AttackResult[];
  let allStrategies: StrategyResponse[] | undefined;

  if (isStatic) {
    // Static mode — run all attacks in fixed order (Stage 1 behavior)
    console.log(`Running ${scenarioCount} attack scenarios...\n`);
    allResults = await runAllAttacksStatic(client);

  } else if (isTeam) {
    // Team mode — multi-identity coordinated pressure (Stage 4)
    const library = buildLibraryMenu();
    allResults = [];
    const allTeamData: TeamRoundData[] = [];
    const perPersonaAccum = new Map<string, AttackResult[]>();
    for (const p of team!) perPersonaAccum.set(p.config.name, []);
    let totalNovel = 0;
    let totalNovelExecuted = 0;
    let totalNovelValidated = 0;
    let totalCoordOps = 0;

    for (let round = 1; round <= rounds; round++) {
      printRoundHeader(round, rounds, "Team: multi-identity coordinated pressure");

      // Step A: Strategist assigns attacks to personas + coordinated ops
      let teamStrategy;
      try {
        teamStrategy = await pickTeamAttacks(library, round, rounds, team!, perPersonaAccum);
      } catch (err) {
        console.log(`  Strategist API failed: ${err instanceof Error ? err.message : String(err)}`);
        console.log("  Falling back to default team attack selection.\n");
        teamStrategy = getDefaultTeamAttacks(library, round, team!);
      }

      console.log(`  Strategy: ${teamStrategy.strategy}`);
      if (teamStrategy.usedFallback) {
        console.log("  ⚠ Using fallback selection (Claude API unavailable)\n");
      }

      // Step B: Run per-persona independent assignments
      console.log("\n  ── Per-Persona Assignments ──");
      const personaResults = await runPersonaAssignments(
        teamStrategy.assignments, team!, agentGateUrl, process.env.AGENTGATE_REST_KEY, round,
      );

      // Accumulate per-persona results
      const roundPerPersona = new Map<string, AttackResult[]>();
      const roundLibraryResults: AttackResult[] = [];
      for (const pr of personaResults) {
        roundPerPersona.set(pr.persona, pr.results);
        const accum = perPersonaAccum.get(pr.persona) || [];
        accum.push(...pr.results);
        perPersonaAccum.set(pr.persona, accum);
        roundLibraryResults.push(...pr.results);
      }

      // Step C: Run coordinated operations
      let coordOpResults: CoordinatedOpResult[] = [];
      if (teamStrategy.coordinatedOps.length > 0) {
        console.log("\n  ── Coordinated Operations ──");
        coordOpResults = await runCoordinatedOps(
          teamStrategy.coordinatedOps, team!, agentGateUrl, process.env.AGENTGATE_REST_KEY, round,
        );
        totalCoordOps += coordOpResults.length;

        // Add coord op results to per-persona accumulators and library results
        for (const cor of coordOpResults) {
          roundLibraryResults.push(...cor.results);
          // Attribute to first persona in the op for accumulation
          if (cor.op.personas.length > 0) {
            const accum = perPersonaAccum.get(cor.op.personas[0]) || [];
            accum.push(...cor.results);
            perPersonaAccum.set(cor.op.personas[0], accum);
          }
        }
      }

      // Step D: Reasoner analyzes per-persona results
      console.log("\n  ── Reasoner Analysis ──\n");
      let reasonerOutput;
      try {
        reasonerOutput = await analyzeTeamResults(perPersonaAccum, round);
      } catch (err) {
        console.log(`  Reasoner failed: ${err instanceof Error ? err.message : String(err)}`);
        reasonerOutput = { analysis: "Reasoner unavailable", hypotheses: [] };
      }

      console.log(`  Analysis: ${reasonerOutput.analysis.slice(0, 200)}${reasonerOutput.analysis.length > 200 ? "..." : ""}`);
      console.log(`  Hypotheses: ${reasonerOutput.hypotheses.length}`);
      for (const h of reasonerOutput.hypotheses) {
        const personaTag = h.targetPersona ? ` [${h.targetPersona}]` : "";
        console.log(`    [${h.id}]${personaTag} ${h.description.slice(0, 80)}${h.description.length > 80 ? "..." : ""} (${h.confidence})`);
      }

      // Step E: Generator produces persona-targeted novel attacks
      console.log("\n  ── Novel Attacks ──\n");
      const novelResults: AttackResult[] = [];
      const generationOutcomes: GenerationResult[] = [];
      const noveltyRegistry = new Map(getAllScenarios().map((s) => [s.id, { name: s.name, description: s.description }]));

      for (const hypothesis of reasonerOutput.hypotheses) {
        console.log(`  Generating attack for: ${hypothesis.id}${hypothesis.targetPersona ? ` [${hypothesis.targetPersona}]` : ""}...`);

        // Build narrow persona context if targeted
        let personaCtx: PersonaContext | undefined;
        let targetPersonaIdentity: PersonaIdentity | undefined;
        if (hypothesis.targetPersona && team) {
          targetPersonaIdentity = team.find((p) => p.config.name === hypothesis.targetPersona);
          if (targetPersonaIdentity) {
            const priorResults = perPersonaAccum.get(hypothesis.targetPersona) || [];
            const lastFinding = priorResults.length > 0
              ? `${priorResults[priorResults.length - 1].scenarioName}: ${priorResults[priorResults.length - 1].details.slice(0, 100)}`
              : undefined;
            personaCtx = {
              name: targetPersonaIdentity.config.name,
              specialty: targetPersonaIdentity.config.specialty,
              attackFamilies: targetPersonaIdentity.config.attackFamilies,
              priorFinding: lastFinding,
              objective: hypothesis.description,
            };
          }
        }

        let genResult: GenerationResult;
        try {
          genResult = await generateAttack(hypothesis, noveltyRegistry, personaCtx);
        } catch (err) {
          console.log(`    Generation failed: ${err instanceof Error ? err.message : String(err)}`);
          genResult = {
            success: false,
            failure: { hypothesis, reason: `Generation error: ${err instanceof Error ? err.message : String(err)}` },
          };
        }
        generationOutcomes.push(genResult);

        if (!genResult.success) {
          console.log(`    ✗ Generation failed: ${genResult.failure.reason}`);
          continue;
        }

        console.log("");
        console.log(`  ═══ NOVEL ATTACK: ${hypothesis.id}${hypothesis.targetPersona ? ` [${hypothesis.targetPersona}]` : ""} ═══`);
        console.log(genResult.attack.code);
        console.log("  ═══════════════════════════════");
        console.log("");

        // Execute in sandbox with persona identity if targeted
        const execIdentity = targetPersonaIdentity || { identityId, keys, config: { name: "primary" } as any };
        console.log(`    Executing in sandbox as ${hypothesis.targetPersona || "primary"}...`);
        const sandboxResult = await executeInSandbox(genResult.attack.code, {
          targetUrl: agentGateUrl,
          agentIdentity: {
            identityId: execIdentity.identityId,
            publicKey: execIdentity.keys.publicKey,
            privateKey: execIdentity.keys.privateKey,
          },
          restKey: process.env.AGENTGATE_REST_KEY,
          personaName: hypothesis.targetPersona,
        });

        // Convert to AttackResult
        const attackResult: AttackResult = sandboxResult.success && sandboxResult.result
          ? {
              scenarioId: hypothesis.id,
              scenarioName: hypothesis.description,
              category: "Novel Attack",
              expectedOutcome: "Probing: " + hypothesis.targetDefense,
              actualOutcome: sandboxResult.result.caught
                ? `CAUGHT: ${sandboxResult.result.reason}`
                : `UNCAUGHT: ${sandboxResult.result.reason}`,
              caught: sandboxResult.result.caught,
              details: `Persona: ${hypothesis.targetPersona || "primary"}. Hypothesis: ${hypothesis.rationale}. Result: ${sandboxResult.result.reason}`,
              sideEffects: {
                additionalNotes: `Sandbox logs: ${sandboxResult.logs.join("; ")}. Duration: ${sandboxResult.durationMs}ms`,
                ...(sandboxResult.result.sideEffects || {}),
              },
            }
          : {
              scenarioId: hypothesis.id,
              scenarioName: hypothesis.description,
              category: "Novel Attack",
              expectedOutcome: "Probing: " + hypothesis.targetDefense,
              actualOutcome: sandboxResult.timedOut
                ? "TIMEOUT: sandbox execution exceeded 15s"
                : `ERROR: ${sandboxResult.error || "Unknown sandbox error"}`,
              caught: true,
              details: `Persona: ${hypothesis.targetPersona || "primary"}. Sandbox ${sandboxResult.timedOut ? "timed out" : "errored"}: ${sandboxResult.error || "unknown"}`,
            };

        novelResults.push(attackResult);
        const status = attackResult.caught ? "CAUGHT" : "UNCAUGHT ⚠️";
        console.log(`    [${hypothesis.id}] → ${status}: ${attackResult.actualOutcome.slice(0, 100)}`);
      }

      totalNovel += reasonerOutput.hypotheses.length;
      totalNovelValidated += generationOutcomes.filter((g) => g.success).length;
      totalNovelExecuted += novelResults.length;

      // Combine all round results
      allResults.push(...roundLibraryResults, ...novelResults);
      allTeamData.push({
        roundNumber: round,
        perPersonaResults: roundPerPersona,
        coordinatedOpResults: coordOpResults,
        hypotheses: reasonerOutput.hypotheses,
        generationOutcomes,
        novelResults,
      });

      // Round summary
      const allRoundResults = [...roundLibraryResults, ...novelResults];
      const totalCaught = allRoundResults.filter((r) => r.caught).length;
      const totalUncaught = allRoundResults.filter((r) => !r.caught).length;

      console.log("");
      console.log("───────────────────────────────────────────");
      console.log(`  Round ${round} complete:`);
      for (const pr of personaResults) {
        const c = pr.results.filter((r) => r.caught).length;
        console.log(`    ${pr.persona.padEnd(8)}: ${pr.results.length} attacks, ${c} caught`);
      }
      if (coordOpResults.length > 0) {
        console.log(`    Coord ops: ${coordOpResults.length}`);
      }
      console.log(`    Novel:   ${novelResults.length} executed, ${novelResults.filter((r) => r.caught).length} caught`);
      console.log(`    Total:   ${allRoundResults.length} attacks, ${totalCaught} caught, ${totalUncaught} uncaught`);
      console.log("───────────────────────────────────────────");
    }

    // Generate report with team data
    console.log("\nAll rounds complete. Generating report...\n");
    const report = await generateReport(allResults, undefined, undefined, allTeamData);
    console.log(report);

    // Final team summary
    const caught = allResults.filter((r) => r.caught).length;
    const uncaught = allResults.filter((r) => !r.caught).length;
    const libraryTotal = allResults.filter((r) => r.category !== "Novel Attack").length;

    console.log("");
    console.log("════════════════════════════════════════");
    console.log("  TEAM SUMMARY");
    console.log("════════════════════════════════════════");
    for (const persona of team!) {
      const pResults = perPersonaAccum.get(persona.config.name) || [];
      const pCaught = pResults.filter((r) => r.caught).length;
      console.log(`  ${persona.config.displayName.padEnd(8)} ${pResults.length} attacks, ${pCaught} caught`);
    }
    console.log("────────────────────────────────────────");
    console.log(`  Coordinated ops:     ${totalCoordOps}`);
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
    return;

  } else if (isRecursiveEffective) {
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
    return;

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
