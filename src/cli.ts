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
import { getSwarmConfig, createSwarmIdentities, type SwarmAgentIdentity } from "./swarm";
import { runSwarmCampaign, validateCampaignConfig, type SwarmCampaignConfig } from "./swarm-runner";
import { generateSwarmReport } from "./swarm-reporter";
import { runScout } from "./sleeper/scout-runner";
import { runStrike } from "./sleeper/strike-runner";
import { generateTemporalReport } from "./sleeper/temporal-reporter";
import { DEFAULT_SLEEPER_IDENTITY_PATH, sleeperIdentityExists } from "./sleeper/identity-store";

async function main() {
  // Parse CLI args
  const targetIndex = process.argv.indexOf("--target");
  const agentGateUrl =
    (targetIndex !== -1 && process.argv[targetIndex + 1]) ||
    process.env.AGENTGATE_URL ||
    "http://127.0.0.1:3000";

  const roundsIndex = process.argv.indexOf("--rounds");
  const roundsArg = roundsIndex !== -1 ? parseInt(process.argv[roundsIndex + 1], 10) : NaN;
  const MAX_ROUNDS = 20;
  const requestedRounds = Number.isFinite(roundsArg) && roundsArg > 0 ? roundsArg : 3;
  const rounds = Math.min(requestedRounds, MAX_ROUNDS);
  if (requestedRounds > MAX_ROUNDS) {
    console.log(`Warning: --rounds capped at maximum of ${MAX_ROUNDS} (requested: ${requestedRounds}).`);
  }

  const isStatic = process.argv.includes("--static");
  const isRecursive = process.argv.includes("--recursive");
  const isTeam = process.argv.includes("--team");
  const isFreshTeam = process.argv.includes("--fresh-team");
  const isFreshSwarm = process.argv.includes("--fresh-swarm");
  const isSwarm = process.argv.includes("--swarm") || isFreshSwarm;
  const isSequential = process.argv.includes("--sequential");

  // Sleeper agent (v0.6.0) flags
  const isScout = process.argv.includes("--scout");
  const isStrike = process.argv.includes("--strike");
  const isCampaign = process.argv.includes("--campaign");
  const isReportTemporal = process.argv.includes("--report-temporal");
  const isBlind = process.argv.includes("--blind");
  const skipNonceTtl = process.argv.includes("--skip-nonce-ttl");

  const reconFileIndex = process.argv.indexOf("--recon-file");
  const reconFilePath = reconFileIndex !== -1 ? process.argv[reconFileIndex + 1] : undefined;

  const identityFileIndex = process.argv.indexOf("--identity-file");
  const identityFilePath = identityFileIndex !== -1 ? process.argv[identityFileIndex + 1] : DEFAULT_SLEEPER_IDENTITY_PATH;

  const identityModeIndex = process.argv.indexOf("--identity-mode");
  const identityModeRaw = identityModeIndex !== -1 ? process.argv[identityModeIndex + 1] : "fresh";
  if (identityModeRaw !== "same" && identityModeRaw !== "fresh") {
    console.error(`Error: --identity-mode must be "same" or "fresh" (got "${identityModeRaw}").`);
    process.exit(1);
  }
  const identityMode = identityModeRaw as "same" | "fresh";

  // Sleeper mutual exclusivity checks
  const sleeperFlags = [isScout, isStrike, isCampaign, isReportTemporal].filter(Boolean).length;
  if (sleeperFlags > 1 && !(isScout && isCampaign)) {
    console.error("Error: --scout, --strike, --campaign, and --report-temporal are mutually exclusive (except --scout with --campaign).");
    process.exit(1);
  }
  if (sleeperFlags > 0 && (isStatic || isRecursive || isTeam || isSwarm)) {
    console.error("Error: sleeper flags (--scout, --strike, --campaign, --report-temporal) cannot be combined with --static, --recursive, --team, or --swarm.");
    process.exit(1);
  }
  if (isBlind && reconFilePath) {
    console.error("Error: --blind cannot be combined with --recon-file.");
    process.exit(1);
  }

  // --team implies --recursive, --swarm implies --recursive
  const isRecursiveEffective = isRecursive || isTeam;

  // Mutual exclusivity checks
  if (isStatic && (isRecursiveEffective || isSwarm)) {
    console.error("Error: --static and --recursive/--team/--swarm are mutually exclusive.");
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
  if (isSwarm && isTeam) {
    console.error("Error: --swarm and --team are mutually exclusive.");
    process.exit(1);
  }
  if (isSequential && !isSwarm) {
    console.error("Error: --sequential requires --swarm.");
    process.exit(1);
  }
  if (isSwarm && isRecursive) {
    console.log("Warning: --recursive is ignored in swarm mode. Swarm mode does not include novel attack generation.");
  }

  // Verify required env vars
  if (!process.env.AGENTGATE_REST_KEY) {
    console.error("Error: AGENTGATE_REST_KEY not set in environment. Add it to .env or export it.");
    process.exit(1);
  }
  if (!process.env.ANTHROPIC_API_KEY && !isStatic && !isScout && !isReportTemporal) {
    console.error("Error: ANTHROPIC_API_KEY not set in environment. Add it to .env or export it.");
    process.exit(1);
  }
  if (!process.env.ANTHROPIC_API_KEY && isStatic) {
    console.log("Warning: ANTHROPIC_API_KEY not set. Report generation will be skipped.");
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SLEEPER AGENT MODES (Stage 6 — v0.6.0)
  // ═══════════════════════════════════════════════════════════════════════

  if (isReportTemporal) {
    const report = await generateTemporalReport();
    console.log(report);
    process.exit(0);
    return;
  }

  if (isScout || isCampaign) {
    const scoutResult = await runScout({
      targetUrl: agentGateUrl,
      apiKey: process.env.AGENTGATE_REST_KEY!,
      skipNonceTtl,
      outputPath: "recon.json",
      identityFilePath,
    });

    if (!isCampaign) {
      process.exit(0);
      return;
    }

    // Campaign mode: run all four strike variants after scout
    console.log("\n  Campaign mode: running 4 strike variants...\n");

    const campaignVariants: Array<{ label: string; options: Parameters<typeof runStrike>[0] }> = [
      {
        label: "1. Same identity + recon",
        options: {
          targetUrl: agentGateUrl,
          apiKey: process.env.AGENTGATE_REST_KEY!,
          reconFile: "recon.json",
          identityMode: "same",
          identityFile: identityFilePath,
          scoutKeys: scoutResult.scoutKeys,
          scoutIdentityId: scoutResult.scoutIdentityId,
        },
      },
      {
        // Design choice: this variant reuses the scout identity but omits
        // the recon file. The target server sees the same identity that ran
        // scout probes, so server-side state (reputation, rate-limit
        // counters) carries over. This is intentional — the variant
        // isolates the value of the recon *file* while holding identity
        // constant. It is NOT a true blind baseline; variant 4
        // (fresh + blind) serves that role. The temporal reporter's
        // Finding A delta (same+recon vs same+blind) therefore measures
        // "what recon intelligence adds" given identical server-side
        // identity history, not recon advantage from a cold start.
        label: "2. Same identity + blind",
        options: {
          targetUrl: agentGateUrl,
          apiKey: process.env.AGENTGATE_REST_KEY!,
          identityMode: "same",
          identityFile: identityFilePath,
          scoutKeys: scoutResult.scoutKeys,
          scoutIdentityId: scoutResult.scoutIdentityId,
        },
      },
      {
        label: "3. Fresh identity + recon",
        options: {
          targetUrl: agentGateUrl,
          apiKey: process.env.AGENTGATE_REST_KEY!,
          reconFile: "recon.json",
          identityMode: "fresh",
        },
      },
      {
        label: "4. Fresh identity + blind",
        options: {
          targetUrl: agentGateUrl,
          apiKey: process.env.AGENTGATE_REST_KEY!,
          identityMode: "fresh",
        },
      },
    ];

    let campaignFailures = 0;
    for (const variant of campaignVariants) {
      try {
        await runStrike(variant.options);
      } catch (err) {
        campaignFailures++;
        console.error(`\n  Campaign variant "${variant.label}" failed: ${err instanceof Error ? err.message : String(err)}`);
        console.error("  Continuing to next variant...\n");
      }
    }

    // Generate report regardless of individual failures
    if (campaignFailures > 0) {
      console.log(`\n  ${campaignFailures}/4 campaign variants failed. Generating partial report...\n`);
    }
    const report = await generateTemporalReport();
    console.log(report);

    process.exit(0);
    return;
  }

  if (isStrike) {
    if (identityMode === "same" && !sleeperIdentityExists(identityFilePath)) {
      console.error(`Error: --identity-mode same requires a sleeper identity file. Run --scout first or provide --identity-file (looked for ${identityFilePath}).`);
      process.exit(1);
    }

    await runStrike({
      targetUrl: agentGateUrl,
      apiKey: process.env.AGENTGATE_REST_KEY!,
      reconFile: isBlind ? undefined : reconFilePath,
      identityFile: identityFilePath,
      identityMode,
    });
    process.exit(0);
    return;
  }

  // Startup banner (for non-sleeper modes)
  const scenarioCount = getAllScenarios().length;
  const modeText = isStatic
    ? `Static (${scenarioCount} scenarios)`
    : isSwarm
      ? `Swarm (${rounds} rounds, ${isSequential ? "sequential" : "interleaved"})`
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

  // ═══════════════════════════════════════════════════════════════════════
  // SWARM MODE (Stage 5 — v0.5.0-alpha)
  // ═══════════════════════════════════════════════════════════════════════

  if (isSwarm) {
    console.log("Initializing swarm identities...");
    if (isFreshSwarm) {
      console.log("  --fresh-swarm: deleting existing swarm identity files");
    }

    const swarmIdentities = await createSwarmIdentities(
      agentGateUrl,
      process.env.AGENTGATE_REST_KEY,
      isFreshSwarm,
    );

    const fullSwarmConfig = getSwarmConfig();

    // Build identities map for all 9 agents
    const identitiesMap = new Map<string, SwarmAgentIdentity>();
    for (const identity of swarmIdentities) {
      identitiesMap.set(identity.config.agentId, identity);
    }

    console.log(`  ${identitiesMap.size} identities loaded (Alpha + Beta + Gamma)`);
    for (const [agentId, identity] of identitiesMap) {
      console.log(`    ${agentId}: ${identity.identityId.slice(0, 20)}... [${identity.config.bondBudgetCents}¢]`);
    }
    console.log("");

    const campaignConfig: SwarmCampaignConfig = {
      swarmConfig: fullSwarmConfig,
      identities: identitiesMap,
      targetUrl: agentGateUrl,
      totalRounds: rounds,
      sequential: isSequential,
    };

    const errors = validateCampaignConfig(campaignConfig);
    if (errors.length > 0) {
      console.error("Campaign config validation failed:");
      for (const err of errors) console.error(`  - ${err}`);
      process.exit(1);
    }

    const result = await runSwarmCampaign(campaignConfig);

    // Generate swarm report
    console.log("\nAll rounds complete. Generating swarm report...\n");
    const report = await generateSwarmReport(result);
    console.log(report);

    if (result.interrupted) {
      console.log("");
      console.log(`WARNING: Swarm campaign was interrupted after ${result.completedRounds}/${result.plannedRounds} round(s).`);
      if (result.interruptionReason) {
        console.log(`Reason: ${result.interruptionReason}`);
      }
    }

    // Print campaign summary
    console.log("");
    console.log("════════════════════════════════════════");
    console.log("  SWARM CAMPAIGN SUMMARY");
    console.log("════════════════════════════════════════");
    for (const [teamName, summary] of result.perTeamSummary) {
      console.log(`  ${teamName.padEnd(8)} ${summary.attacks} attacks, ${summary.caught} caught, ${summary.uncaught} uncaught`);
    }
    console.log("────────────────────────────────────────");
    console.log(`  Total attacks:   ${result.totalAttacks}`);
    console.log(`  Caught:          ${result.totalCaught}`);
    console.log(`  Uncaught:        ${result.totalUncaught}`);
    console.log(`  Intel log:       ${result.intelLog.getAllEntries().length} entries`);
    console.log(`  Completed:       ${result.completedRounds}/${result.plannedRounds} rounds`);
    console.log("════════════════════════════════════════");
    console.log("");

    process.exit(result.interrupted || result.totalUncaught > 0 ? 1 : 0);
    return;
  }

  // Create or load primary identity (used by all non-swarm modes)
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

  // Generate report (skip if no API key — static mode can run without it)
  if (process.env.ANTHROPIC_API_KEY) {
    console.log("\nAll attacks complete. Generating report...\n");
    try {
      const report = await generateReport(allResults, allStrategies);
      console.log(report);
    } catch (err) {
      console.log(`\nReport generation failed: ${err instanceof Error ? err.message : String(err)}`);
      console.log("Skipping report — results summary below.\n");
    }
  } else {
    console.log("\nAll attacks complete. Report generation skipped (no ANTHROPIC_API_KEY).\n");
  }

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

main().catch((err) => {
  console.error(`\nFatal error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
