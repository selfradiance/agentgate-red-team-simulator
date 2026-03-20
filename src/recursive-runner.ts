// Recursive runner — extends the adaptive loop with novel attack generation.
// Each round: strategist picks library attacks → reasoner analyzes →
// generator produces novel code → sandbox executes novel attacks.

import type { AttackResult } from "./log";
import type { AttackClient } from "./attacks/replay";
import type { AttackHypothesis } from "./reasoner";
import type { GenerationResult } from "./generator";
import { runSelectedAttacks } from "./runner";
import { buildLibraryMenu, pickAttacks, getDefaultAttacks } from "./strategist";
import { analyzeResults } from "./reasoner";
import { generateAttack } from "./generator";
import { executeInSandbox, type ExecutorOptions } from "./sandbox/executor";
import { getAllScenarios } from "./registry";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RecursiveRoundResult {
  libraryResults: AttackResult[];
  novelResults: AttackResult[];
  hypotheses: AttackHypothesis[];
  generationOutcomes: GenerationResult[];
}

export interface RecursiveOptions {
  targetUrl: string;
  agentIdentity: {
    identityId: string;
    publicKey: string;
    privateKey: string;
  };
  restKey: string;
}

// ---------------------------------------------------------------------------
// Build registry map for novelty checks
// ---------------------------------------------------------------------------

function buildNoveltyRegistry(): Map<string, { name: string; description: string }> {
  const scenarios = getAllScenarios();
  const map = new Map<string, { name: string; description: string }>();
  for (const s of scenarios) {
    map.set(s.id, { name: s.name, description: s.description });
  }
  return map;
}

// ---------------------------------------------------------------------------
// Convert sandbox result to AttackResult
// ---------------------------------------------------------------------------

function sandboxToAttackResult(
  hypothesis: AttackHypothesis,
  sandboxResult: Awaited<ReturnType<typeof executeInSandbox>>,
): AttackResult {
  if (sandboxResult.success && sandboxResult.result) {
    return {
      scenarioId: hypothesis.id,
      scenarioName: hypothesis.description,
      category: "Novel Attack",
      expectedOutcome: "Probing: " + hypothesis.targetDefense,
      actualOutcome: sandboxResult.result.caught
        ? `CAUGHT: ${sandboxResult.result.reason}`
        : `UNCAUGHT: ${sandboxResult.result.reason}`,
      caught: sandboxResult.result.caught,
      details: `Hypothesis: ${hypothesis.rationale}. Result: ${sandboxResult.result.reason}`,
      sideEffects: sandboxResult.result.sideEffects ? {
        additionalNotes: `Sandbox logs: ${sandboxResult.logs.join("; ")}. Duration: ${sandboxResult.durationMs}ms`,
        ...sandboxResult.result.sideEffects,
      } : {
        additionalNotes: `Sandbox logs: ${sandboxResult.logs.join("; ")}. Duration: ${sandboxResult.durationMs}ms`,
      },
    };
  }

  // Sandbox error or timeout — treat as caught (attack failed, not AgentGate vulnerability)
  return {
    scenarioId: hypothesis.id,
    scenarioName: hypothesis.description,
    category: "Novel Attack",
    expectedOutcome: "Probing: " + hypothesis.targetDefense,
    actualOutcome: sandboxResult.timedOut
      ? "TIMEOUT: sandbox execution exceeded 15s"
      : `ERROR: ${sandboxResult.error || "Unknown sandbox error"}`,
    caught: true,
    details: `Hypothesis: ${hypothesis.rationale}. Sandbox ${sandboxResult.timedOut ? "timed out" : "errored"}: ${sandboxResult.error || "unknown"}. Logs: ${sandboxResult.logs.join("; ")}`,
  };
}

// ---------------------------------------------------------------------------
// Main function — run one recursive round
// ---------------------------------------------------------------------------

export async function runRecursiveRound(
  roundNumber: number,
  totalRounds: number,
  allPriorResults: AttackResult[],
  client: AttackClient,
  options: RecursiveOptions,
): Promise<RecursiveRoundResult> {
  const library = buildLibraryMenu();
  const noveltyRegistry = buildNoveltyRegistry();

  // Step A: Strategist picks library attacks
  console.log("\n  ── Library Attacks ──\n");

  let strategy;
  try {
    strategy = await pickAttacks(library, roundNumber, totalRounds, allPriorResults);
  } catch (err) {
    console.log(`  Strategist API failed: ${err instanceof Error ? err.message : String(err)}`);
    console.log("  Falling back to default attack selection.\n");
    strategy = getDefaultAttacks(library, roundNumber);
  }

  if (strategy.usedFallback) {
    console.log("  ⚠ Using fallback selection (Claude API unavailable)\n");
  }

  const libraryResults = await runSelectedAttacks(strategy.attacks, client, roundNumber);

  const libCaught = libraryResults.filter((r) => r.caught).length;
  console.log(`\n  Library: ${libraryResults.length} attacks, ${libCaught} caught\n`);

  // Step B: Reasoner analyzes all results so far
  console.log("  ── Reasoner Analysis ──\n");

  const combinedResults = [...allPriorResults, ...libraryResults];
  let reasonerOutput;
  try {
    reasonerOutput = await analyzeResults(combinedResults, roundNumber);
  } catch (err) {
    console.log(`  Reasoner failed: ${err instanceof Error ? err.message : String(err)}`);
    reasonerOutput = { analysis: "Reasoner unavailable", hypotheses: [] };
  }

  console.log(`  Analysis: ${reasonerOutput.analysis.slice(0, 200)}${reasonerOutput.analysis.length > 200 ? "..." : ""}`);
  console.log(`  Hypotheses: ${reasonerOutput.hypotheses.length}`);
  for (const h of reasonerOutput.hypotheses) {
    console.log(`    [${h.id}] ${h.description.slice(0, 80)}${h.description.length > 80 ? "..." : ""} (${h.confidence})`);
  }

  // Step C: Generator produces novel attack code
  console.log("\n  ── Novel Attacks ──\n");

  const novelResults: AttackResult[] = [];
  const generationOutcomes: GenerationResult[] = [];

  const executorOptions: ExecutorOptions = {
    targetUrl: options.targetUrl,
    agentIdentity: options.agentIdentity,
    restKey: options.restKey,
  };

  for (const hypothesis of reasonerOutput.hypotheses) {
    console.log(`  Generating attack for: ${hypothesis.id}...`);

    let genResult: GenerationResult;
    try {
      genResult = await generateAttack(hypothesis, noveltyRegistry);
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

    // Print the generated code
    console.log("");
    console.log(`  ═══ NOVEL ATTACK: ${hypothesis.id} ═══`);
    console.log(genResult.attack.code);
    console.log("  ═══════════════════════════════");
    console.log("");

    // Execute in sandbox
    console.log(`    Executing in sandbox...`);
    const sandboxResult = await executeInSandbox(genResult.attack.code, executorOptions);
    const attackResult = sandboxToAttackResult(hypothesis, sandboxResult);
    novelResults.push(attackResult);

    const status = attackResult.caught ? "CAUGHT" : "UNCAUGHT ⚠️";
    console.log(`    [${hypothesis.id}] → ${status}: ${attackResult.actualOutcome.slice(0, 100)}`);
  }

  if (novelResults.length === 0 && reasonerOutput.hypotheses.length > 0) {
    console.log("  No novel attacks executed (all generation attempts failed)");
  } else if (reasonerOutput.hypotheses.length === 0) {
    console.log("  No hypotheses produced — skipping novel attack generation");
  }

  return {
    libraryResults,
    novelResults,
    hypotheses: reasonerOutput.hypotheses,
    generationOutcomes,
  };
}
