// Runs attack scenarios against a live AgentGate instance — supports
// static, adaptive, team per-persona, and coordinated operation modes.

import type { AttackResult } from "./log";
import type { AttackClient } from "./attacks/replay";
import type { AttackPick, PersonaAssignment, CoordinatedOp } from "./strategist";
import { getAllScenarios, getScenario } from "./registry";
import type { PersonaIdentity } from "./personas";

// ---------------------------------------------------------------------------
// Numeric-aware sort for scenario IDs like "1.1", "2.3", "10.1"
// ---------------------------------------------------------------------------

function sortScenarioIds(ids: string[]): string[] {
  return [...ids].sort((a, b) => {
    const [aCat, aNum] = a.split(".").map(Number);
    const [bCat, bNum] = b.split(".").map(Number);
    if (aCat !== bCat) return aCat - bCat;
    return aNum - bNum;
  });
}

// ---------------------------------------------------------------------------
// Build an AttackClient from a PersonaIdentity
// ---------------------------------------------------------------------------

export function personaToClient(persona: PersonaIdentity, agentGateUrl: string, apiKey: string): AttackClient {
  return {
    agentGateUrl,
    apiKey,
    keys: persona.keys,
    identityId: persona.identityId,
  };
}

// ---------------------------------------------------------------------------
// Print helpers
// ---------------------------------------------------------------------------

export function printRoundHeader(round: number, totalRounds: number, strategy: string): void {
  console.log("");
  console.log("═══════════════════════════════════════════");
  console.log(`  ROUND ${round} of ${totalRounds}`);
  console.log(`  Strategy: ${strategy}`);
  console.log("═══════════════════════════════════════════");
  console.log("");
}

export function printRoundSummary(round: number, results: AttackResult[]): void {
  const caught = results.filter((r) => r.caught).length;
  const uncaught = results.filter((r) => !r.caught).length;
  console.log("");
  console.log("───────────────────────────────────────────");
  console.log(`  Round ${round} complete: ${results.length} attacks, ${caught} caught, ${uncaught} uncaught`);
  console.log("───────────────────────────────────────────");
}

// ---------------------------------------------------------------------------
// Core: Run specific attacks by ID with a given client
// ---------------------------------------------------------------------------

export async function runSelectedAttacks(
  picks: AttackPick[],
  client: AttackClient,
  round: number,
): Promise<AttackResult[]> {
  const results: AttackResult[] = [];

  for (const pick of picks) {
    const entry = getScenario(pick.id);

    if (!entry) {
      const result: AttackResult = {
        scenarioId: pick.id,
        scenarioName: "UNKNOWN",
        category: "UNKNOWN",
        expectedOutcome: "N/A",
        actualOutcome: "UNKNOWN — scenario ID not found in registry",
        caught: false,
        details: `Scenario ${pick.id} not found in registry. The strategist may have returned an invalid ID.`,
      };
      results.push(result);
      console.log(`  [${pick.id}] UNKNOWN — NOT FOUND in registry`);
      continue;
    }

    try {
      const result = await (entry.execute as (client: AttackClient, params?: Record<string, unknown>) => Promise<AttackResult>)(client, pick.params);
      results.push(result);

      const status = result.caught ? "CAUGHT" : "UNCAUGHT ⚠️";
      console.log(`  [${pick.id}] ${entry.name} → ${status}`);
    } catch (err) {
      const result: AttackResult = {
        scenarioId: pick.id,
        scenarioName: entry.name,
        category: entry.category,
        expectedOutcome: entry.description,
        actualOutcome: `Error: ${err instanceof Error ? err.message : String(err)}`,
        caught: false,
        details: `Attack threw an unexpected error: ${err instanceof Error ? err.message : String(err)}`,
      };
      results.push(result);
      console.log(`  [${pick.id}] ${entry.name} → [ERROR] ${result.actualOutcome}`);
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Static mode: Run all attacks in fixed order
// ---------------------------------------------------------------------------

export async function runAllAttacksStatic(client: AttackClient): Promise<AttackResult[]> {
  const scenarios = getAllScenarios();
  const sortedIds = sortScenarioIds(scenarios.map((s) => s.id));

  const results: AttackResult[] = [];

  for (const id of sortedIds) {
    const entry = getScenario(id)!;
    console.log(`Running attack [${id}]: ${entry.name}...`);

    try {
      const result = await (entry.execute as (client: AttackClient, params?: Record<string, unknown>) => Promise<AttackResult>)(client);
      results.push(result);

      if (result.caught) {
        console.log("  → [CAUGHT]");
      } else {
        console.log("  → [UNCAUGHT] ⚠️");
      }
    } catch (err) {
      const result: AttackResult = {
        scenarioId: id,
        scenarioName: entry.name,
        category: entry.category,
        expectedOutcome: entry.description,
        actualOutcome: `Error: ${err instanceof Error ? err.message : String(err)}`,
        caught: false,
        details: `Attack threw an unexpected error: ${err instanceof Error ? err.message : String(err)}`,
      };
      results.push(result);
      console.log(`  → [ERROR] ${result.actualOutcome}`);
    }
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════════
// TEAM MODE — per-persona assignments and coordinated operations
// ═══════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// Run per-persona independent assignments
// ---------------------------------------------------------------------------

export interface PersonaResults {
  persona: string;
  results: AttackResult[];
}

export async function runPersonaAssignments(
  assignments: PersonaAssignment[],
  team: PersonaIdentity[],
  agentGateUrl: string,
  apiKey: string,
  round: number,
): Promise<PersonaResults[]> {
  const allPersonaResults: PersonaResults[] = [];

  for (const assignment of assignments) {
    const persona = team.find((p) => p.config.name === assignment.persona);
    if (!persona) {
      console.log(`  ⚠ Unknown persona "${assignment.persona}" — skipping`);
      continue;
    }

    if (assignment.attacks.length === 0) continue;

    console.log(`\n  ── ${persona.config.displayName} (${persona.config.specialty}) ──\n`);

    const client = personaToClient(persona, agentGateUrl, apiKey);
    const results = await runSelectedAttacks(assignment.attacks, client, round);

    allPersonaResults.push({ persona: persona.config.name, results });

    const caught = results.filter((r) => r.caught).length;
    console.log(`\n  ${persona.config.displayName}: ${results.length} attacks, ${caught} caught`);
  }

  return allPersonaResults;
}

// ---------------------------------------------------------------------------
// Run coordinated operations
// ---------------------------------------------------------------------------

export interface CoordinatedOpResult {
  op: CoordinatedOp;
  results: AttackResult[];
  intel?: string;
}

const DISTRIBUTED_PROBE_STAGGER_MS = 500;

export async function runCoordinatedOps(
  ops: CoordinatedOp[],
  team: PersonaIdentity[],
  agentGateUrl: string,
  apiKey: string,
  round: number,
): Promise<CoordinatedOpResult[]> {
  const opResults: CoordinatedOpResult[] = [];

  for (const op of ops) {
    console.log(`\n  ── Coordinated: ${op.type} ──`);
    console.log(`  Target: ${op.targetDefense}`);
    console.log(`  Personas: ${op.personas.join(" + ")}`);
    console.log(`  Expected signal: ${op.expectedSignal}`);
    console.log(`  Why multi-identity: ${op.whyMultiIdentity}`);

    if (op.type === "handoff") {
      const result = await runHandoff(op, team, agentGateUrl, apiKey, round);
      opResults.push(result);
    } else if (op.type === "distributed_probe") {
      const result = await runDistributedProbe(op, team, agentGateUrl, apiKey, round);
      opResults.push(result);
    } else {
      console.log(`  ⚠ Unknown coordination type: ${op.type} — skipping`);
    }
  }

  return opResults;
}

// ---------------------------------------------------------------------------
// Handoff: Persona A runs → extract intel → Persona B runs with intel
// ---------------------------------------------------------------------------

async function runHandoff(
  op: CoordinatedOp,
  team: PersonaIdentity[],
  agentGateUrl: string,
  apiKey: string,
  round: number,
): Promise<CoordinatedOpResult> {
  const allResults: AttackResult[] = [];

  if (op.personas.length < 2 || op.attackRefs.length < 2) {
    console.log("  ⚠ Handoff requires at least 2 personas and 2 attack refs");
    return { op, results: [] };
  }

  // Step 1: Persona A runs their attack
  const personaA = team.find((p) => p.config.name === op.personas[0]);
  if (!personaA) {
    console.log(`  ⚠ Persona "${op.personas[0]}" not found — skipping handoff`);
    return { op, results: [] };
  }

  console.log(`\n  Handoff step 1: ${personaA.config.displayName} runs [${op.attackRefs[0]}]`);
  const clientA = personaToClient(personaA, agentGateUrl, apiKey);
  const resultsA = await runSelectedAttacks(
    [{ id: op.attackRefs[0], reasoning: `Handoff step 1 — intel gathering for ${op.targetDefense}` }],
    clientA,
    round,
  );
  allResults.push(...resultsA);

  // Extract intel from the result
  let intel = op.intelSummary || "";
  if (resultsA.length > 0) {
    const firstResult = resultsA[0];
    if (!intel) {
      intel = `${firstResult.caught ? "CAUGHT" : "UNCAUGHT"}: ${firstResult.details.slice(0, 200)}`;
    }
  }
  console.log(`  Intel extracted: ${intel.slice(0, 100)}${intel.length > 100 ? "..." : ""}`);

  // Step 2: Persona B runs with intel as sharedIntel param
  const personaB = team.find((p) => p.config.name === op.personas[1]);
  if (!personaB) {
    console.log(`  ⚠ Persona "${op.personas[1]}" not found — skipping handoff step 2`);
    return { op, results: allResults, intel };
  }

  console.log(`  Handoff step 2: ${personaB.config.displayName} runs [${op.attackRefs[1]}] with intel`);
  const clientB = personaToClient(personaB, agentGateUrl, apiKey);
  const resultsB = await runSelectedAttacks(
    [{ id: op.attackRefs[1], params: { sharedIntel: intel }, reasoning: `Handoff step 2 — exploiting intel from ${personaA.config.displayName}` }],
    clientB,
    round,
  );
  allResults.push(...resultsB);

  const caught = allResults.filter((r) => r.caught).length;
  console.log(`  Handoff complete: ${allResults.length} attacks, ${caught} caught`);

  return { op, results: allResults, intel };
}

// ---------------------------------------------------------------------------
// Distributed probe: Both personas attack concurrently with stagger
// ---------------------------------------------------------------------------

async function runDistributedProbe(
  op: CoordinatedOp,
  team: PersonaIdentity[],
  agentGateUrl: string,
  apiKey: string,
  round: number,
): Promise<CoordinatedOpResult> {
  if (op.personas.length < 2 || op.attackRefs.length < 2) {
    console.log("  ⚠ Distributed probe requires at least 2 personas and 2 attack refs");
    return { op, results: [] };
  }

  const personaA = team.find((p) => p.config.name === op.personas[0]);
  const personaB = team.find((p) => p.config.name === op.personas[1]);

  if (!personaA || !personaB) {
    console.log(`  ⚠ One or both personas not found — skipping distributed probe`);
    return { op, results: [] };
  }

  console.log(`\n  Distributed probe: ${personaA.config.displayName} + ${personaB.config.displayName} (${DISTRIBUTED_PROBE_STAGGER_MS}ms stagger)`);

  const clientA = personaToClient(personaA, agentGateUrl, apiKey);
  const clientB = personaToClient(personaB, agentGateUrl, apiKey);

  // Launch A immediately, B after stagger
  const promiseA = runSelectedAttacks(
    [{ id: op.attackRefs[0], reasoning: `Distributed probe — concurrent with ${personaB.config.displayName}` }],
    clientA,
    round,
  );

  // Stagger
  await new Promise((resolve) => setTimeout(resolve, DISTRIBUTED_PROBE_STAGGER_MS));

  const promiseB = runSelectedAttacks(
    [{ id: op.attackRefs[1], reasoning: `Distributed probe — concurrent with ${personaA.config.displayName}` }],
    clientB,
    round,
  );

  const [resultsA, resultsB] = await Promise.all([promiseA, promiseB]);
  const allResults = [...resultsA, ...resultsB];

  const caught = allResults.filter((r) => r.caught).length;
  console.log(`  Distributed probe complete: ${allResults.length} attacks, ${caught} caught`);

  return { op, results: allResults };
}
