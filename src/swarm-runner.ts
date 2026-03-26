// Interleaved campaign runner for Stage 5 swarm mode. Orchestrates
// multi-round campaigns with three teams of three agents each, using
// coordinator synthesis and per-team strategists between rounds.
// Does NOT replace runner.ts — that file still handles --static and --team modes.

import type { AttackResult } from "./log";
import type { AttackClient } from "./attacks/replay";
import type { SwarmConfig, SwarmTeamName, SwarmAgentIdentity } from "./swarm";
import type { SwarmStrategistConfig, SwarmAttackPick } from "./swarm-strategist";
import type { CoordinatorConfig, RoundResultEntry } from "./coordinator";
import type { LibraryEntry } from "./strategist";
import { IntelLog } from "./intel-log";
import { getScenario } from "./registry";
import { buildLibraryMenu } from "./strategist";
import { pickSwarmAttacks, submitTeamQuestions, getDefaultSwarmAttacks } from "./swarm-strategist";
import { synthesizeIntelligence } from "./coordinator";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SwarmCampaignConfig {
  swarmConfig: SwarmConfig;
  identities: Map<string, SwarmAgentIdentity>;
  targetUrl: string;
  totalRounds: number;
  sequential: boolean;
}

export interface SwarmAttackResult extends AttackResult {
  teamName: SwarmTeamName;
  agentId: string;
  roundNumber: number;
  executionPosition: number;
}

export interface SwarmRoundResult {
  roundNumber: number;
  teamResults: Map<SwarmTeamName, SwarmAttackResult[]>;
  coordinatorSynthesis: boolean;
}

export interface TeamSummary {
  attacks: number;
  caught: number;
  uncaught: number;
}

export interface SwarmCampaignResult {
  rounds: SwarmRoundResult[];
  intelLog: IntelLog;
  totalAttacks: number;
  totalCaught: number;
  totalUncaught: number;
  perTeamSummary: Map<SwarmTeamName, TeamSummary>;
}

export interface QueuedAttack {
  pick: SwarmAttackPick;
  teamName: SwarmTeamName;
  agentId: string;
}

// ---------------------------------------------------------------------------
// Interleave helper
// ---------------------------------------------------------------------------

/**
 * Deterministic round-robin interleave across teams.
 * If teams have unequal counts, remaining attacks from longer lists go at the end.
 */
export function interleaveAttacks(teamAttacks: Map<string, QueuedAttack[]>): QueuedAttack[] {
  const teams = [...teamAttacks.keys()].sort();
  const queues = teams.map((t) => [...(teamAttacks.get(t) ?? [])]);
  const result: QueuedAttack[] = [];

  const maxLen = Math.max(...queues.map((q) => q.length), 0);

  for (let i = 0; i < maxLen; i++) {
    for (const queue of queues) {
      if (i < queue.length) {
        result.push(queue[i]);
      }
    }
  }

  return result;
}

/**
 * Sequential ordering: all Alpha attacks, then Beta, then Gamma.
 */
export function sequentialAttacks(teamAttacks: Map<string, QueuedAttack[]>): QueuedAttack[] {
  const teams = [...teamAttacks.keys()].sort();
  const result: QueuedAttack[] = [];
  for (const team of teams) {
    result.push(...(teamAttacks.get(team) ?? []));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Build AttackClient from swarm identity
// ---------------------------------------------------------------------------

function identityToClient(identity: SwarmAgentIdentity, targetUrl: string, apiKey: string): AttackClient {
  return {
    agentGateUrl: targetUrl,
    apiKey,
    keys: identity.keys,
    identityId: identity.identityId,
  };
}

// ---------------------------------------------------------------------------
// Execute a single queued attack
// ---------------------------------------------------------------------------

async function executeQueuedAttack(
  attack: QueuedAttack,
  position: number,
  roundNumber: number,
  identities: Map<string, SwarmAgentIdentity>,
  targetUrl: string,
  apiKey: string,
): Promise<SwarmAttackResult> {
  const identity = identities.get(attack.agentId);

  if (!identity) {
    console.log(`  [${attack.teamName}/${attack.agentId}] [${attack.pick.id}] SKIPPED — identity not found`);
    return {
      scenarioId: attack.pick.id,
      scenarioName: "UNKNOWN",
      category: "UNKNOWN",
      expectedOutcome: "N/A",
      actualOutcome: `Identity ${attack.agentId} not found`,
      caught: false,
      details: `Agent identity ${attack.agentId} not found in loaded identities.`,
      teamName: attack.teamName,
      agentId: attack.agentId,
      roundNumber,
      executionPosition: position,
    };
  }

  const entry = getScenario(attack.pick.id);

  if (!entry) {
    console.log(`  [${attack.teamName}/${attack.agentId}] [${attack.pick.id}] NOT FOUND in registry`);
    return {
      scenarioId: attack.pick.id,
      scenarioName: "UNKNOWN",
      category: "UNKNOWN",
      expectedOutcome: "N/A",
      actualOutcome: `Scenario ${attack.pick.id} not found in registry`,
      caught: false,
      details: `Scenario ${attack.pick.id} not found in registry.`,
      teamName: attack.teamName,
      agentId: attack.agentId,
      roundNumber,
      executionPosition: position,
    };
  }

  console.log(`  [Round ${roundNumber}] [${attack.teamName}/${attack.agentId}] Running attack ${attack.pick.id}: ${entry.name}...`);

  try {
    const client = identityToClient(identity, targetUrl, apiKey);
    const result = await (entry.execute as (client: AttackClient, params?: Record<string, unknown>) => Promise<AttackResult>)(client, attack.pick.params);

    const status = result.caught ? "CAUGHT" : "UNCAUGHT";
    console.log(`    → ${status}`);

    return {
      ...result,
      teamName: attack.teamName,
      agentId: attack.agentId,
      roundNumber,
      executionPosition: position,
    };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.log(`    → [ERROR] ${errorMsg}`);

    return {
      scenarioId: attack.pick.id,
      scenarioName: entry.name,
      category: entry.category,
      expectedOutcome: entry.description,
      actualOutcome: `Error: ${errorMsg}`,
      caught: false,
      details: `Attack threw an unexpected error: ${errorMsg}`,
      teamName: attack.teamName,
      agentId: attack.agentId,
      roundNumber,
      executionPosition: position,
    };
  }
}

// ---------------------------------------------------------------------------
// Print helpers
// ---------------------------------------------------------------------------

export function printCampaignBanner(config: SwarmCampaignConfig): void {
  const { swarmConfig, totalRounds, sequential } = config;
  const mode = sequential ? "sequential" : "interleaved";

  console.log("");
  console.log("╔═══════════════════════════════════════════════╗");
  console.log("║          SWARM CAMPAIGN — v0.5.0-alpha        ║");
  console.log("╚═══════════════════════════════════════════════╝");
  console.log("");
  console.log(`  Teams: ${swarmConfig.teams.length}`);
  console.log(`  Agents per team: ${swarmConfig.teams[0].agents.length}`);
  console.log(`  Total rounds: ${totalRounds}`);
  console.log(`  Execution mode: ${mode}`);
  console.log(`  Campaign budget cap: ${swarmConfig.campaignCapCents}¢`);
  console.log("");

  for (const team of swarmConfig.teams) {
    console.log(`  Team ${team.name.toUpperCase()}: ${team.objective}`);
    console.log(`    Budget: ${team.teamBudgetCents}¢ (${team.agents[0].bondBudgetCents}¢/agent)`);
  }

  console.log("");
}

export function printSwarmRoundSummary(roundNumber: number, results: SwarmAttackResult[]): void {
  console.log("");
  console.log("───────────────────────────────────────────");
  console.log(`  Round ${roundNumber} Summary`);
  console.log("───────────────────────────────────────────");

  const teams = new Set(results.map((r) => r.teamName));
  for (const team of [...teams].sort()) {
    const teamResults = results.filter((r) => r.teamName === team);
    const caught = teamResults.filter((r) => r.caught).length;
    const uncaught = teamResults.length - caught;
    console.log(`  ${team}: ${teamResults.length} attacks, ${caught} caught, ${uncaught} uncaught`);
  }

  const totalCaught = results.filter((r) => r.caught).length;
  console.log(`  TOTAL: ${results.length} attacks, ${totalCaught} caught, ${results.length - totalCaught} uncaught`);
  console.log("───────────────────────────────────────────");
}

// ---------------------------------------------------------------------------
// Aggregate campaign results
// ---------------------------------------------------------------------------

export function aggregateCampaignResults(
  rounds: SwarmRoundResult[],
  intelLog: IntelLog,
): SwarmCampaignResult {
  const perTeamSummary = new Map<SwarmTeamName, TeamSummary>();
  let totalAttacks = 0;
  let totalCaught = 0;
  let totalUncaught = 0;

  for (const round of rounds) {
    for (const [teamName, results] of round.teamResults) {
      const existing = perTeamSummary.get(teamName) ?? { attacks: 0, caught: 0, uncaught: 0 };
      for (const r of results) {
        existing.attacks++;
        totalAttacks++;
        if (r.caught) {
          existing.caught++;
          totalCaught++;
        } else {
          existing.uncaught++;
          totalUncaught++;
        }
      }
      perTeamSummary.set(teamName, existing);
    }
  }

  return {
    rounds,
    intelLog,
    totalAttacks,
    totalCaught,
    totalUncaught,
    perTeamSummary,
  };
}

// ---------------------------------------------------------------------------
// Validate config
// ---------------------------------------------------------------------------

export function validateCampaignConfig(config: SwarmCampaignConfig): string[] {
  const errors: string[] = [];

  if (!config.swarmConfig) errors.push("swarmConfig is required");
  if (!config.identities || config.identities.size === 0) errors.push("identities map is required and must not be empty");
  if (!config.targetUrl) errors.push("targetUrl is required");
  if (config.totalRounds < 1) errors.push("totalRounds must be at least 1");

  if (config.swarmConfig?.teams) {
    for (const team of config.swarmConfig.teams) {
      for (const agent of team.agents) {
        if (!config.identities?.has(agent.agentId)) {
          errors.push(`Missing identity for agent ${agent.agentId}`);
        }
      }
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// Main campaign loop
// ---------------------------------------------------------------------------

export async function runSwarmCampaign(config: SwarmCampaignConfig): Promise<SwarmCampaignResult> {
  const { swarmConfig, identities, targetUrl, totalRounds, sequential } = config;

  const apiKey = process.env.AGENTGATE_REST_KEY ?? "";
  const intelLog = new IntelLog();
  const library = buildLibraryMenu();
  const rounds: SwarmRoundResult[] = [];

  // All prior results per team (across rounds)
  const allPriorResults = new Map<SwarmTeamName, AttackResult[]>();
  for (const team of swarmConfig.teams) {
    allPriorResults.set(team.name, []);
  }

  printCampaignBanner(config);

  for (let round = 1; round <= totalRounds; round++) {
    console.log("");
    console.log("═══════════════════════════════════════════");
    console.log(`  ROUND ${round} of ${totalRounds}`);
    console.log("═══════════════════════════════════════════");

    // (a) Coordinator synthesis — skip round 1 (no prior results)
    let didSynthesize = false;
    if (round > 1) {
      console.log("\n  Coordinator synthesizing intelligence...");
      const prevRound = rounds[rounds.length - 1];
      const roundResults: RoundResultEntry[] = [];
      for (const [teamName, results] of prevRound.teamResults) {
        for (const r of results) {
          roundResults.push({ team: teamName, agentId: r.agentId, result: r });
        }
      }

      const coordConfig: CoordinatorConfig = {
        intelLog,
        completedRound: round - 1,
        roundResults,
      };
      await synthesizeIntelligence(coordConfig);
      didSynthesize = true;
      console.log("  Coordinator synthesis complete.");
    }

    // (b) Each team's strategist picks attacks (sequentially: Alpha, Beta, Gamma)
    const teamAttacks = new Map<string, QueuedAttack[]>();

    for (const team of swarmConfig.teams) {
      console.log(`\n  Team ${team.name.toUpperCase()} strategist picking attacks...`);

      const sharedIntel = intelLog.getSharedIntelForStrategist(team.name, round);
      const priorResults = allPriorResults.get(team.name) ?? [];

      const stratConfig: SwarmStrategistConfig = {
        team,
        currentRound: round,
        totalRounds,
        priorResults,
        sharedIntel,
        attackLibrary: library,
        novelAttackResults: [],
      };

      const response = await pickSwarmAttacks(stratConfig);
      console.log(`  ${team.name}: ${response.selectedAttacks.length} attacks selected — ${response.strategy}`);

      // (c) Submit team questions to intel log
      submitTeamQuestions(response, intelLog, round);

      // Build queued attacks
      const queued: QueuedAttack[] = response.selectedAttacks.map((pick) => ({
        pick,
        teamName: team.name,
        agentId: pick.agentId,
      }));
      teamAttacks.set(team.name, queued);
    }

    // (d) & (e) Build execution queue
    const executionQueue = sequential
      ? sequentialAttacks(teamAttacks)
      : interleaveAttacks(teamAttacks);

    console.log(`\n  Execution queue: ${executionQueue.length} attacks (${sequential ? "sequential" : "interleaved"})`);

    // (f) Execute each attack
    const roundResults: SwarmAttackResult[] = [];
    for (let i = 0; i < executionQueue.length; i++) {
      const attack = executionQueue[i];
      const result = await executeQueuedAttack(
        attack,
        i,
        round,
        identities,
        targetUrl,
        apiKey,
      );
      roundResults.push(result);
    }

    // (g) Collect results for this round, grouped by team
    const teamResults = new Map<SwarmTeamName, SwarmAttackResult[]>();
    for (const result of roundResults) {
      const existing = teamResults.get(result.teamName) ?? [];
      existing.push(result);
      teamResults.set(result.teamName, existing);
    }

    // Update cumulative prior results
    for (const [teamName, results] of teamResults) {
      const prior = allPriorResults.get(teamName) ?? [];
      prior.push(...results);
      allPriorResults.set(teamName, prior);
    }

    // Also add team observations to intel log
    for (const [teamName, results] of teamResults) {
      const caught = results.filter((r) => r.caught).length;
      const uncaught = results.length - caught;
      intelLog.addEntry({
        round,
        team: teamName,
        type: "observation",
        subject: `round-${round}-summary`,
        content: `${results.length} attacks executed: ${caught} caught, ${uncaught} uncaught`,
        targetHint: null,
      });
    }

    rounds.push({
      roundNumber: round,
      teamResults,
      coordinatorSynthesis: didSynthesize,
    });

    // (h) Print round summary
    printSwarmRoundSummary(round, roundResults);
  }

  return aggregateCampaignResults(rounds, intelLog);
}
