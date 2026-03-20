// Generates a human-readable findings report from attack results via Claude API.
// Supports static, adaptive, recursive, and team modes.

import Anthropic from "@anthropic-ai/sdk";
import type { AttackResult } from "./log";
import type { StrategyResponse } from "./strategist";
import type { AttackHypothesis } from "./reasoner";
import type { GenerationResult } from "./generator";
import type { CoordinatedOpResult } from "./runner";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RecursiveRoundData {
  roundNumber: number;
  hypotheses: AttackHypothesis[];
  generationOutcomes: GenerationResult[];
  novelResults: AttackResult[];
}

export interface TeamRoundData {
  roundNumber: number;
  perPersonaResults: Map<string, AttackResult[]>;
  coordinatedOpResults: CoordinatedOpResult[];
  hypotheses: AttackHypothesis[];
  generationOutcomes: GenerationResult[];
  novelResults: AttackResult[];
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a security auditor analyzing red team results against AgentGate, a collateralized execution engine for AI agents. Generate a concise, structured findings report. Be direct and factual. Do not pad the report.

If the results span multiple rounds with strategist reasoning, your report should include:
1. An executive summary of the overall red team engagement
2. A per-round breakdown showing: the strategist's stated strategy, which attacks were selected and why, and what was caught/uncaught
3. A strategy evolution analysis: how did the strategist adapt between rounds? Did it escalate appropriately? Did it discover any attack chains?
4. A results table covering ALL attacks across all rounds
5. A final assessment: overall security posture, any gaps found, recommendations

If the results include recursive mode data (novel attack generation), also include:
6. A "Recursive Analysis" section covering: novel attack hypotheses, what was generated, what was found, and whether the recursive loop surfaced anything the static library didn't
7. A "Strategy Evolution" section analyzing how the reasoner adapted across rounds — did later hypotheses target different defenses? Did any novel attack find something library attacks missed?
8. In the results table, mark each attack as either "Library" or "Novel" to distinguish them

If the results include team mode data (multi-identity coordinated pressure), also include:
9. A "Per-Persona Breakdown" section showing: attacks attempted, caught count, uncaught count, and novel attacks generated — for each persona (Shadow, Whale, Chaos)
10. A "Coordinated Operations" section showing: for each op, the type (handoff/distributed_probe), participating personas, target defense, outcome, and outcome classification
11. Outcome classification for each coordinated op must be one of three categories:
    - "Intended behavior" — multi-identity result matches what AgentGate's per-identity design should produce
    - "Inconclusive" — result is ambiguous, possibly due to timing or insufficient signal
    - "Genuine coordinated-pressure finding" — multi-identity pressure produced enforcement inconsistency that single-identity testing did not surface
12. Keep the team analysis empirical. "No weakness found under coordinated pressure" is a valid and strong result.

If the results are from a single static pass (no strategist reasoning), generate: an executive summary (2-3 sentences), a results table showing each attack scenario with its outcome, a section on any uncaught attacks (if any) with severity and recommendations, and a final assessment of AgentGate's defense posture.`;

// ---------------------------------------------------------------------------
// Build user message
// ---------------------------------------------------------------------------

function buildUserMessage(
  results: AttackResult[],
  strategies?: StrategyResponse[],
  recursiveData?: RecursiveRoundData[],
  teamData?: TeamRoundData[],
): string {
  // Team mode — highest priority
  if (teamData && teamData.length > 0) {
    const roundSummaries = teamData.map((td) => {
      // Per-persona breakdown
      const personaBreakdown: Record<string, { attacks: number; caught: number; uncaught: number }> = {};
      for (const [name, personaResults] of td.perPersonaResults) {
        const caught = personaResults.filter((r) => r.caught).length;
        personaBreakdown[name] = {
          attacks: personaResults.length,
          caught,
          uncaught: personaResults.length - caught,
        };
      }

      // Coordinated op summaries
      const coordOps = td.coordinatedOpResults.map((cor) => ({
        type: cor.op.type,
        personas: cor.op.personas,
        targetDefense: cor.op.targetDefense,
        expectedSignal: cor.op.expectedSignal,
        whyMultiIdentity: cor.op.whyMultiIdentity,
        intel: cor.intel,
        resultCount: cor.results.length,
        caughtCount: cor.results.filter((r) => r.caught).length,
        results: cor.results.map((r) => ({
          scenarioId: r.scenarioId,
          caught: r.caught,
          actualOutcome: r.actualOutcome.slice(0, 200),
        })),
      }));

      // Novel attack summaries
      const generatedCount = td.generationOutcomes.filter((g) => g.success).length;
      const hypothesisSummaries = td.hypotheses.map((h) => ({
        id: h.id,
        description: h.description,
        targetDefense: h.targetDefense,
        targetPersona: h.targetPersona,
        confidence: h.confidence,
      }));

      const generatedCode = td.generationOutcomes
        .filter((g): g is Extract<typeof g, { success: true }> => g.success)
        .map((g) => ({
          hypothesisId: g.attack.hypothesis.id,
          targetPersona: g.attack.hypothesis.targetPersona,
          code: g.attack.code.split("\n").slice(0, 80).join("\n"),
        }));

      return {
        round: td.roundNumber,
        personaBreakdown,
        coordinatedOps: coordOps,
        hypothesesCount: td.hypotheses.length,
        generatedCount,
        executedCount: td.novelResults.length,
        hypotheses: hypothesisSummaries,
        generatedCode,
      };
    });

    return JSON.stringify({
      mode: "team",
      totalRounds: teamData.length,
      teamRounds: roundSummaries,
      allResults: results.map((r) => ({
        ...r,
        attackType: r.category === "Novel Attack" ? "Novel" : "Library",
      })),
    }, null, 2);
  }

  // Recursive mode
  if (recursiveData && recursiveData.length > 0) {
    const roundSummaries = recursiveData.map((rd) => {
      const generatedCount = rd.generationOutcomes.filter((g) => g.success).length;
      const hypothesisSummaries = rd.hypotheses.map((h) => ({
        id: h.id,
        description: h.description,
        targetDefense: h.targetDefense,
        rationale: h.rationale,
        confidence: h.confidence,
      }));

      const generatedCode = rd.generationOutcomes
        .filter((g): g is Extract<typeof g, { success: true }> => g.success)
        .map((g) => ({
          hypothesisId: g.attack.hypothesis.id,
          code: g.attack.code.split("\n").slice(0, 80).join("\n"),
        }));

      const novelOutcomes = rd.novelResults.map((r) => ({
        scenarioId: r.scenarioId,
        scenarioName: r.scenarioName,
        caught: r.caught,
        actualOutcome: r.actualOutcome,
        details: r.details,
      }));

      return {
        round: rd.roundNumber,
        hypothesesCount: rd.hypotheses.length,
        generatedCount,
        executedCount: rd.novelResults.length,
        hypotheses: hypothesisSummaries,
        generatedCode,
        novelOutcomes,
      };
    });

    return JSON.stringify({
      mode: "recursive",
      totalRounds: recursiveData.length,
      recursiveRounds: roundSummaries,
      allResults: results.map((r) => ({
        ...r,
        attackType: r.category === "Novel Attack" ? "Novel" : "Library",
      })),
    }, null, 2);
  }

  // Adaptive mode
  if (strategies && strategies.length > 0) {
    const roundData = strategies.map((strategy) => ({
      round: strategy.round,
      strategy: strategy.strategy,
      usedFallback: strategy.usedFallback || false,
      attackPicks: strategy.attacks.map((a) => ({
        id: a.id,
        reasoning: a.reasoning,
        params: a.params,
      })),
    }));

    return JSON.stringify({
      mode: "adaptive",
      totalRounds: strategies.length,
      rounds: roundData,
      allResults: results,
    }, null, 2);
  }

  // Static mode
  return JSON.stringify({
    mode: "static",
    results,
  }, null, 2);
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

export async function generateReport(
  results: AttackResult[],
  strategies?: StrategyResponse[],
  recursiveData?: RecursiveRoundData[],
  teamData?: TeamRoundData[],
): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — cannot generate report");
  }

  const client = new Anthropic({ apiKey });

  const userMessage = buildUserMessage(results, strategies, recursiveData, teamData);

  const response = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 8000,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: userMessage,
      },
    ],
  });

  const textBlock = response.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from Claude API");
  }

  return textBlock.text;
}
