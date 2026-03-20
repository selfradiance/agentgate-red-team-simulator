// Generates a human-readable findings report from attack results via Claude API

import Anthropic from "@anthropic-ai/sdk";
import type { AttackResult } from "./log";
import type { StrategyResponse } from "./strategist";
import type { AttackHypothesis } from "./reasoner";
import type { GenerationResult } from "./generator";

// ---------------------------------------------------------------------------
// Types for recursive mode data
// ---------------------------------------------------------------------------

export interface RecursiveRoundData {
  roundNumber: number;
  hypotheses: AttackHypothesis[];
  generationOutcomes: GenerationResult[];
  novelResults: AttackResult[];
}

// ---------------------------------------------------------------------------
// System prompts
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

If the results are from a single static pass (no strategist reasoning), generate: an executive summary (2-3 sentences), a results table showing each attack scenario with its outcome, a section on any uncaught attacks (if any) with severity and recommendations, and a final assessment of AgentGate's defense posture.`;

// ---------------------------------------------------------------------------
// Build user message
// ---------------------------------------------------------------------------

function buildUserMessage(
  results: AttackResult[],
  strategies?: StrategyResponse[],
  recursiveData?: RecursiveRoundData[],
): string {
  if (recursiveData && recursiveData.length > 0) {
    // Recursive mode — includes library + novel attacks + reasoning
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

  if (strategies && strategies.length > 0) {
    // Adaptive mode
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
): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — cannot generate report");
  }

  const client = new Anthropic({ apiKey });

  const userMessage = buildUserMessage(results, strategies, recursiveData);

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
