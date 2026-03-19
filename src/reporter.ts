// Generates a human-readable findings report from attack results via Claude API

import Anthropic from "@anthropic-ai/sdk";
import type { AttackResult } from "./log";
import type { StrategyResponse } from "./strategist";

const SYSTEM_PROMPT = `You are a security auditor analyzing red team results against AgentGate, a collateralized execution engine for AI agents. Generate a concise, structured findings report. Be direct and factual. Do not pad the report.

If the results span multiple rounds with strategist reasoning, your report should include:
1. An executive summary of the overall red team engagement
2. A per-round breakdown showing: the strategist's stated strategy, which attacks were selected and why, and what was caught/uncaught
3. A strategy evolution analysis: how did the strategist adapt between rounds? Did it escalate appropriately? Did it discover any attack chains?
4. A results table covering ALL attacks across all rounds
5. A final assessment: overall security posture, any gaps found, recommendations

If the results are from a single static pass (no strategist reasoning), generate: an executive summary (2-3 sentences), a results table showing each attack scenario with its outcome, a section on any uncaught attacks (if any) with severity and recommendations, and a final assessment of AgentGate's defense posture.`;

export async function generateReport(
  results: AttackResult[],
  strategies?: StrategyResponse[],
): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — cannot generate report");
  }

  const client = new Anthropic({ apiKey });

  // Build user message — structured differently for adaptive vs static
  let userMessage: string;

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

    userMessage = JSON.stringify({
      mode: "adaptive",
      totalRounds: strategies.length,
      rounds: roundData,
      allResults: results,
    }, null, 2);
  } else {
    userMessage = JSON.stringify({
      mode: "static",
      results,
    }, null, 2);
  }

  const response = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 4000,
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
