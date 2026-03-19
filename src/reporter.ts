// Generates a human-readable findings report from attack results via Claude API

import Anthropic from "@anthropic-ai/sdk";
import type { AttackResult } from "./log";

export async function generateReport(results: AttackResult[]): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — cannot generate report");
  }

  const client = new Anthropic({ apiKey });

  const response = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 2000,
    system: "You are a security auditor analyzing red team results against AgentGate, a collateralized execution engine for AI agents. Generate a concise, structured findings report. Include: an executive summary (2-3 sentences), a results table showing each attack scenario with its outcome, a section on any uncaught attacks (if any) with severity and recommendations, and a final assessment of AgentGate's defense posture. Be direct and factual. Do not pad the report.",
    messages: [
      {
        role: "user",
        content: JSON.stringify(results, null, 2),
      },
    ],
  });

  const textBlock = response.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from Claude API");
  }

  return textBlock.text;
}
