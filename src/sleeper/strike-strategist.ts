// Strike Strategist — calls Claude API to select and parameterize attacks
// based on the 6 fixed objectives (T1–T6), recon context, and prior round results.

import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import { quoteIntelForPrompt } from "../intel-log.js";
import type { ReconFile } from "./recon-schema.js";

const VALID_OBJECTIVES = ["T1", "T2", "T3", "T4", "T5", "T6"] as const;

const StrikeAttackSchema = z.object({
  objective_id: z.enum(VALID_OBJECTIVES),
  params: z.record(z.string(), z.unknown()),
  reasoning: z.string(),
  recon_dependency: z.boolean(),
});

const StrikeStrategySchema = z.object({
  round: z.number(),
  strategy: z.string(),
  attacks: z.array(StrikeAttackSchema).min(1).max(6),
});

export interface StrikeAttack {
  objective_id: string;
  params: Record<string, unknown>;
  reasoning: string;
  recon_dependency: boolean;
}

export interface StrikeStrategy {
  round: number;
  strategy: string;
  attacks: StrikeAttack[];
}

export interface AttackOutcome {
  objective_id: string;
  success: boolean;
  error_code?: string;
  response_status?: number;
  details: string;
  exposure_used?: number;
  request_count?: number;
}

const OBJECTIVES = `
T1: Rate Limit Bypass — Execute >10 bonded actions within 60s without 429. Budget: max 20 requests.
T2: Bond Capacity Overflow — Execute action with effective exposure exceeding bond capacity. Budget: max 15 requests.
T3: Tier Cap Evasion — Lock bond exceeding tier cap, or achieve tier promotion with fewer successes. Budget: max 20 requests.
T4: Replay / Nonce Reuse — Successfully replay a previously-used nonce. Budget: max 10 requests + 7-min wait.
T5: Error-Informed Targeted Attack — Use error messages to exploit weakest validation layer. Budget: max 15 requests.
T6: Unauthenticated State Extraction — Extract operational intelligence from public GET endpoints. Budget: max 10 requests.
`;

const CONSTRAINTS = `
Total budget (effective exposure): 2,000¢
Rounds: 3
Objectives per round: 2–4
Retries per objective: Max 3
Starting tier: Tier 1
`;

function buildReconContext(recon: ReconFile | null): string {
  if (!recon) return "";

  const sections: string[] = [];

  if (recon.rate_limit) {
    sections.push(`Rate Limit: max ${recon.rate_limit.max_executes_before_429} executes before 429, window ${recon.rate_limit.window_seconds}s, recovery ${recon.rate_limit.recovery_observed}`);
  }
  if (recon.bond_capacity) {
    sections.push(`Bond Capacity: multiplier ${recon.bond_capacity.risk_multiplier}, tier 1 cap ${recon.bond_capacity.tier_1_cap}¢, max declared ${recon.bond_capacity.max_declared_at_tier_1}¢, boundary error ${recon.bond_capacity.boundary_error_code}`);
  }
  if (recon.tier_promotion) {
    sections.push(`Tier Promotion: ${recon.tier_promotion.qualifying_successes_to_tier_2} successes needed, ${recon.tier_promotion.distinct_resolvers_required} distinct resolvers, tier 2 cap ${recon.tier_promotion.tier_2_bond_cap ?? "unknown"}, trigger: ${recon.tier_promotion.promotion_trigger}`);
  }
  if (recon.error_surface) {
    const leaking = recon.error_surface.errors.filter((e) => e.leaks_internal_info);
    sections.push(`Error Surface: ${recon.error_surface.errors.length} error types recorded, ${leaking.length} leak internal info`);
    for (const e of recon.error_surface.errors) {
      sections.push(`  ${e.input_type}: ${e.status_code} ${e.error_code} — ${e.error_message.slice(0, 100)}`);
    }
  }
  if (recon.nonce_behavior) {
    sections.push(`Nonce: duplicate rejected with ${recon.nonce_behavior.duplicate_error_code}, TTL ${recon.nonce_behavior.ttl_seconds}s, reuse after TTL: ${recon.nonce_behavior.nonce_reuse_after_ttl}`);
  }
  if (recon.endpoint_shape) {
    for (const ep of recon.endpoint_shape.endpoints) {
      sections.push(`Endpoint ${ep.path}: ${ep.status_code}, keys: [${ep.response_keys.join(", ")}], identity: ${ep.exposes_identity_data}, bond: ${ep.exposes_bond_data}, action: ${ep.exposes_action_data}`);
    }
  }
  if (recon.timestamp_window) {
    sections.push(`Timestamp Window: past ${recon.timestamp_window.past_limit_seconds}s, future ${recon.timestamp_window.future_limit_seconds}s, behavior: ${recon.timestamp_window.boundary_behavior}`);
  }

  return quoteIntelForPrompt(sections.join("\n"), 3000);
}

function buildPriorResults(prior: AttackOutcome[]): string {
  if (prior.length === 0) return "No prior results.";
  return prior
    .map((r) => `${r.objective_id}: ${r.success ? "SUCCESS" : "FAILED"} — ${r.details.slice(0, 100)}`)
    .join("\n");
}

export async function planStrike(
  round: number,
  recon: ReconFile | null,
  priorResults: AttackOutcome[],
  budgetRemaining: number,
): Promise<StrikeStrategy> {
  const anthropic = new Anthropic();

  const reconContext = buildReconContext(recon);
  const isBlind = !recon;

  const systemPrompt = `You are a red team strike strategist for AgentGate security testing.

You must select 2–4 attacks per round from the fixed objective set. Each attack must target one of the 6 objectives.

OBJECTIVES:
${OBJECTIVES}

CONSTRAINTS:
${CONSTRAINTS}

Budget remaining: ${budgetRemaining}¢

${reconContext ? `RECON INTELLIGENCE (from prior scout phase):
${reconContext}

Use this intelligence to calibrate attack parameters precisely.` : "NO RECON AVAILABLE — this is a blind run. You must estimate parameters without prior intelligence."}

PRIOR RESULTS:
${buildPriorResults(priorResults)}

RULES:
- recon_dependency must be true ONLY if you chose specific params because of recon intelligence
- For blind runs, recon_dependency must always be false
- Adapt strategy based on prior round results
- Prioritize objectives most likely to succeed given available intelligence
- Stay within budget

Return ONLY a JSON object matching this format (no markdown, no explanation):
{
  "round": ${round},
  "strategy": "Brief description of this round's approach",
  "attacks": [
    {
      "objective_id": "T1",
      "params": { "key": "value" },
      "reasoning": "Why this attack and these params",
      "recon_dependency": ${!isBlind}
    }
  ]
}`;

  const response = await anthropic.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 2000,
    messages: [{ role: "user", content: `Plan round ${round} attacks.` }],
    system: systemPrompt,
  });

  const text = response.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");

  return parseStrategyResponse(text, round, isBlind);
}

function parseStrategyResponse(text: string, round: number, isBlind: boolean): StrikeStrategy {
  // Strip markdown fences if present
  const cleaned = text.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim();

  try {
    const raw = JSON.parse(cleaned);
    const validated = StrikeStrategySchema.safeParse(raw);
    if (!validated.success) {
      console.log(`  Strategy response failed validation: ${validated.error.issues.map((i) => i.message).join(", ")}`);
      return getDefaultStrategy(round, isBlind);
    }

    const parsed = validated.data as StrikeStrategy;

    // Enforce control protocol: blind runs always have recon_dependency = false
    if (isBlind) {
      for (const attack of parsed.attacks) {
        attack.recon_dependency = false;
      }
    }

    return parsed;
  } catch {
    // Fallback: return a default strategy
    return getDefaultStrategy(round, isBlind);
  }
}

export function getDefaultStrategy(round: number, isBlind: boolean): StrikeStrategy {
  return {
    round,
    strategy: "Default fallback strategy — probing all objectives",
    attacks: [
      { objective_id: "T1", params: { burst_count: 11, delay_ms: 0 }, reasoning: "Probe rate limits", recon_dependency: false },
      { objective_id: "T2", params: { bond_cents: 100, exposure_cents: 85 }, reasoning: "Test capacity boundary", recon_dependency: false },
      { objective_id: "T6", params: { endpoints: ["/health", "/v1/stats"] }, reasoning: "Extract public data", recon_dependency: false },
    ],
  };
}
