// Generator — turns attack hypotheses into validated JavaScript attack functions.
// Calls Claude API to generate code, validates it, retries once on failure.

import Anthropic from "@anthropic-ai/sdk";
import type { AttackHypothesis } from "./reasoner";
import { validateGeneratedCode, checkNovelty, type ValidationResult } from "./sandbox/validator";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GeneratedAttack {
  hypothesis: AttackHypothesis;
  code: string;
  validationResult: ValidationResult;
}

export interface GenerationFailure {
  hypothesis: AttackHypothesis;
  reason: string;
}

export type GenerationResult =
  | { success: true; attack: GeneratedAttack }
  | { success: false; failure: GenerationFailure };

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a red team code generator. You write JavaScript attack functions that probe security defenses of AgentGate, a bonded execution engine for AI agents. Your output must be a single JavaScript function and nothing else — no markdown fences, no explanation, no preamble.`;

// ---------------------------------------------------------------------------
// Build user message
// ---------------------------------------------------------------------------

function buildUserMessage(hypothesis: AttackHypothesis, retryReason?: string): string {
  const parts: string[] = [];

  if (retryReason) {
    parts.push(`Your previous output was rejected by the validator:`);
    parts.push(`Reason: ${retryReason}`);
    parts.push("");
    parts.push("Please fix the issue and output ONLY the corrected function.");
    parts.push("");
  }

  parts.push("Attack hypothesis:");
  parts.push(`- Description: ${hypothesis.description}`);
  parts.push(`- Target defense: ${hypothesis.targetDefense}`);
  parts.push(`- Rationale: ${hypothesis.rationale}`);
  parts.push("");

  parts.push(`Available toolkit methods (these are the ONLY functions you can call):
- toolkit.signedPost(path, body) — Makes a signed HTTP POST to AgentGate. Returns { status, body }.
- toolkit.rawPost(path, body, headers) — Makes an unsigned POST with custom headers. Returns { status, body }.
- toolkit.rawGet(path) — Makes a GET request. Returns { status, body }.
- toolkit.createIdentity() — Creates a new Ed25519 identity on AgentGate. Returns { identityId, publicKey, privateKey }. Max 3 per attack.
- toolkit.signedPostAs(identity, path, body) — Makes a signed POST as a specific identity (from createIdentity). Returns { status, body }.
- toolkit.sleep(ms) — Waits for ms milliseconds. Max 5000ms.
- toolkit.getReputation(identityId) — Gets reputation score. Returns { score, ... }.
- toolkit.getBondStatus(bondId) — Gets bond state. Returns { status, ... }.
- toolkit.getActionStatus(actionId) — Gets action state. Returns { status, ... }.
- toolkit.checkDashboardForRawHtml() — Checks dashboard for XSS/unescaped content. Returns { foundRawHtml, details? }.
- toolkit.log(message) — Logs a message (visible to the operator).`);
  parts.push("");

  parts.push(`CONSTRAINTS — you MUST follow all of these:
1. Output ONLY the function. No markdown, no explanation, no backticks.
2. Function signature must be exactly: async function novelAttack(toolkit) { ... }
3. Use ONLY the toolkit methods listed above. Do NOT use require, import, fetch, fs, process, eval, Function, setTimeout, setInterval, or any Node.js built-in.
4. Return an object: { caught: boolean, reason: string, sideEffects?: object }
   - caught = true means AgentGate blocked the attack (the defense held)
   - caught = false means the attack got through (a potential vulnerability)
5. Include toolkit.log() calls to explain what you're doing at each step.
6. Keep it focused — one attack idea, well-executed.`);
  parts.push("");

  parts.push(`IMPORTANT — AgentGate API reference (use these exact paths and field names):
- Lock bond: POST /v1/bonds/lock { identityId, amountCents, currency: "USD", ttlSeconds, reason } → returns { bondId }
- Execute action: POST /v1/actions/execute { identityId, bondId, actionType, payload, exposure_cents } → returns { actionId }
- Resolve action: POST /v1/actions/{actionId}/resolve { outcome: "success"|"failed"|"malicious" }
- Create identity: POST /v1/identities { publicKey } → returns { identityId }
Note: field names are camelCase (amountCents, ttlSeconds, bondId, actionType, actionId). Do NOT use snake_case (amount_cents, ttl_seconds, bond_id, action_type).`);
  parts.push("");

  parts.push(`Example 1 (boundary probe):
async function novelAttack(toolkit) {
  toolkit.log("Testing bond capacity at exact 1.2x boundary");
  var identity = await toolkit.createIdentity();
  var bond = await toolkit.signedPostAs(identity, '/v1/bonds/lock', { identityId: identity.identityId, amountCents: 100, currency: 'USD', ttlSeconds: 300, reason: 'boundary-test' });
  if (bond.status >= 300) return { caught: true, reason: 'Bond creation failed: ' + bond.status };
  var bondId = bond.body.bondId;
  toolkit.log("Bond locked: " + bondId);
  var result = await toolkit.signedPostAs(identity, '/v1/actions/execute', { identityId: identity.identityId, bondId: bondId, actionType: 'test', payload: {}, exposure_cents: 84 });
  toolkit.log("Boundary execute returned: " + result.status);
  var caught = result.status >= 300;
  return { caught: caught, reason: caught ? 'Capacity boundary enforced at 84 cents' : 'Boundary execute succeeded unexpectedly' };
}`);
  parts.push("");

  parts.push(`Example 2 (cross-identity probe):
async function novelAttack(toolkit) {
  toolkit.log("Testing if identity B can resolve identity A's action");
  var identityA = await toolkit.createIdentity();
  var identityB = await toolkit.createIdentity();
  var bond = await toolkit.signedPostAs(identityA, '/v1/bonds/lock', { identityId: identityA.identityId, amountCents: 100, currency: 'USD', ttlSeconds: 300, reason: 'cross-id-test' });
  if (bond.status >= 300) return { caught: true, reason: 'Bond creation failed' };
  var action = await toolkit.signedPostAs(identityA, '/v1/actions/execute', { identityId: identityA.identityId, bondId: bond.body.bondId, actionType: 'test', payload: {}, exposure_cents: 50 });
  if (action.status >= 300) return { caught: true, reason: 'Action creation failed' };
  var resolve = await toolkit.signedPostAs(identityB, '/v1/actions/' + action.body.actionId + '/resolve', { outcome: 'success' });
  var caught = resolve.status >= 300;
  return { caught: caught, reason: caught ? 'Cross-identity resolve blocked' : 'Identity B resolved A\\'s action!' };
}`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Strip markdown fences
// ---------------------------------------------------------------------------

export function stripFences(text: string): string {
  let cleaned = text.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:javascript|js|typescript|ts)?\s*\n?/, "").replace(/\n?```\s*$/, "");
  }
  return cleaned.trim();
}

// ---------------------------------------------------------------------------
// Call Claude API for code generation
// ---------------------------------------------------------------------------

async function callGeneratorApi(
  hypothesis: AttackHypothesis,
  retryReason?: string,
): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — cannot generate attack code");
  }

  const client = new Anthropic({ apiKey });

  const response = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 2000,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: buildUserMessage(hypothesis, retryReason),
      },
    ],
  });

  const textBlock = response.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from Claude API");
  }

  return stripFences(textBlock.text);
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

export async function generateAttack(
  hypothesis: AttackHypothesis,
  existingRegistry: Map<string, { name: string; description: string }> | null,
): Promise<GenerationResult> {
  try {
    // First attempt
    let code = await callGeneratorApi(hypothesis);
    let validation = validateGeneratedCode(code);

    // Retry once if validation fails
    if (!validation.valid) {
      try {
        code = await callGeneratorApi(hypothesis, validation.reason);
        validation = validateGeneratedCode(code);
      } catch (retryErr) {
        return {
          success: false,
          failure: {
            hypothesis,
            reason: `Validation failed, retry API error: ${retryErr instanceof Error ? retryErr.message : String(retryErr)}`,
          },
        };
      }

      if (!validation.valid) {
        return {
          success: false,
          failure: {
            hypothesis,
            reason: `Validation failed after retry: ${validation.reason}`,
          },
        };
      }
    }

    // Novelty check (no retry — if description is too similar, the hypothesis is the problem)
    const novelty = checkNovelty(code, hypothesis.description, existingRegistry);
    if (!novelty.valid) {
      return {
        success: false,
        failure: {
          hypothesis,
          reason: novelty.reason || "Failed novelty check",
        },
      };
    }

    return {
      success: true,
      attack: { hypothesis, code, validationResult: validation },
    };
  } catch (err) {
    return {
      success: false,
      failure: {
        hypothesis,
        reason: `API error: ${err instanceof Error ? err.message : String(err)}`,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Exported for testing: validate + novelty check on pre-generated code
// ---------------------------------------------------------------------------

export function validateAndCheck(
  code: string,
  hypothesis: AttackHypothesis,
  existingRegistry: Map<string, { name: string; description: string }> | null,
): GenerationResult {
  const validation = validateGeneratedCode(code);
  if (!validation.valid) {
    return {
      success: false,
      failure: { hypothesis, reason: `Validation failed: ${validation.reason}` },
    };
  }

  const novelty = checkNovelty(code, hypothesis.description, existingRegistry);
  if (!novelty.valid) {
    return {
      success: false,
      failure: { hypothesis, reason: novelty.reason || "Failed novelty check" },
    };
  }

  return {
    success: true,
    attack: { hypothesis, code, validationResult: validation },
  };
}
