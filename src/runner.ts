// Runs all attack scenarios against a live AgentGate instance

import { AttackLog } from "./log";
import type { AttackClient, AttackScenario } from "./attacks/replay";
import { replayAttacks } from "./attacks/replay";
import { bondCapacityAttacks } from "./attacks/bond-capacity";
import { signatureAttacks } from "./attacks/signature";
import { authorizationAttacks } from "./attacks/authorization";
import { inputValidationAttacks } from "./attacks/input-validation";
import { rateLimitAttacks } from "./attacks/rate-limit";
import { timingAttacks } from "./attacks/timing";
import { protocolAttacks } from "./attacks/protocol";
import { mcpAttacks } from "./attacks/mcp";

const allScenarios: AttackScenario[] = [
  ...replayAttacks,
  ...bondCapacityAttacks,
  ...signatureAttacks,
  ...authorizationAttacks,
  ...inputValidationAttacks,
  ...rateLimitAttacks,
  ...timingAttacks,
  ...protocolAttacks,
  ...mcpAttacks,
];

export async function runAttacks(client: AttackClient): Promise<AttackLog> {
  const log = new AttackLog();

  for (const scenario of allScenarios) {
    console.log(`Running attack [${scenario.id}]: ${scenario.name}...`);

    try {
      const result = await scenario.execute(client);
      log.record(result);

      if (result.caught) {
        console.log("  → [CAUGHT]");
      } else {
        console.log("  → [UNCAUGHT] ⚠️");
      }
    } catch (err) {
      const result = {
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        category: scenario.category,
        expectedOutcome: scenario.expectedOutcome,
        actualOutcome: `Error: ${err instanceof Error ? err.message : String(err)}`,
        caught: false,
        details: `Attack threw an unexpected error: ${err instanceof Error ? err.message : String(err)}`,
      };
      log.record(result);
      console.log(`  → [ERROR] ${result.actualOutcome}`);
    }
  }

  return log;
}
