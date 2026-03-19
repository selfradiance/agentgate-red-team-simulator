// MCP transport abuse scenarios — tests AgentGate's MCP endpoint (port 3001) security

import { randomUUID } from "node:crypto";
import type { AttackResult } from "../log";
import type { AttackScenario, AttackClient, AttackParams } from "./replay";

const CATEGORY = "MCP Transport Abuse";

// ---------------------------------------------------------------------------
// Helper — derive MCP URL from the AgentGate REST URL (port 3000 → 3001)
// ---------------------------------------------------------------------------

function getMcpUrl(agentGateUrl: string): string {
  const url = new URL(agentGateUrl);
  url.port = "3001";
  return url.toString().replace(/\/$/, "");
}

// ---------------------------------------------------------------------------
// Attack 9.1: MCP without auth key
// ---------------------------------------------------------------------------

async function attack9_1(client: AttackClient, _params?: AttackParams): Promise<AttackResult> {
  const mcpUrl = getMcpUrl(client.agentGateUrl);
  const mcpEndpoint = `${mcpUrl}/mcp`;

  // Send a POST to the MCP endpoint without x-agentgate-key
  let response: Response;
  try {
    response = await fetch(mcpEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: randomUUID(),
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "agent-004-red-team", version: "0.1.0" },
        },
      }),
    });
  } catch (err) {
    return {
      scenarioId: "9.1",
      scenarioName: "MCP without auth key",
      category: CATEGORY,
      expectedOutcome: "Rejected — missing x-agentgate-key",
      actualOutcome: `Connection failed: ${err instanceof Error ? err.message : String(err)}`,
      caught: true,
      details: `Could not reach MCP endpoint at ${mcpEndpoint} — port 3001 may not be running or reachable. This is expected if MCP is not enabled.`,
    };
  }

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    const text = await response.text().catch(() => "(empty)");
    data = { error: "UNPARSEABLE_RESPONSE", message: text };
  }

  const caught = response.status >= 400;
  return {
    scenarioId: "9.1",
    scenarioName: "MCP without auth key",
    category: CATEGORY,
    expectedOutcome: "Rejected — missing x-agentgate-key on MCP endpoint",
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `MCP endpoint rejected the unauthenticated request (${response.status}).`
      : `MCP endpoint accepted a request without x-agentgate-key — MCP auth may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 9.2: MCP session exhaustion
// ---------------------------------------------------------------------------

async function attack9_2(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const sessionCount = (typeof params?.session_count === "number" ? params.session_count : 105);
  const mcpUrl = getMcpUrl(client.agentGateUrl);
  const mcpEndpoint = `${mcpUrl}/mcp`;

  // Try to open many concurrent MCP sessions (cap is 100)
  const results: { index: number; status: number }[] = [];

  const promises = Array.from({ length: sessionCount }, async (_, i) => {
    try {
      const response = await fetch(mcpEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agentgate-key": client.apiKey,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: randomUUID(),
          method: "initialize",
          params: {
            protocolVersion: "2025-03-26",
            capabilities: {},
            clientInfo: { name: `agent-004-session-${i}`, version: "0.1.0" },
          },
        }),
      });
      results.push({ index: i, status: response.status });
    } catch {
      results.push({ index: i, status: 0 }); // connection failed
    }
  });

  await Promise.all(promises);

  const succeeded = results.filter((r) => r.status >= 200 && r.status < 300).length;
  const rejected = results.filter((r) => r.status >= 400).length;
  const failed = results.filter((r) => r.status === 0).length;

  // If MCP is unreachable, that's informative but not a failure
  if (failed === sessionCount) {
    return {
      scenarioId: "9.2",
      scenarioName: "MCP session exhaustion",
      category: CATEGORY,
      expectedOutcome: `${sessionCount} sessions — cap is 100, excess should be rejected`,
      actualOutcome: `All ${sessionCount} connections failed — MCP port 3001 not reachable`,
      caught: true,
      details: `MCP endpoint not reachable at ${mcpEndpoint}. Port 3001 may not be running. This is expected if MCP is not enabled.`,
    };
  }

  const caught = rejected > 0 || succeeded <= 100;
  return {
    scenarioId: "9.2",
    scenarioName: "MCP session exhaustion",
    category: CATEGORY,
    expectedOutcome: `${sessionCount} sessions — cap is 100, excess should be rejected`,
    actualOutcome: `${succeeded} succeeded, ${rejected} rejected, ${failed} connection failures`,
    caught,
    details: caught
      ? `MCP session cap enforced — ${succeeded} sessions accepted, ${rejected} rejected beyond the 100-session cap.`
      : `All ${succeeded} sessions accepted — session cap may not be enforced.`,
  };
}

// ---------------------------------------------------------------------------
// Attack 9.3: MCP malformed/oversized request
// ---------------------------------------------------------------------------

async function attack9_3(client: AttackClient, params?: AttackParams): Promise<AttackResult> {
  const abuseType = (typeof params?.abuse_type === "string" ? params.abuse_type : "oversized");
  const mcpUrl = getMcpUrl(client.agentGateUrl);
  const mcpEndpoint = `${mcpUrl}/mcp`;

  let body: string;

  if (abuseType === "oversized") {
    // >1MB body (MCP has 1MB limit)
    const oversizedData = "X".repeat(1_100_000);
    body = JSON.stringify({
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "tools/call",
      params: { name: "test", arguments: { data: oversizedData } },
    });
  } else if (abuseType === "invalid-method") {
    body = JSON.stringify({
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "nonexistent/attack-method",
      params: {},
    });
  } else {
    // malformed — not valid JSON-RPC
    body = JSON.stringify({
      not_jsonrpc: true,
      garbage: "malformed payload",
      id: 12345,
    });
  }

  let response: Response;
  try {
    response = await fetch(mcpEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agentgate-key": client.apiKey,
      },
      body,
    });
  } catch (err) {
    return {
      scenarioId: "9.3",
      scenarioName: "MCP malformed/oversized request",
      category: CATEGORY,
      expectedOutcome: `Rejected — ${abuseType} MCP request`,
      actualOutcome: `Connection failed: ${err instanceof Error ? err.message : String(err)}`,
      caught: true,
      details: `Could not reach MCP endpoint at ${mcpEndpoint} — port 3001 may not be running. This is expected if MCP is not enabled.`,
    };
  }

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    const text = await response.text().catch(() => "(empty)");
    data = { error: "UNPARSEABLE_RESPONSE", message: text };
  }

  const caught = response.status >= 400;
  return {
    scenarioId: "9.3",
    scenarioName: "MCP malformed/oversized request",
    category: CATEGORY,
    expectedOutcome: `Rejected — ${abuseType} MCP request`,
    actualOutcome: `${response.status} ${JSON.stringify(data)}`,
    caught,
    details: caught
      ? `MCP endpoint rejected the ${abuseType} request (${response.status}).`
      : `MCP endpoint accepted the ${abuseType} request — ${abuseType} validation may be missing.`,
  };
}

// ---------------------------------------------------------------------------
// Exported scenario list
// ---------------------------------------------------------------------------

export const mcpAttacks: AttackScenario[] = [
  {
    id: "9.1",
    name: "MCP without auth key",
    category: CATEGORY,
    description: "Hit /mcp on port 3001 without x-agentgate-key header",
    expectedOutcome: "rejected — missing auth key",
    execute: (client, params?) => attack9_1(client, params),
  },
  {
    id: "9.2",
    name: "MCP session exhaustion",
    category: CATEGORY,
    description: "Open 100+ concurrent MCP sessions to test session cap enforcement",
    expectedOutcome: "excess sessions rejected beyond 100-session cap",
    execute: (client, params?) => attack9_2(client, params),
  },
  {
    id: "9.3",
    name: "MCP malformed/oversized request",
    category: CATEGORY,
    description: "Send oversized (>1MB), invalid method, or malformed payloads to MCP",
    expectedOutcome: "rejected — invalid MCP request",
    execute: (client, params?) => attack9_3(client, params),
  },
];
