// Swarm identity management for Stage 5 — three teams of three agents
// (9 identities total) with distinct strategic objectives and a three-layer
// budget model (per-agent, per-team, campaign cap).

import { generateKeyPairSync, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { signRequest, type AgentKeys } from "./agentgate-client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SwarmTeamName = "alpha" | "beta" | "gamma";

export interface SwarmAgentConfig {
  agentId: string;           // e.g., "alpha-1", "beta-3"
  team: SwarmTeamName;
  identityFilePath: string;  // e.g., "swarm-identity-alpha-1.json"
  bondBudgetCents: number;
}

export interface SwarmTeam {
  name: SwarmTeamName;
  objective: string;
  agents: [SwarmAgentConfig, SwarmAgentConfig, SwarmAgentConfig];
  teamBudgetCents: number;
}

export interface SwarmConfig {
  teams: [SwarmTeam, SwarmTeam, SwarmTeam];
  campaignCapCents: number;
}

export interface SwarmAgentIdentity {
  config: SwarmAgentConfig;
  keys: AgentKeys;
  identityId: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const AGENT_BUDGETS: Record<SwarmTeamName, number> = {
  alpha: 50,
  beta: 100,
  gamma: 150,
};

const TEAM_OBJECTIVES: Record<SwarmTeamName, string> = {
  alpha: "Reconnaissance — map defenses, discover endpoints, probe timing",
  beta: "Trust exploitation — build reputation, then exploit trust assumptions",
  gamma: "Coordinated pressure — synchronized attacks to overwhelm per-identity defenses",
};

const CAMPAIGN_CAP_CENTS = 900;

function buildAgentConfig(team: SwarmTeamName, index: number): SwarmAgentConfig {
  const agentId = `${team}-${index}`;
  return {
    agentId,
    team,
    identityFilePath: `swarm-identity-${agentId}.json`,
    bondBudgetCents: AGENT_BUDGETS[team],
  };
}

function buildTeam(name: SwarmTeamName): SwarmTeam {
  const agents: [SwarmAgentConfig, SwarmAgentConfig, SwarmAgentConfig] = [
    buildAgentConfig(name, 1),
    buildAgentConfig(name, 2),
    buildAgentConfig(name, 3),
  ];
  return {
    name,
    objective: TEAM_OBJECTIVES[name],
    agents,
    teamBudgetCents: agents.reduce((sum, a) => sum + a.bondBudgetCents, 0),
  };
}

export function getSwarmConfig(): SwarmConfig {
  return {
    teams: [buildTeam("alpha"), buildTeam("beta"), buildTeam("gamma")],
    campaignCapCents: CAMPAIGN_CAP_CENTS,
  };
}

// ---------------------------------------------------------------------------
// Identity file helpers (same patterns as personas.ts)
// ---------------------------------------------------------------------------

interface SavedSwarmIdentity {
  publicKey: string;
  privateKey: string;
  identityId?: string;
}

function resolveIdentityPath(config: SwarmAgentConfig): string {
  return path.resolve(config.identityFilePath);
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

function loadKeypairFromFile(filePath: string): AgentKeys | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    const data: SavedSwarmIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (data.publicKey && data.privateKey) {
      return { publicKey: data.publicKey, privateKey: data.privateKey };
    }
  } catch {
    // Corrupted file — will regenerate
  }
  return null;
}

function loadIdentityIdFromFile(filePath: string): string | undefined {
  if (!fs.existsSync(filePath)) return undefined;
  try {
    const data: SavedSwarmIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return data.identityId;
  } catch {
    return undefined;
  }
}

function saveKeypairToFile(filePath: string, keys: AgentKeys): void {
  fs.writeFileSync(filePath, JSON.stringify(keys, null, 2), { encoding: "utf8", mode: 0o600 });
}

function saveIdentityIdToFile(filePath: string, identityId: string): void {
  const data: SavedSwarmIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
  data.identityId = identityId;
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), { encoding: "utf8", mode: 0o600 });
}

function generateKeypair(): AgentKeys {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });

  if (!publicJwk.x || !privateJwk.d) {
    throw new Error("Failed to export Ed25519 keypair as JWK");
  }

  return {
    publicKey: base64UrlToBase64(publicJwk.x),
    privateKey: base64UrlToBase64(privateJwk.d),
  };
}

async function registerIdentityOnAgentGate(
  keys: AgentKeys,
  agentGateUrl: string,
  restKey: string,
): Promise<string> {
  const nonce = randomUUID();
  const timestamp = Date.now().toString();
  const apiPath = "/v1/identities";
  const body = { publicKey: keys.publicKey };
  const signature = signRequest(keys.publicKey, keys.privateKey, nonce, "POST", apiPath, timestamp, body);

  const response = await fetch(new URL(apiPath, agentGateUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nonce": nonce,
      "x-agentgate-key": restKey,
      "x-agentgate-timestamp": timestamp,
      "x-agentgate-signature": signature,
    },
    body: JSON.stringify(body),
  });

  const data = await response.json() as Record<string, unknown>;

  if (!response.ok) {
    if (response.status === 409) {
      throw new Error(
        `Identity already registered but ID not saved locally. Delete ${keys.publicKey.slice(0, 8)}... identity file and try again, or use --fresh-swarm.`,
      );
    }
    throw new Error(`Identity registration failed (${response.status}): ${JSON.stringify(data)}`);
  }

  if (typeof data.identityId !== "string") {
    throw new Error(`No identityId returned: ${JSON.stringify(data)}`);
  }

  return data.identityId as string;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Return all 9 SwarmAgentConfig objects across all 3 teams.
 */
export function getAllAgentConfigs(): SwarmAgentConfig[] {
  const config = getSwarmConfig();
  return config.teams.flatMap((t) => t.agents);
}

/**
 * Load or create a single swarm agent's identity. If the identity file exists
 * with a saved identityId, reuse it. Otherwise generate a new keypair and
 * register it on AgentGate.
 */
export async function loadOrCreateSwarmAgentIdentity(
  config: SwarmAgentConfig,
  agentGateUrl: string,
  restKey: string,
): Promise<SwarmAgentIdentity> {
  const filePath = resolveIdentityPath(config);

  let keys = loadKeypairFromFile(filePath);
  if (!keys) {
    keys = generateKeypair();
    saveKeypairToFile(filePath, keys);
  }

  let identityId = loadIdentityIdFromFile(filePath);
  if (!identityId) {
    identityId = await registerIdentityOnAgentGate(keys, agentGateUrl, restKey);
    saveIdentityIdToFile(filePath, identityId);
  }

  return { config, keys, identityId };
}

/**
 * Delete all 9 swarm identity files (for --fresh-swarm).
 */
export function deleteSwarmIdentities(): void {
  for (const agentConfig of getAllAgentConfigs()) {
    const filePath = resolveIdentityPath(agentConfig);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}

/**
 * Create all 9 swarm identities on AgentGate (or load from files).
 * Returns a flat array of all 9 SwarmAgentIdentity objects.
 */
export async function createSwarmIdentities(
  agentGateUrl: string,
  restKey: string,
  freshSwarm: boolean = false,
): Promise<SwarmAgentIdentity[]> {
  if (freshSwarm) {
    deleteSwarmIdentities();
  }

  const identities: SwarmAgentIdentity[] = [];
  for (const agentConfig of getAllAgentConfigs()) {
    const identity = await loadOrCreateSwarmAgentIdentity(agentConfig, agentGateUrl, restKey);
    identities.push(identity);
  }

  return identities;
}

/**
 * Find a swarm agent identity by agentId (e.g., "alpha-1").
 */
export function getSwarmAgent(
  identities: SwarmAgentIdentity[],
  agentId: string,
): SwarmAgentIdentity | undefined {
  return identities.find((i) => i.config.agentId === agentId);
}

/**
 * Get all identities belonging to a specific team.
 */
export function getTeamIdentities(
  identities: SwarmAgentIdentity[],
  team: SwarmTeamName,
): SwarmAgentIdentity[] {
  return identities.filter((i) => i.config.team === team);
}
