// Persona definitions for Stage 4 — three specialist identities with
// mechanically distinct bond budgets and attack-family affinities.
// Each persona gets its own AgentGate identity and Ed25519 keypair.

import { generateKeyPairSync, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { signRequest, type AgentKeys } from "./agentgate-client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PersonaConfig {
  name: string;
  displayName: string;
  specialty: string;
  role: string;
  bondBudgetCents: number;
  attackFamilies: number[];   // category numbers this persona prioritizes
  identityFile: string;       // e.g., "agent-identity-shadow.json"
}

export interface PersonaIdentity {
  config: PersonaConfig;
  keys: AgentKeys;
  identityId: string;
}

// ---------------------------------------------------------------------------
// Persona configurations
// ---------------------------------------------------------------------------

export const SHADOW: PersonaConfig = {
  name: "shadow",
  displayName: "Shadow",
  specialty: "Recon & Timing",
  role: "Intel gatherer. Runs first in handoff operations. Probes boundaries that Whale and Chaos exploit later.",
  bondBudgetCents: 50,
  attackFamilies: [1, 3, 7, 12],
  identityFile: "agent-identity-shadow.json",
};

export const WHALE: PersonaConfig = {
  name: "whale",
  displayName: "Whale",
  specialty: "Economic & Bond",
  role: "Economic pressure. Exploits intel from Shadow. Tests bond math, capacity rules, and reputation manipulation.",
  bondBudgetCents: 200,
  attackFamilies: [2, 6, 10, 11],
  identityFile: "agent-identity-whale.json",
};

export const CHAOS: PersonaConfig = {
  name: "chaos",
  displayName: "Chaos",
  specialty: "Input Fuzzing & Protocol",
  role: "Surface-area disruption. Malformed inputs, boundary violations, protocol abuse. Second identity for cross-identity pressure testing.",
  bondBudgetCents: 100,
  attackFamilies: [4, 5, 8, 9],
  identityFile: "agent-identity-chaos.json",
};

export const ALL_PERSONAS: PersonaConfig[] = [SHADOW, WHALE, CHAOS];

// ---------------------------------------------------------------------------
// Identity file helpers
// ---------------------------------------------------------------------------

interface SavedPersonaIdentity {
  publicKey: string;
  privateKey: string;
  identityId?: string;
}

function identityFilePath(config: PersonaConfig): string {
  return path.resolve(config.identityFile);
}

function base64UrlToBase64(value: string): string {
  return Buffer.from(value, "base64url").toString("base64");
}

function loadKeypairFromFile(filePath: string): AgentKeys | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    const data: SavedPersonaIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
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
    const data: SavedPersonaIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return data.identityId;
  } catch {
    return undefined;
  }
}

function saveKeypairToFile(filePath: string, keys: AgentKeys): void {
  fs.writeFileSync(filePath, JSON.stringify(keys, null, 2), "utf8");
}

function saveIdentityIdToFile(filePath: string, identityId: string): void {
  const data: SavedPersonaIdentity = JSON.parse(fs.readFileSync(filePath, "utf8"));
  data.identityId = identityId;
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

// ---------------------------------------------------------------------------
// Generate a new Ed25519 keypair
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Register identity on AgentGate (signed request)
// ---------------------------------------------------------------------------

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
    // 409 means keypair already registered but we lost the identity ID
    if (response.status === 409) {
      throw new Error(
        `Identity already registered but ID not saved locally. Delete ${apiPath} identity file and try again, or use --fresh-team.`,
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
 * Load or create a persona's identity. If the identity file exists with a
 * saved identityId, reuse it. Otherwise generate a new keypair and register
 * it on AgentGate.
 */
export async function loadOrCreatePersonaIdentity(
  config: PersonaConfig,
  agentGateUrl: string,
  restKey: string,
): Promise<PersonaIdentity> {
  const filePath = identityFilePath(config);

  // Try to load existing keypair
  let keys = loadKeypairFromFile(filePath);
  if (!keys) {
    keys = generateKeypair();
    saveKeypairToFile(filePath, keys);
  }

  // Try to load existing identity ID
  let identityId = loadIdentityIdFromFile(filePath);
  if (!identityId) {
    identityId = await registerIdentityOnAgentGate(keys, agentGateUrl, restKey);
    saveIdentityIdToFile(filePath, identityId);
  }

  return { config, keys, identityId };
}

/**
 * Delete all persona identity files (for --fresh-team).
 */
export function deleteAllPersonaIdentityFiles(): void {
  for (const config of ALL_PERSONAS) {
    const filePath = identityFilePath(config);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}

/**
 * Load or create all three persona identities.
 */
export async function initializeTeam(
  agentGateUrl: string,
  restKey: string,
  freshTeam: boolean = false,
): Promise<PersonaIdentity[]> {
  if (freshTeam) {
    deleteAllPersonaIdentityFiles();
  }

  const team: PersonaIdentity[] = [];
  for (const config of ALL_PERSONAS) {
    const identity = await loadOrCreatePersonaIdentity(config, agentGateUrl, restKey);
    team.push(identity);
  }

  return team;
}

/**
 * Find a persona identity by name.
 */
export function getPersona(team: PersonaIdentity[], name: string): PersonaIdentity | undefined {
  return team.find((p) => p.config.name === name);
}
