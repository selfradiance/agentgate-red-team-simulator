// S6: Endpoint Shape Discovery
// Hits all known GET endpoints (unauthenticated).
// No bonds, no actions, nothing enters resolution.

import type { ReconFile } from "../recon-schema.js";
import { rawGet } from "./scout-client.js";

export const hypothesis = "unauthenticated_reconnaissance";

interface EndpointRecord {
  path: string;
  status_code: number;
  response_keys: string[];
  exposes_identity_data: boolean;
  exposes_bond_data: boolean;
  exposes_action_data: boolean;
}

const IDENTITY_KEYS = ["identityId", "publicKey", "reputation", "tier", "identity"];
const BOND_KEYS = ["bondId", "bond", "amountCents", "bondStatus", "bonds"];
const ACTION_KEYS = ["actionId", "action", "actions", "outcome", "exposure"];

function detectExposure(keys: string[], patterns: string[]): boolean {
  return keys.some((k) => patterns.some((p) => k.toLowerCase().includes(p.toLowerCase())));
}

export async function probe(
  targetUrl: string,
  scoutIdentityId: string,
): Promise<ReconFile["endpoint_shape"]> {
  const endpoints: EndpointRecord[] = [];

  const paths = [
    "/health",
    "/v1/stats",
    `/v1/identities/${scoutIdentityId}`,
    "/dashboard",
  ];

  for (const path of paths) {
    const result = await rawGet(targetUrl, path);
    const responseKeys = typeof result.data === "object" && result.data !== null
      ? Object.keys(result.data)
      : [];

    // For nested objects, also collect top-level keys of nested values
    const allKeys = [...responseKeys];
    for (const key of responseKeys) {
      const val = result.data[key];
      if (typeof val === "object" && val !== null && !Array.isArray(val)) {
        allKeys.push(...Object.keys(val as Record<string, unknown>).map((k) => `${key}.${k}`));
      }
    }

    endpoints.push({
      path,
      status_code: result.status,
      response_keys: responseKeys,
      exposes_identity_data: detectExposure(allKeys, IDENTITY_KEYS),
      exposes_bond_data: detectExposure(allKeys, BOND_KEYS),
      exposes_action_data: detectExposure(allKeys, ACTION_KEYS),
    });
  }

  return { endpoints };
}
