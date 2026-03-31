import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { ScoutKeys } from "./scout/scout-client.js";

export const SLEEPER_IDENTITY_VERSION = "1.0" as const;

const SleeperIdentitySchema = z.object({
  version: z.literal(SLEEPER_IDENTITY_VERSION),
  identity_id: z.string(),
  target_url: z.string(),
  created_at: z.string().datetime(),
  keys: z.object({
    publicKey: z.string(),
    privateKey: z.string(),
  }),
});

export type SleeperIdentityRecord = z.infer<typeof SleeperIdentitySchema>;

export const DEFAULT_SLEEPER_IDENTITY_PATH = join(
  process.cwd(),
  "sleeper-identity.json",
);

export async function saveSleeperIdentity(
  identityId: string,
  targetUrl: string,
  keys: ScoutKeys,
  identityPath: string = DEFAULT_SLEEPER_IDENTITY_PATH,
): Promise<SleeperIdentityRecord> {
  const record = SleeperIdentitySchema.parse({
    version: SLEEPER_IDENTITY_VERSION,
    identity_id: identityId,
    target_url: targetUrl,
    created_at: new Date().toISOString(),
    keys,
  });

  await writeFile(identityPath, JSON.stringify(record, null, 2), "utf-8");
  return record;
}

export async function loadSleeperIdentity(
  identityPath: string = DEFAULT_SLEEPER_IDENTITY_PATH,
): Promise<SleeperIdentityRecord> {
  const raw = await readFile(identityPath, "utf-8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse sleeper identity file ${identityPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return SleeperIdentitySchema.parse(parsed);
}

export function sleeperIdentityExists(
  identityPath: string = DEFAULT_SLEEPER_IDENTITY_PATH,
): boolean {
  return existsSync(identityPath);
}
