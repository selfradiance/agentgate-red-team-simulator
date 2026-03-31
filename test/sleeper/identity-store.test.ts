import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { loadSleeperIdentity, saveSleeperIdentity } from "../../src/sleeper/identity-store.js";

let tmpDir: string;
let identityPath: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "sleeper-identity-test-"));
  identityPath = join(tmpDir, "sleeper-identity.json");
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("sleeper identity store", () => {
  it("persists and reloads sleeper identity state", async () => {
    await saveSleeperIdentity(
      "identity-123",
      "http://127.0.0.1:3000",
      { publicKey: "pub", privateKey: "priv" },
      identityPath,
    );

    const loaded = await loadSleeperIdentity(identityPath);
    expect(loaded.identity_id).toBe("identity-123");
    expect(loaded.target_url).toBe("http://127.0.0.1:3000");
    expect(loaded.keys.publicKey).toBe("pub");
    expect(loaded.keys.privateKey).toBe("priv");
  });

  it("throws a clear error for invalid JSON", async () => {
    await writeFile(identityPath, "{broken", "utf-8");
    await expect(loadSleeperIdentity(identityPath)).rejects.toThrow(
      /Failed to parse sleeper identity file/,
    );
  });
});
