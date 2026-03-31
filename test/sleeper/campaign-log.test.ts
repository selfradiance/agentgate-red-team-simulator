import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  CampaignRunSchema,
  CampaignLogSchema,
  InvalidCampaignLogError,
  appendRun,
  readCampaignLog,
  type CampaignRun,
} from "../../src/sleeper/campaign-log.js";

function makeRun(overrides: Partial<CampaignRun> = {}): CampaignRun {
  return {
    run_id: "run-001",
    mode: "strike",
    identity_mode: "same",
    recon_mode: "recon",
    timestamp: "2026-03-31T12:00:00.000Z",
    metrics: {
      success_rate: 0.5,
      cost_effective_exposure: 1200,
      probe_count: 30,
      precision: 0.6,
      recon_dependent_count: 4,
      time_to_first_boundary: 12.5,
    },
    attack_log: [
      {
        objective_id: "T1",
        params: { burst_count: 11 },
        reasoning: "Rate limit boundary at 10/60s",
        recon_dependency: true,
        success: true,
      },
    ],
    ...overrides,
  };
}

let tmpDir: string;
let logPath: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "campaign-log-test-"));
  logPath = join(tmpDir, "test-campaign-log.json");
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("CampaignRunSchema", () => {
  it("accepts a valid run", () => {
    const result = CampaignRunSchema.safeParse(makeRun());
    expect(result.success).toBe(true);
  });

  it("rejects invalid mode", () => {
    const result = CampaignRunSchema.safeParse(
      makeRun({ mode: "recon" as "scout" })
    );
    expect(result.success).toBe(false);
  });

  it("rejects invalid identity_mode", () => {
    const result = CampaignRunSchema.safeParse(
      makeRun({ identity_mode: "unknown" as "same" })
    );
    expect(result.success).toBe(false);
  });

  it("rejects invalid recon_mode", () => {
    const result = CampaignRunSchema.safeParse(
      makeRun({ recon_mode: "partial" as "recon" })
    );
    expect(result.success).toBe(false);
  });
});

describe("CampaignLogSchema", () => {
  it("accepts an array of valid runs", () => {
    const result = CampaignLogSchema.safeParse([
      makeRun({ run_id: "run-001" }),
      makeRun({ run_id: "run-002", mode: "scout", recon_mode: "blind" }),
    ]);
    expect(result.success).toBe(true);
  });

  it("accepts an empty array", () => {
    const result = CampaignLogSchema.safeParse([]);
    expect(result.success).toBe(true);
  });
});

describe("readCampaignLog", () => {
  it("returns empty array when file does not exist", async () => {
    const log = await readCampaignLog(logPath);
    expect(log).toEqual([]);
  });

  it("throws InvalidCampaignLogError for malformed JSON", async () => {
    await writeFile(logPath, "{broken", "utf-8");
    await expect(readCampaignLog(logPath)).rejects.toBeInstanceOf(InvalidCampaignLogError);
  });
});

describe("appendRun", () => {
  it("creates file and writes first run", async () => {
    const run = makeRun();
    await appendRun(logPath, run);
    const log = await readCampaignLog(logPath);
    expect(log).toHaveLength(1);
    expect(log[0].run_id).toBe("run-001");
  });

  it("appends to existing log", async () => {
    await appendRun(logPath, makeRun({ run_id: "run-001" }));
    await appendRun(logPath, makeRun({ run_id: "run-002" }));
    const log = await readCampaignLog(logPath);
    expect(log).toHaveLength(2);
    expect(log[0].run_id).toBe("run-001");
    expect(log[1].run_id).toBe("run-002");
  });

  it("validates the run before appending", async () => {
    const badRun = { ...makeRun(), mode: "invalid" } as unknown as CampaignRun;
    await expect(appendRun(logPath, badRun)).rejects.toThrow();
  });

  it("preserves existing data when appending", async () => {
    const run1 = makeRun({ run_id: "run-001", recon_mode: "recon" });
    const run2 = makeRun({ run_id: "run-002", recon_mode: "blind" });
    await appendRun(logPath, run1);
    await appendRun(logPath, run2);
    const log = await readCampaignLog(logPath);
    expect(log[0].recon_mode).toBe("recon");
    expect(log[1].recon_mode).toBe("blind");
  });

  it("keeps both runs when appending concurrently", async () => {
    await Promise.all([
      appendRun(logPath, makeRun({ run_id: "run-001" })),
      appendRun(logPath, makeRun({ run_id: "run-002" })),
    ]);

    const log = await readCampaignLog(logPath);
    expect(log).toHaveLength(2);
    expect(log.map((run) => run.run_id).sort()).toEqual(["run-001", "run-002"]);
  });
});
