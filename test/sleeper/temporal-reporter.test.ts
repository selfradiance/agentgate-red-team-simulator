// Unit tests for temporal reporter — tests matrix generation and delta computation.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { generateTemporalReport } from "../../src/sleeper/temporal-reporter.js";
import type { CampaignRun } from "../../src/sleeper/campaign-log.js";

function makeRun(overrides: Partial<CampaignRun> = {}): CampaignRun {
  return {
    run_id: "test-run",
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
    attack_log: [],
    ...overrides,
  };
}

let tmpDir: string;
let logPath: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "reporter-test-"));
  logPath = join(tmpDir, "test-campaign-log.json");
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("Temporal Reporter", () => {
  it("returns message when no data exists", async () => {
    const report = await generateTemporalReport({ campaignLogPath: logPath });
    expect(report).toContain("No campaign data");
  });

  it("generates report with partial data (fallback mode)", async () => {
    const log = [
      makeRun({ run_id: "same-recon", identity_mode: "same", recon_mode: "recon", metrics: { ...makeRun().metrics, success_rate: 0.7 } }),
      makeRun({ run_id: "same-blind", identity_mode: "same", recon_mode: "blind", metrics: { ...makeRun().metrics, success_rate: 0.3 } }),
    ];
    await writeFile(logPath, JSON.stringify(log), "utf-8");

    // This will fail Claude API call and fall back to raw report
    const report = await generateTemporalReport({ campaignLogPath: logPath });
    expect(report).toBeTruthy();
    expect(report.length).toBeGreaterThan(50);
  });

  it("generates report with all four strike variants", async () => {
    const log = [
      makeRun({ run_id: "scout", mode: "scout", metrics: { ...makeRun().metrics, probe_count: 56 } }),
      makeRun({ run_id: "same-recon", identity_mode: "same", recon_mode: "recon" }),
      makeRun({ run_id: "same-blind", identity_mode: "same", recon_mode: "blind" }),
      makeRun({ run_id: "fresh-recon", identity_mode: "fresh", recon_mode: "recon" }),
      makeRun({ run_id: "fresh-blind", identity_mode: "fresh", recon_mode: "blind" }),
    ];
    await writeFile(logPath, JSON.stringify(log), "utf-8");

    const report = await generateTemporalReport({ campaignLogPath: logPath });
    expect(report).toBeTruthy();
    expect(report.length).toBeGreaterThan(50);
  });
});
