// Temporal Reporter — reads campaign log and generates the comparison matrix.
// Outputs the 4-column table and Governance Interpretation section.

import Anthropic from "@anthropic-ai/sdk";
import { readCampaignLog, type CampaignLog, type CampaignRun } from "./campaign-log.js";

export interface ReportOptions {
  campaignLogPath?: string;
}

function findRun(log: CampaignLog, identityMode: string, reconMode: string): CampaignRun | undefined {
  return log.find((r) => r.mode === "strike" && r.identity_mode === identityMode && r.recon_mode === reconMode);
}

function formatMetric(value: number | undefined, type: "percent" | "cents" | "count" | "seconds"): string {
  if (value === undefined) return "N/A";
  switch (type) {
    case "percent": return `${(value * 100).toFixed(1)}%`;
    case "cents": return `${value}¢`;
    case "count": return String(value);
    case "seconds": return `${value.toFixed(1)}s`;
  }
}

function buildMatrixText(log: CampaignLog): string {
  const sameRecon = findRun(log, "same", "recon");
  const sameBlind = findRun(log, "same", "blind");
  const freshRecon = findRun(log, "fresh", "recon");
  const freshBlind = findRun(log, "fresh", "blind");

  const runs = [sameRecon, sameBlind, freshRecon, freshBlind];
  const headers = ["Same+Recon", "Same+Blind", "Fresh+Recon", "Fresh+Blind"];

  const metrics: { label: string; key: keyof CampaignRun["metrics"]; type: "percent" | "cents" | "count" | "seconds" }[] = [
    { label: "Success rate", key: "success_rate", type: "percent" },
    { label: "Cost (exposure)", key: "cost_effective_exposure", type: "cents" },
    { label: "Probe count", key: "probe_count", type: "count" },
    { label: "Precision", key: "precision", type: "percent" },
    { label: "Recon-dependent", key: "recon_dependent_count", type: "count" },
    { label: "Time to boundary", key: "time_to_first_boundary", type: "seconds" },
  ];

  // Build table
  const colWidth = 16;
  const labelWidth = 20;

  let table = "\n";
  table += "".padEnd(labelWidth) + headers.map((h) => h.padEnd(colWidth)).join("") + "\n";
  table += "─".repeat(labelWidth + colWidth * 4) + "\n";

  for (const metric of metrics) {
    let row = metric.label.padEnd(labelWidth);
    for (const run of runs) {
      const val = run ? run.metrics[metric.key] : undefined;
      row += formatMetric(val, metric.type).padEnd(colWidth);
    }
    table += row + "\n";
  }

  return table;
}

function computeDeltas(log: CampaignLog): string {
  const sameRecon = findRun(log, "same", "recon");
  const sameBlind = findRun(log, "same", "blind");
  const freshRecon = findRun(log, "fresh", "recon");
  const freshBlind = findRun(log, "fresh", "blind");

  const sections: string[] = [];

  // Finding A: Recon materially improves strike effectiveness
  if (sameRecon && sameBlind) {
    const delta = sameRecon.metrics.success_rate - sameBlind.metrics.success_rate;
    sections.push(`Finding A — Recon Advantage (same identity): ${(delta * 100).toFixed(1)}pp success rate improvement`);
  }
  if (freshRecon && freshBlind) {
    const delta = freshRecon.metrics.success_rate - freshBlind.metrics.success_rate;
    sections.push(`Finding A — Recon Advantage (fresh identity): ${(delta * 100).toFixed(1)}pp success rate improvement`);
  }

  // Finding B: Information extraction not priced/penalized
  const scoutRun = log.find((r) => r.mode === "scout");
  if (scoutRun) {
    sections.push(`Finding B — Scout completed with ${scoutRun.metrics.probe_count} probes at ${scoutRun.metrics.cost_effective_exposure}¢ exposure. Compliant information extraction was not penalized.`);
  } else {
    sections.push("Finding B — No scout run in log. Cannot assess information extraction cost.");
  }

  // Finding C: Cross-session intelligence reuse
  if (sameRecon && freshRecon) {
    const sameRD = sameRecon.metrics.recon_dependent_count;
    const freshRD = freshRecon.metrics.recon_dependent_count;
    sections.push(`Finding C — Recon-dependent attacks: ${sameRD} (same identity), ${freshRD} (fresh identity). Intelligence gathered compliantly in scout session was operationally reused with no provenance link.`);
  }

  return sections.join("\n\n");
}

export async function generateTemporalReport(options: ReportOptions = {}): Promise<string> {
  const logPath = options.campaignLogPath ?? "temporal-campaign-log.json";
  const log = await readCampaignLog(logPath);

  if (log.length === 0) {
    return "No campaign data found. Run scout and strike phases first.";
  }

  const matrix = buildMatrixText(log);
  const deltas = computeDeltas(log);

  // Try to enhance with Claude API, fall back to raw data
  try {
    const anthropic = new Anthropic();
    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514",
      max_tokens: 3000,
      messages: [{
        role: "user",
        content: `Analyze this temporal attack pattern campaign data and provide a governance interpretation.

COMPARISON MATRIX:
${matrix}

COMPUTED DELTAS:
${deltas}

CAMPAIGN LOG ENTRIES: ${log.length}
- Scout runs: ${log.filter((r) => r.mode === "scout").length}
- Strike runs: ${log.filter((r) => r.mode === "strike").length}

Provide:
1. Executive summary (2-3 sentences)
2. The comparison matrix (reproduce it cleanly)
3. Governance Interpretation mapping deltas to:
   - Finding A: Does recon materially improve strike effectiveness?
   - Finding B: Is compliant-session information extraction priced or penalized?
   - Finding C: Can intelligence gathered compliantly be reused cross-session without provenance tracking?
4. Recommended remediation signals

Format as clean text with section headers.`,
      }],
    });

    const text = response.content
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("");

    return text;
  } catch {
    // Fallback: return raw analysis
    let report = "";
    report += "════════════════════════════════════════════════════════════\n";
    report += "  TEMPORAL ATTACK PATTERN — CAMPAIGN REPORT\n";
    report += "════════════════════════════════════════════════════════════\n\n";
    report += "COMPARISON MATRIX:\n";
    report += matrix;
    report += "\n\nGOVERNANCE INTERPRETATION:\n\n";
    report += deltas;
    report += "\n\n════════════════════════════════════════════════════════════\n";
    return report;
  }
}
