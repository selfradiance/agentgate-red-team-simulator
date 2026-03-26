// Shared intelligence log for Stage 5 — enables indirect coordination
// between swarm teams. Teams write observations and questions; the campaign
// coordinator synthesizes cross-team patterns between rounds.
// In-memory only — resets each run.

import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IntelTeam = "alpha" | "beta" | "gamma" | "coordinator";
export type IntelType = "observation" | "question" | "synthesis";

export interface IntelEntry {
  id: string;
  round: number;
  team: IntelTeam;
  type: IntelType;
  subject: string;
  content: string;
  targetHint: string | null;
}

// ---------------------------------------------------------------------------
// IntelLog
// ---------------------------------------------------------------------------

export class IntelLog {
  private entries: IntelEntry[] = [];

  /**
   * Add an entry to the log. Auto-generates a unique ID.
   */
  addEntry(entry: Omit<IntelEntry, "id">): IntelEntry {
    const full: IntelEntry = { id: randomUUID(), ...entry };
    this.entries.push(full);
    return full;
  }

  /**
   * All entries from a specific round, in chronological order.
   */
  getEntriesByRound(round: number): IntelEntry[] {
    return this.entries.filter((e) => e.round === round);
  }

  /**
   * All entries from a specific team, in chronological order.
   */
  getEntriesByTeam(team: string): IntelEntry[] {
    return this.entries.filter((e) => e.team === team);
  }

  /**
   * All entries of a specific type, in chronological order.
   */
  getEntriesByType(type: string): IntelEntry[] {
    return this.entries.filter((e) => e.type === type);
  }

  /**
   * All questions submitted by OTHER teams — i.e., questions this team
   * might want to act on. Excludes questions from the requesting team.
   */
  getQuestionsForTeam(team: string): IntelEntry[] {
    return this.entries.filter((e) => e.type === "question" && e.team !== team);
  }

  /**
   * Full chronological log.
   */
  getAllEntries(): IntelEntry[] {
    return [...this.entries];
  }

  /**
   * All coordinator synthesis entries.
   */
  getSyntheses(): IntelEntry[] {
    return this.entries.filter((e) => e.type === "synthesis");
  }

  /**
   * Format all entries from prior rounds (not current round) into a plain
   * text summary suitable for including in a strategist prompt.
   *
   * Includes: observations from all teams, coordinator syntheses.
   * Excludes: entries from the current round (strategist should not see
   * other teams' activity in the same round before acting).
   */
  getSharedIntelForStrategist(team: string, currentRound: number): string {
    const priorEntries = this.entries.filter((e) => e.round < currentRound);

    if (priorEntries.length === 0) {
      return "No prior intelligence available.";
    }

    const lines: string[] = [];
    lines.push("=== SHARED INTELLIGENCE LOG ===");
    lines.push("");

    // Group by round
    const rounds = [...new Set(priorEntries.map((e) => e.round))].sort((a, b) => a - b);

    for (const round of rounds) {
      lines.push(`--- Round ${round} ---`);
      const roundEntries = priorEntries.filter((e) => e.round === round);

      for (const entry of roundEntries) {
        const hint = entry.targetHint ? ` [target: ${entry.targetHint}]` : "";
        lines.push(`[${entry.team}] (${entry.type}) ${entry.subject}${hint}: ${entry.content}`);
      }

      lines.push("");
    }

    return lines.join("\n").trimEnd();
  }
}
