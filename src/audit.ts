import { appendFile } from "node:fs/promises";
import type { DetectionSummary, Mode } from "./types.js";

export type Action = "redacted" | "blocked" | "warned" | "clean";

export interface AuditEntry {
  ts: string;
  route: string;
  format: string;
  mode: Mode;
  action: Action;
  summary: DetectionSummary;
}

/**
 * Append-only audit trail. We deliberately record only counts, types, and
 * severities — never the matched values or their placeholders. The log is safe
 * to ship to a SIEM without leaking the very data we are protecting.
 */
export class AuditLog {
  /**
   * @param path  optional JSONL file to append entries to.
   * @param sink  optional callback that receives each entry. When provided it
   *              replaces the default console output (used by the VS Code
   *              extension to route findings into an Output channel).
   */
  constructor(
    private path?: string,
    private sink?: (entry: AuditEntry) => void,
  ) {}

  async record(entry: AuditEntry): Promise<void> {
    const { summary, action, route } = entry;

    if (this.sink) {
      this.sink(entry);
    } else if (summary.total > 0) {
      // Surface a one-line summary on the console for live visibility.
      const types = Object.entries(summary.byType)
        .map(([t, n]) => `${t}:${n}`)
        .join(", ");
      const tag =
        action === "blocked" ? "BLOCK" : action === "redacted" ? "REDACT" : action === "warned" ? "WARN" : "OK";
      console.log(`[aegis] ${tag} ${route} — ${summary.total} finding(s) [${types}]`);
    }

    if (!this.path) return;
    try {
      await appendFile(this.path, JSON.stringify(entry) + "\n", "utf8");
    } catch (err) {
      console.error(`[aegis] failed to write audit log: ${(err as Error).message}`);
    }
  }
}
