/**
 * Compliance reporting over the audit log. Maps detected data types to the
 * regulatory frameworks they touch (PCI DSS, HIPAA, GDPR, plus a secrets/SOC2
 * bucket) and aggregates counts over a time window — the kind of report
 * Strac/Cyberhaven produce, generated locally from your own audit trail.
 */
import type { AuditEntry } from "./audit.js";

export const FRAMEWORK_MAP: Record<string, string[]> = {
  PCI_DSS: ["CREDIT_CARD", "IBAN", "STRIPE_KEY", "DB_URI_PASSWORD"],
  HIPAA: ["PERSON_NAME", "EMAIL", "PHONE", "SSN", "DATE_OF_BIRTH", "STREET_ADDRESS", "PASSPORT", "MRN"],
  GDPR: [
    "PERSON_NAME", "EMAIL", "PHONE", "SSN", "IPV4", "STREET_ADDRESS", "DATE_OF_BIRTH",
    "PASSPORT", "IBAN", "CREDIT_CARD", "NER_PERSON", "NER_LOCATION",
  ],
  SECRETS_SOC2: [
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GCP_API_KEY", "GCP_SERVICE_ACCT", "ANTHROPIC_KEY",
    "OPENAI_KEY", "GITHUB_TOKEN", "GITHUB_PAT_FINE", "SLACK_TOKEN", "STRIPE_KEY", "SENDGRID_KEY",
    "TWILIO_KEY", "NPM_TOKEN", "JWT", "BEARER_TOKEN", "PRIVATE_KEY", "GENERIC_SECRET", "DB_URI_PASSWORD",
  ],
};

export interface FrameworkReport {
  total: number;
  byType: Record<string, number>;
}

export interface ComplianceReport {
  generatedAt: string;
  since?: string;
  events: number;
  requestEvents: number;
  responseEvents: number;
  totalFindings: number;
  byType: Record<string, number>;
  frameworks: Record<string, FrameworkReport>;
}

function frameworksForType(type: string): string[] {
  return Object.keys(FRAMEWORK_MAP).filter((fw) => FRAMEWORK_MAP[fw]!.includes(type));
}

export function buildReport(entries: AuditEntry[], opts: { since?: string; generatedAt: string }): ComplianceReport {
  const frameworks: Record<string, FrameworkReport> = {};
  for (const fw of Object.keys(FRAMEWORK_MAP)) frameworks[fw] = { total: 0, byType: {} };
  const byType: Record<string, number> = {};

  let events = 0;
  let requestEvents = 0;
  let responseEvents = 0;
  let totalFindings = 0;

  for (const e of entries) {
    if (opts.since && e.ts < opts.since) continue;
    events++;
    if (e.direction === "response") responseEvents++;
    else requestEvents++;

    for (const [type, count] of Object.entries(e.summary?.byType ?? {})) {
      byType[type] = (byType[type] ?? 0) + count;
      totalFindings += count;
      for (const fw of frameworksForType(type)) {
        const f = frameworks[fw]!;
        f.total += count;
        f.byType[type] = (f.byType[type] ?? 0) + count;
      }
    }
  }

  return { generatedAt: opts.generatedAt, since: opts.since, events, requestEvents, responseEvents, totalFindings, byType, frameworks };
}

export function formatReportText(r: ComplianceReport): string {
  const lines: string[] = [];
  lines.push("Aegis compliance report");
  lines.push(`generated: ${r.generatedAt}${r.since ? `   since: ${r.since}` : ""}`);
  lines.push("");
  lines.push(`events: ${r.events}  (request: ${r.requestEvents}, response: ${r.responseEvents})`);
  lines.push(`total findings: ${r.totalFindings}`);
  lines.push("");
  for (const [fw, f] of Object.entries(r.frameworks)) {
    const status = f.total > 0 ? `${f.total} finding(s)` : "no exposure detected";
    lines.push(`${fw.replace(/_/g, " ")}: ${status}`);
    for (const [type, n] of Object.entries(f.byType).sort((a, b) => b[1] - a[1])) {
      lines.push(`    ${type.padEnd(20)} ${n}`);
    }
  }
  return lines.join("\n");
}

/** Parse a JSONL audit file into entries (skips malformed lines). */
export function parseAuditFile(text: string): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as AuditEntry);
    } catch {
      /* skip */
    }
  }
  return out;
}
