import { describe, it, expect } from "vitest";
import { buildReport, formatReportText, parseAuditFile } from "../src/report.js";
import type { AuditEntry } from "../src/audit.js";

function entry(ts: string, byType: Record<string, number>, direction?: "request" | "response"): AuditEntry {
  return {
    ts,
    route: "/v1/messages",
    format: "anthropic",
    mode: "redact",
    action: "redacted",
    direction,
    summary: { total: 0, byCategory: {}, byType, bySeverity: {}, highestSeverity: null, categoriesPresent: [] },
  };
}

describe("compliance report", () => {
  const entries = [
    entry("2026-06-01T10:00:00Z", { CREDIT_CARD: 2, EMAIL: 1, AWS_ACCESS_KEY: 1 }),
    entry("2026-06-02T10:00:00Z", { SSN: 1, PERSON_NAME: 1 }),
    entry("2026-06-03T10:00:00Z", { OPENAI_KEY: 1 }, "response"),
    entry("2026-05-01T10:00:00Z", { CREDIT_CARD: 5 }), // older — excluded by --since
  ];

  it("maps data types to the right frameworks", () => {
    const r = buildReport(entries, { generatedAt: "now" });
    expect(r.frameworks.PCI_DSS!.byType.CREDIT_CARD).toBe(7);
    expect(r.frameworks.GDPR!.byType.EMAIL).toBe(1);
    expect(r.frameworks.GDPR!.byType.SSN).toBe(1);
    expect(r.frameworks.SECRETS_SOC2!.byType.AWS_ACCESS_KEY).toBe(1);
    expect(r.frameworks.SECRETS_SOC2!.byType.OPENAI_KEY).toBe(1);
    expect(r.frameworks.HIPAA!.byType.PERSON_NAME).toBe(1);
  });

  it("counts request vs response direction", () => {
    const r = buildReport(entries, { generatedAt: "now" });
    expect(r.responseEvents).toBe(1);
    expect(r.requestEvents).toBe(3);
  });

  it("honours the --since window", () => {
    const r = buildReport(entries, { generatedAt: "now", since: "2026-06-01T00:00:00Z" });
    expect(r.frameworks.PCI_DSS!.byType.CREDIT_CARD).toBe(2); // the May entry of 5 is excluded
    expect(r.events).toBe(3);
  });

  it("renders a text report", () => {
    const text = formatReportText(buildReport(entries, { generatedAt: "now" }));
    expect(text).toContain("PCI DSS");
    expect(text).toContain("CREDIT_CARD");
  });

  it("parses JSONL audit files and skips junk", () => {
    const parsed = parseAuditFile('{"ts":"t","route":"/x","format":"a","mode":"redact","action":"clean","summary":{"byType":{}}}\nnot-json\n');
    expect(parsed).toHaveLength(1);
  });
});
