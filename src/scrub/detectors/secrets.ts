import type { Detector, RawMatch } from "../../types.js";
import { runPatterns, type PatternSpec } from "./util.js";

/**
 * High-signal credential patterns. Ordered roughly from most-specific to least.
 * Overlap resolution downstream keeps the longest/earliest match, so specific
 * provider tokens win over the generic "assignment" catch-alls.
 */
const PATTERNS: PatternSpec[] = [
  // --- Private keys (capture the whole PEM block) ---
  {
    type: "PRIVATE_KEY",
    severity: "critical",
    source: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
  },

  // --- Cloud providers ---
  { type: "AWS_ACCESS_KEY", severity: "critical", source: "\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\\b" },
  {
    type: "AWS_SECRET_KEY",
    severity: "critical",
    source: "(?:aws_secret_access_key|aws_secret)\\s*[=:]\\s*[\"']?([A-Za-z0-9/+]{40})[\"']?",
    flags: "i",
    group: 1,
  },
  { type: "GCP_API_KEY", severity: "high", source: "\\bAIza[0-9A-Za-z_\\-]{35}\\b" },
  { type: "GCP_SERVICE_ACCT", severity: "high", source: "\"private_key_id\"\\s*:\\s*\"[a-f0-9]{40}\"" },

  // --- Provider API keys ---
  { type: "ANTHROPIC_KEY", severity: "critical", source: "\\bsk-ant-[A-Za-z0-9_\\-]{20,}\\b" },
  { type: "OPENAI_KEY", severity: "critical", source: "\\bsk-(?:proj-)?[A-Za-z0-9_\\-]{20,}\\b" },
  { type: "GITHUB_TOKEN", severity: "critical", source: "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b" },
  { type: "GITHUB_PAT_FINE", severity: "critical", source: "\\bgithub_pat_[A-Za-z0-9_]{22,255}\\b" },
  { type: "SLACK_TOKEN", severity: "high", source: "\\bxox[baprs]-[A-Za-z0-9\\-]{10,}\\b" },
  { type: "STRIPE_KEY", severity: "critical", source: "\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\\b" },
  { type: "SENDGRID_KEY", severity: "high", source: "\\bSG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}\\b" },
  { type: "TWILIO_KEY", severity: "high", source: "\\bSK[0-9a-fA-F]{32}\\b" },
  { type: "NPM_TOKEN", severity: "high", source: "\\bnpm_[A-Za-z0-9]{36}\\b" },

  // --- Tokens / JWT ---
  { type: "JWT", severity: "high", source: "\\beyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b" },
  {
    type: "BEARER_TOKEN",
    severity: "high",
    source: "[Bb]earer\\s+([A-Za-z0-9._\\-]{20,})",
    group: 1,
  },

  // --- Connection strings with embedded credentials (capture the password) ---
  {
    type: "DB_URI_PASSWORD",
    severity: "critical",
    // Greedy password group backtracks to the LAST '@' before the host, so
    // passwords that themselves contain '@' are captured in full.
    source: "(?:postgres|postgresql|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqp|amqps)://[^:@\\s/]+:([^\\s/]+)@",
    flags: "i",
    group: 1,
  },

  // --- Generic credential assignments (lower precedence, capture the value) ---
  {
    type: "GENERIC_SECRET",
    severity: "medium",
    source: "(?:password|passwd|pwd|secret|api[_\\-]?key|access[_\\-]?token|auth[_\\-]?token|client[_\\-]?secret)\\s*[=:]\\s*[\"']([^\"'\\n]{6,})[\"']",
    flags: "i",
    group: 1,
  },
];

export const secretsDetector: Detector = {
  name: "secrets",
  category: "secret",
  run(text: string): RawMatch[] {
    return runPatterns(text, PATTERNS, "secret");
  },
};
