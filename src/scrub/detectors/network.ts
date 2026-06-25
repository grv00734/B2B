import type { Detector, RawMatch } from "../../types.js";
import { runPattern, type PatternSpec } from "./util.js";

/** IPv4 with octet validation to avoid matching version strings like 1.2.3.4.5. */
const IPV4: PatternSpec = {
  type: "IPV4",
  severity: "low",
  source: "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b",
};

/** Internal-looking hostnames are often more sensitive than the IPs themselves. */
const INTERNAL_HOST: PatternSpec = {
  type: "INTERNAL_HOST",
  severity: "medium",
  source: "\\b[a-z0-9\\-]+\\.(?:internal|intranet|corp|local|lan|svc\\.cluster\\.local)\\b",
  flags: "i",
};

export const networkDetector: Detector = {
  name: "network",
  category: "network",
  run(text: string): RawMatch[] {
    return [
      ...runPattern(text, IPV4, "network"),
      ...runPattern(text, INTERNAL_HOST, "network"),
    ];
  },
};
