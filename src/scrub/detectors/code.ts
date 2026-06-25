import type { Detector, RawMatch } from "../../types.js";
import { escapeRegExp } from "./util.js";

/**
 * Source-code / IP heuristics. Two signals:
 *  - confidentiality markers in headers/comments (CONFIDENTIAL, PROPRIETARY, ...)
 *  - references to internal-only package namespaces
 *
 * Markers are high-signal that the surrounding content should not leave the org;
 * pair this detector with `blockOn: ["code"]` for a hard stop on flagged files.
 */
export function makeCodeDetector(markers: string[], internalNamespaces: string[]): Detector {
  const cleanMarkers = markers.map((m) => m.trim()).filter(Boolean);
  const cleanNs = internalNamespaces.map((n) => n.trim()).filter(Boolean);

  const markerRe =
    cleanMarkers.length > 0
      ? new RegExp(cleanMarkers.map(escapeRegExp).join("|"), "gid")
      : null;
  const nsRe =
    cleanNs.length > 0 ? new RegExp(cleanNs.map(escapeRegExp).join("|"), "gd") : null;

  return {
    name: "code",
    category: "code",
    run(text: string): RawMatch[] {
      const out: RawMatch[] = [];

      if (markerRe) {
        for (const m of text.matchAll(markerRe)) {
          const start = m.index ?? 0;
          out.push({
            start,
            end: start + m[0].length,
            value: m[0],
            type: "CONFIDENTIAL_MARKER",
            category: "code",
            severity: "critical",
          });
        }
      }

      if (nsRe) {
        for (const m of text.matchAll(nsRe)) {
          const start = m.index ?? 0;
          out.push({
            start,
            end: start + m[0].length,
            value: m[0],
            type: "INTERNAL_NAMESPACE",
            category: "code",
            severity: "high",
          });
        }
      }

      return out;
    },
  };
}
