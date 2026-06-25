import { spawnSync } from "node:child_process";
import type { Detector, RawMatch, Severity } from "../../types.js";

/**
 * Optional bridge to a LOCAL named-entity-recognition model (e.g. a GLiNER or
 * Microsoft Presidio script running on this machine). This gives context-aware
 * detection of unstructured PII without sending anything to a cloud service.
 *
 * The configured command receives the text on stdin and must print a JSON array
 * of entities. Both shapes are accepted:
 *   [{ "start": 10, "end": 18, "type": "PERSON" }]
 *   [{ "start": 10, "end": 18, "entity_type": "PERSON", "score": 0.9 }]
 *
 * It fails open: if the command errors or returns junk, no NER matches are added
 * (the regex/dictionary detectors still run).
 */
interface NerEntity {
  start: number;
  end: number;
  type?: string;
  entity_type?: string;
  label?: string;
}

const SEVERITY: Severity = "medium";

export function makeNerDetector(command: string): Detector {
  let warned = false;
  return {
    name: "ner",
    category: "pii",
    run(text: string): RawMatch[] {
      if (!text.trim()) return [];
      try {
        const res = spawnSync(command, {
          input: text,
          shell: true,
          encoding: "utf8",
          timeout: 5000,
          maxBuffer: 16 * 1024 * 1024,
        });
        if (res.status !== 0 || !res.stdout) return [];
        const entities = JSON.parse(res.stdout) as NerEntity[];
        if (!Array.isArray(entities)) return [];
        const out: RawMatch[] = [];
        for (const e of entities) {
          if (typeof e.start !== "number" || typeof e.end !== "number" || e.end <= e.start) continue;
          const label = (e.type ?? e.entity_type ?? e.label ?? "ENTITY").toUpperCase();
          out.push({
            start: e.start,
            end: e.end,
            value: text.slice(e.start, e.end),
            type: `NER_${label}`,
            category: "pii",
            severity: SEVERITY,
          });
        }
        return out;
      } catch (err) {
        if (!warned) {
          warned = true;
          console.error(`[aegis] NER command failed (continuing without it): ${(err as Error).message}`);
        }
        return [];
      }
    },
  };
}
