import type { Detector, RawMatch } from "../../types.js";

/**
 * In-process NER for unstructured PII using Transformers.js (ONNX/WASM) — runs
 * any local Hugging Face token-classification model, fully offline once cached.
 *
 * The dependency is OPTIONAL: it is imported lazily so the package stays small
 * and builds without it. If `@huggingface/transformers` (or the model) is not
 * available, the detector fails open (returns []), and the regex/heuristic
 * detectors still run. Install with:  npm i @huggingface/transformers
 *
 * This is an async-only detector: `run()` returns [] and `runAsync()` does the
 * inference, so it only contributes through the Scrubber's async path.
 */
const DEFAULT_MODEL = "Xenova/bert-base-NER";

interface NerEntity {
  start?: number;
  end?: number;
  entity_group?: string;
  entity?: string;
}

export function makeMlNerDetector(model: string = DEFAULT_MODEL): Detector {
  let pipe: ((t: string, o?: unknown) => Promise<NerEntity[]>) | null = null;
  let loading: Promise<unknown> | null = null;
  let unavailable = false;

  async function getPipe(): Promise<typeof pipe> {
    if (pipe) return pipe;
    if (unavailable) return null;
    if (!loading) {
      loading = (async () => {
        try {
          // Variable specifier keeps TS/build from requiring the optional dep.
          const spec = "@huggingface/transformers";
          const mod = (await import(spec)) as { pipeline: (task: string, model: string) => Promise<unknown> };
          pipe = (await mod.pipeline("token-classification", model)) as typeof pipe;
        } catch (err) {
          unavailable = true;
          console.error(`[aegis] ML NER unavailable (continuing without it): ${(err as Error).message}`);
        }
      })();
    }
    await loading;
    return pipe;
  }

  return {
    name: "ml-ner",
    category: "pii",
    run(): RawMatch[] {
      return []; // async-only
    },
    async runAsync(text: string): Promise<RawMatch[]> {
      if (!text.trim()) return [];
      const p = await getPipe();
      if (!p) return [];
      try {
        const ents = await p(text, { aggregation_strategy: "simple" });
        const out: RawMatch[] = [];
        for (const e of ents) {
          if (typeof e.start !== "number" || typeof e.end !== "number" || e.end <= e.start) continue;
          const label = String(e.entity_group ?? e.entity ?? "ENTITY").toUpperCase().replace(/[^A-Z0-9]/g, "_");
          out.push({ start: e.start, end: e.end, value: text.slice(e.start, e.end), type: `NER_${label}`, category: "pii", severity: "medium" });
        }
        return out;
      } catch {
        return [];
      }
    },
  };
}
