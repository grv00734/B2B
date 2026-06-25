/**
 * Format-aware request scrubbing. We only rewrite the fields that carry
 * user/assistant content (prompts, messages, system text) so that structural
 * fields like `model` or `max_tokens` are left untouched.
 *
 * For unknown shapes we fall back to scrubbing every string in the body, which
 * is safe but coarser.
 */
import type { RouteFormat, RawMatch } from "./types.js";
import type { Scrubber } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";

export interface RequestScrubResult {
  body: unknown;
  matches: RawMatch[];
}

type Json = unknown;

function scrubString(s: unknown, scrubber: Scrubber, vault: Vault, sink: RawMatch[]): unknown {
  if (typeof s !== "string") return s;
  const { text, matches } = scrubber.scrub(s, vault);
  sink.push(...matches);
  return text;
}

/** Scrub a content value that may be a plain string or an array of typed blocks. */
function scrubContent(content: Json, scrubber: Scrubber, vault: Vault, sink: RawMatch[]): Json {
  if (typeof content === "string") return scrubString(content, scrubber, vault, sink);
  if (Array.isArray(content)) {
    return content.map((block) => {
      if (block && typeof block === "object" && "text" in block) {
        const b = block as Record<string, unknown>;
        return { ...b, text: scrubString(b.text, scrubber, vault, sink) };
      }
      return block;
    });
  }
  return content;
}

function scrubDeep(value: Json, scrubber: Scrubber, vault: Vault, sink: RawMatch[]): Json {
  if (typeof value === "string") return scrubString(value, scrubber, vault, sink);
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, scrubber, vault, sink));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubDeep(v, scrubber, vault, sink);
    }
    return out;
  }
  return value;
}

export function scrubRequestBody(
  body: Json,
  format: RouteFormat,
  scrubber: Scrubber,
  vault: Vault,
): RequestScrubResult {
  const sink: RawMatch[] = [];

  if (!body || typeof body !== "object") {
    return { body, matches: sink };
  }

  if (format === "anthropic" || format === "openai") {
    const b = { ...(body as Record<string, unknown>) };

    // System prompt (Anthropic supports string or block array).
    if ("system" in b) b.system = scrubContent(b.system, scrubber, vault, sink);

    // Messages array shared by both formats.
    if (Array.isArray(b.messages)) {
      b.messages = (b.messages as Json[]).map((msg) => {
        if (msg && typeof msg === "object" && "content" in msg) {
          const m = msg as Record<string, unknown>;
          return { ...m, content: scrubContent(m.content, scrubber, vault, sink) };
        }
        return msg;
      });
    }

    // OpenAI "responses" API uses `input` instead of `messages`.
    if ("input" in b) b.input = scrubContent(b.input, scrubber, vault, sink);

    return { body: b, matches: sink };
  }

  // Unknown shape: scrub every string we can find.
  return { body: scrubDeep(body, scrubber, vault, sink), matches: sink };
}
