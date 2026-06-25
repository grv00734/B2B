import { describe, it, expect } from "vitest";
import { SseRestorer, carryIndex } from "../src/stream.js";
import { Vault } from "../src/scrub/placeholders.js";

function anthropicDelta(text: string, index = 0): string {
  return `event: content_block_delta\ndata: ${JSON.stringify({
    type: "content_block_delta",
    index,
    delta: { type: "text_delta", text },
  })}\n\n`;
}

/** Extract the concatenated restored text from an Anthropic SSE output. */
function collectText(sse: string): string {
  let out = "";
  for (const block of sse.split("\n\n")) {
    const line = block.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    try {
      const obj = JSON.parse(line.slice(5).trim());
      if (obj?.delta?.type === "text_delta") out += obj.delta.text;
    } catch {
      /* ignore */
    }
  }
  return out;
}

describe("carryIndex", () => {
  it("holds an incomplete placeholder", () => {
    const s = "hello [[REDACTED:EMAIL:1";
    expect(s.slice(carryIndex(s))).toBe("[[REDACTED:EMAIL:1");
  });
  it("holds a trailing prefix of the marker", () => {
    const s = "done [[RED";
    expect(s.slice(carryIndex(s))).toBe("[[RED");
  });
  it("holds nothing for a complete placeholder", () => {
    const s = "x [[REDACTED:EMAIL:1]] y";
    expect(carryIndex(s)).toBe(s.length);
  });
});

describe("SseRestorer", () => {
  it("restores a placeholder split across multiple deltas", () => {
    const vault = new Vault();
    const ph = vault.placeholderFor("dev@acme.com", "EMAIL"); // [[REDACTED:EMAIL:1]]
    const r = new SseRestorer(vault);

    // Feed the placeholder broken into awkward fragments.
    const chunks = ["Your email ", "[[REDA", "CTED:EM", "AIL:1]]", " is set."];
    let out = "";
    for (const c of chunks) out += r.feed(anthropicDelta(c));
    out += r.end();

    expect(collectText(out)).toBe("Your email dev@acme.com is set.");
    expect(out).not.toContain("[[REDACTED");
  });

  it("passes through untouched when nothing was redacted", () => {
    const vault = new Vault(); // empty
    const r = new SseRestorer(vault);
    const input = anthropicDelta("plain text");
    expect(r.feed(input)).toBe(input);
  });

  it("restores within an OpenAI-style stream", () => {
    const vault = new Vault();
    vault.placeholderFor("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"); // :1
    const r = new SseRestorer(vault);
    const mk = (content: string) =>
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content } }] })}\n\n`;

    let out = "";
    out += r.feed(mk("key is [[REDACTED:AWS_ACCESS_KEY:"));
    out += r.feed(mk("1]] ok"));
    out += r.feed("data: [DONE]\n\n");
    out += r.end();

    expect(out).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("[[REDACTED");
    expect(out).toContain("[DONE]");
  });
});
