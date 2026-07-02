import { describe, it, expect, beforeAll } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { makeKeyring } from "../src/keys.js";
import { SurrogateTokenizer } from "../src/scrub/surrogate.js";
import { SseRestorer } from "../src/stream.js";

// Use an in-memory master key so tests never touch ~/.aegis.
beforeAll(() => {
  process.env.AEGIS_TEAM_KEY = Buffer.alloc(32, 7).toString("base64");
});

function ring() {
  return makeKeyring("/nonexistent-aegis-test-dir", "k1");
}

function anthropicDelta(text: string): string {
  return `event: content_block_delta\ndata: ${JSON.stringify({
    type: "content_block_delta",
    index: 0,
    delta: { type: "text_delta", text },
  })}\n\n`;
}

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

const AWS = "AKIAIOSFODNN7EXAMPLE"; // canonical example key: AKIA + 16 base36 chars
const IP = "10.2.14.7";
const HEX = "deadbeefcafebabe0123456789abcdef";

describe("surrogate formatters — format preservation", () => {
  it("AWS key surrogate keeps the AKIA prefix, length, and alphabet", () => {
    const tok = new SurrogateTokenizer(ring());
    const s = tok.encode(AWS, "AWS_ACCESS_KEY")!;
    expect(s).toMatch(/^AKIA[0-9A-Z]{16}$/);
    expect(s).not.toBe(AWS);
  });

  it("IPv4 surrogate is a valid dotted-quad and differs from the original", () => {
    const tok = new SurrogateTokenizer(ring());
    const s = tok.encode(IP, "IPV4")!;
    const octets = s.split(".").map(Number);
    expect(octets).toHaveLength(4);
    expect(octets.every((o) => o >= 0 && o <= 255)).toBe(true);
    expect(s).not.toBe(IP);
  });

  it("hex token surrogate preserves length and case", () => {
    const tok = new SurrogateTokenizer(ring());
    const lower = tok.encode(HEX, "GENERIC")!;
    expect(lower).toMatch(/^[0-9a-f]{32}$/);
    const upper = tok.encode(HEX.toUpperCase(), "GENERIC")!;
    expect(upper).toMatch(/^[0-9A-F]{32}$/);
  });

  it("declines types it has no formatter for (Vault falls back to a placeholder)", () => {
    const tok = new SurrogateTokenizer(ring());
    expect(tok.encode("alice@example.com", "EMAIL")).toBeNull();
  });
});

describe("stateless (vault-free) round-trip — Algorithm 1", () => {
  it("encode then decodeToken recovers the original for every category", () => {
    const tok = new SurrogateTokenizer(ring());
    for (const [value, type] of [
      [AWS, "AWS_ACCESS_KEY"],
      [IP, "IPV4"],
      [HEX, "GENERIC"],
      [HEX.toUpperCase(), "GENERIC"],
    ] as const) {
      const surrogate = tok.encode(value, type)!;
      // A DIFFERENT tokenizer instance (fresh process) still restores it — no shared state.
      const fresh = new SurrogateTokenizer(ring());
      expect(fresh.decodeToken(surrogate)).toBe(value);
    }
  });

  it("the same secret maps to the same surrogate across instances (referential consistency)", () => {
    const a = new SurrogateTokenizer(ring()).encode(AWS, "AWS_ACCESS_KEY");
    const b = new SurrogateTokenizer(ring()).encode(AWS, "AWS_ACCESS_KEY");
    expect(a).toBe(b);
  });
});

describe("end-to-end through the real Scrubber + SseRestorer", () => {
  it("scrubs to surrogates upstream and restores originals in the response stream", () => {
    const scrubber = new Scrubber(DEFAULT_CONFIG);
    const tokenizer = new SurrogateTokenizer(ring());
    const vault = new Vault({ mode: "fpt", tokenizer });

    const original = `deploy with ${AWS} to host ${IP}`;
    const { text: scrubbed } = scrubber.scrub(original, vault);

    // Upstream sees surrogates, never the real values.
    expect(scrubbed).not.toContain(AWS);
    expect(scrubbed).not.toContain(IP);
    expect(scrubbed).toMatch(/AKIA[0-9A-Z]{16}/);
    expect(vault.size).toBe(2);

    // The model echoes the scrubbed text back; the restorer returns real values.
    const restorer = new SseRestorer(vault);
    const out = restorer.feed(anthropicDelta(scrubbed)) + restorer.end();
    expect(collectText(out)).toBe(original);
  });
});
