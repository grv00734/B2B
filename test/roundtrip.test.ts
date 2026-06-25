import { describe, it, expect } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { scrubRequestBody } from "../src/messages.js";

const scrubber = new Scrubber(DEFAULT_CONFIG);

describe("redact + restore roundtrip", () => {
  it("removes the real value from outbound text and restores it on the way back", () => {
    const vault = new Vault();
    const original = "deploy with token sk-ant-abcd1234EFGH5678ijkl and email ops@acme.com";
    const { text: scrubbed } = scrubber.scrub(original, vault);

    expect(scrubbed).not.toContain("sk-ant-abcd1234EFGH5678ijkl");
    expect(scrubbed).not.toContain("ops@acme.com");
    expect(scrubbed).toContain("[[REDACTED:ANTHROPIC_KEY:");

    // The model echoes the placeholder back; restore returns the real value.
    const modelReply = `Set the key ${scrubbed.match(/\[\[REDACTED:ANTHROPIC_KEY:\d+\]\]/)![0]} in your env.`;
    expect(vault.restore(modelReply)).toContain("sk-ant-abcd1234EFGH5678ijkl");
  });

  it("reuses the same placeholder for a repeated value", () => {
    const vault = new Vault();
    const { text } = scrubber.scrub("a@b.com then again a@b.com", vault);
    const tokens = text.match(/\[\[REDACTED:EMAIL:\d+\]\]/g)!;
    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe(tokens[1]);
  });
});

describe("anthropic request body scrubbing", () => {
  it("scrubs system + message content but leaves structural fields alone", () => {
    const vault = new Vault();
    const body = {
      model: "claude-opus-4-8",
      max_tokens: 1024,
      system: "You are helpful. Internal key sk-ant-abcd1234EFGH5678ijkl.",
      messages: [
        { role: "user", content: "my email is dev@acme.com" },
        {
          role: "user",
          content: [{ type: "text", text: "aws AKIAIOSFODNN7EXAMPLE here" }],
        },
      ],
    };

    const { body: out, matches } = scrubRequestBody(body, "anthropic", scrubber, vault) as any;

    expect(out.model).toBe("claude-opus-4-8");
    expect(out.max_tokens).toBe(1024);
    expect(JSON.stringify(out)).not.toContain("sk-ant-abcd1234EFGH5678ijkl");
    expect(JSON.stringify(out)).not.toContain("dev@acme.com");
    expect(JSON.stringify(out)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(matches.length).toBeGreaterThanOrEqual(3);
  });
});

describe("openai request body scrubbing", () => {
  it("scrubs message content", () => {
    const vault = new Vault();
    const body = {
      model: "gpt-4o",
      messages: [{ role: "user", content: "token ghp_0123456789abcdefghijklmnopqrstuvwxyz12" }],
    };
    const { body: out } = scrubRequestBody(body, "openai", scrubber, vault) as any;
    expect(JSON.stringify(out)).not.toContain("ghp_0123456789abcdefghijklmnopqrstuvwxyz12");
  });
});
