import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { scanHistory } from "../src/history.js";

function gitInit(dir: string): void {
  const run = (args: string[]): void => {
    execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  };
  run(["init", "-q"]);
  run(["config", "user.email", "t@t.test"]);
  run(["config", "user.name", "Tester"]);
  run(["config", "commit.gpgsign", "false"]);
}

describe("git history scanning", () => {
  it("finds a secret that was committed and later removed", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-hist-"));
    try {
      gitInit(dir);
      const file = join(dir, "config.env");

      // Commit 1: introduce a secret.
      writeFileSync(file, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
      execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
      execFileSync("git", ["commit", "-qm", "add config"], { cwd: dir, stdio: "ignore" });

      // Commit 2: "remove" it — but it stays in history.
      writeFileSync(file, "AWS_ACCESS_KEY_ID=REDACTED_BY_HAND\n");
      execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
      execFileSync("git", ["commit", "-qm", "scrub config"], { cwd: dir, stdio: "ignore" });

      const res = scanHistory(new Scrubber(DEFAULT_CONFIG), dir);

      expect(res.scannedBlobs).toBeGreaterThanOrEqual(2);
      expect(res.findings.some((f) => f.type === "AWS_ACCESS_KEY")).toBe(true);
      expect(res.summary.byType.AWS_ACCESS_KEY).toBeGreaterThanOrEqual(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("throws on a non-git directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-nogit-"));
    try {
      expect(() => scanHistory(new Scrubber(DEFAULT_CONFIG), dir)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
