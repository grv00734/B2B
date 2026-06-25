/**
 * Scans the entire git history (every version of every file ever committed) for
 * confidential data — the way gitleaks/GitGuardian do, but with the same local
 * engine and your custom dictionary. Catches secrets that were committed and
 * later "removed" but still live in history.
 */
import { spawnSync } from "node:child_process";
import type { Scrubber } from "./scrub/index.js";
import type { DetectionSummary, RawMatch } from "./types.js";
import { summarize } from "./scrub/index.js";

export interface HistoryFinding {
  blob: string;
  path: string;
  type: string;
  severity: string;
  preview: string;
}

export interface HistoryResult {
  scannedBlobs: number;
  findings: HistoryFinding[];
  summary: DetectionSummary;
}

const NUL = String.fromCharCode(0);

function git(args: string[], cwd: string, input?: string): { status: number; stdout: string } {
  const r = spawnSync("git", args, { cwd, input, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return { status: r.status ?? 1, stdout: r.stdout ?? "" };
}

function mask(value: string): string {
  return value.length <= 12 ? "•".repeat(value.length) : value.slice(0, 4) + "…" + value.slice(-2);
}

export function scanHistory(scrubber: Scrubber, cwd: string): HistoryResult {
  const objects = git(["rev-list", "--all", "--objects"], cwd);
  if (objects.status !== 0) {
    throw new Error("not a git repository (or git is unavailable)");
  }

  // Map blob sha -> first path we saw it at. Lines are "<sha>" or "<sha> <path>".
  const blobPath = new Map<string, string>();
  const shas: string[] = [];
  for (const line of objects.stdout.split("\n")) {
    if (!line) continue;
    const sp = line.indexOf(" ");
    const sha = sp === -1 ? line : line.slice(0, sp);
    const path = sp === -1 ? "" : line.slice(sp + 1);
    if (!blobPath.has(sha)) {
      blobPath.set(sha, path);
      shas.push(sha);
    }
  }

  // Identify which objects are blobs.
  const check = git(["cat-file", "--batch-check"], cwd, shas.join("\n"));
  const blobs: string[] = [];
  for (const line of check.stdout.split("\n")) {
    const [sha, type] = line.split(" ");
    if (type === "blob" && sha) blobs.push(sha);
  }

  const findings: HistoryFinding[] = [];
  const allMatches: RawMatch[] = [];
  let scanned = 0;
  const seen = new Set<string>(); // dedupe identical (path + value)

  for (const sha of blobs) {
    const content = git(["cat-file", "blob", sha], cwd).stdout;
    if (!content || content.includes(NUL)) continue; // skip empty / binary blobs
    scanned++;
    const path = blobPath.get(sha) ?? "";
    for (const m of scrubber.detect(content)) {
      const key = `${path}:${m.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      allMatches.push(m);
      findings.push({ blob: sha.slice(0, 10), path, type: m.type, severity: m.severity, preview: mask(m.value) });
    }
  }

  return { scannedBlobs: scanned, findings, summary: summarize(allMatches) };
}
