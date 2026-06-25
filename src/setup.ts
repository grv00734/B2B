/**
 * System-wide auto-routing: write the proxy's base URLs into the user's shell
 * profile so that EVERY new terminal (not just ones inside an editor) sends its
 * AI-agent traffic through the Aegis guard automatically.
 *
 * The change is wrapped in clearly-marked managed markers and is fully
 * reversible via `uninstallShellProfile()` / `aegis setup --undo`.
 */
import { homedir } from "node:os";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const BEGIN = "# >>> aegis guard >>>";
const END = "# <<< aegis guard <<<";

export interface SetupResult {
  files: string[];
  baseUrl: string;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Profiles we will manage, in priority order. Falls back to ~/.profile. */
export function shellProfiles(): string[] {
  const home = homedir();
  const candidates = [".zshrc", ".bashrc", ".bash_profile", ".profile"].map((f) => join(home, f));
  const existing = candidates.filter((f) => existsSync(f));
  return existing.length ? existing : [join(home, ".profile")];
}

function managedBlock(baseUrl: string): string {
  return [
    BEGIN,
    "# Routes AI coding agents (Claude Code, Cursor CLI, etc.) through the local",
    "# Aegis DLP guard so confidential data is scrubbed before it leaves this machine.",
    `export ANTHROPIC_BASE_URL="${baseUrl}"`,
    `export OPENAI_BASE_URL="${baseUrl}/v1"`,
    END,
    "",
  ].join("\n");
}

function stripManaged(text: string): string {
  const re = new RegExp(`\\n?${escapeRegExp(BEGIN)}[\\s\\S]*?${escapeRegExp(END)}\\n?`, "g");
  return text.replace(re, "\n");
}

/** True if any managed profile currently contains the Aegis block. */
export function isInstalled(): boolean {
  return shellProfiles().some((f) => existsSync(f) && readFileSync(f, "utf8").includes(BEGIN));
}

export function installShellProfile(baseUrl: string): SetupResult {
  const files = shellProfiles();
  for (const f of files) {
    const current = existsSync(f) ? readFileSync(f, "utf8") : "";
    const cleaned = stripManaged(current).replace(/\n+$/, "\n");
    writeFileSync(f, `${cleaned}\n${managedBlock(baseUrl)}`, "utf8");
  }
  return { files, baseUrl };
}

export function uninstallShellProfile(): SetupResult {
  const files = shellProfiles().filter((f) => existsSync(f));
  const touched: string[] = [];
  for (const f of files) {
    const current = readFileSync(f, "utf8");
    if (current.includes(BEGIN)) {
      writeFileSync(f, stripManaged(current), "utf8");
      touched.push(f);
    }
  }
  return { files: touched, baseUrl: "" };
}
