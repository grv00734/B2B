/**
 * OS-level transparent interception rules.
 *
 * Linux uses iptables NAT REDIRECT; macOS uses pf rdr. In both cases the rule
 * rewrites outbound HTTPS to the local transparent port, and excludes traffic
 * owned by the proxy's own uid so the proxy's forward connections aren't
 * redirected back into themselves (which would loop forever). Run the proxy as
 * a dedicated user and pass that uid.
 *
 * We never run privileged commands implicitly: `plan()` returns the exact
 * commands to review, and `apply()` only runs them when already root.
 */
import { execFileSync } from "node:child_process";

export type Platform = "linux" | "darwin";

export interface TransparentOptions {
  /** Local port the transparent listener is bound to. */
  port: number;
  /** uid the proxy runs as; its own traffic is excluded to prevent loops. */
  uid?: string | number;
  /** Destination port to redirect (default 443). */
  dport?: number;
  /** Override the target OS (defaults to the current platform). */
  platform?: Platform;
}

export interface TransparentPlan {
  platform: Platform;
  install: string[];
  undo: string[];
  note: string;
  /** pf anchor file contents (macOS only). */
  anchorContent?: string;
}

const PF_ANCHOR = "/etc/pf.anchors/aegis";

function currentPlatform(): Platform {
  return process.platform === "darwin" ? "darwin" : "linux";
}

function uidNote(uid: string | number | undefined): string {
  return uid != null
    ? `Run the proxy as uid ${uid} (e.g. a dedicated 'aegis' user) so its forward traffic isn't redirected back into itself.`
    : `WARNING: no --uid given. On a single-user machine this will loop the proxy's own traffic. Create a dedicated user and pass its uid.`;
}

// --- Linux (iptables) ---

function iptablesArgs(o: TransparentOptions, action: "-A" | "-D"): string[] {
  const dport = o.dport ?? 443;
  const owner = o.uid != null ? ["-m", "owner", "!", "--uid-owner", String(o.uid)] : [];
  return ["-t", "nat", action, "OUTPUT", "-p", "tcp", "--dport", String(dport), ...owner, "-j", "REDIRECT", "--to-ports", String(o.port)];
}

// --- macOS (pf) ---

function pfAnchorContent(o: TransparentOptions): string {
  const dport = o.dport ?? 443;
  const lines = [`rdr pass proto tcp from any to any port ${dport} -> 127.0.0.1 port ${o.port}`];
  // pf translation rules: the LAST matching rule wins, so this exclusion for the
  // proxy's own uid must come after the rdr to take precedence.
  if (o.uid != null) lines.push(`no rdr proto tcp from any to any port ${dport} user ${o.uid}`);
  return lines.join("\n") + "\n";
}

export function plan(o: TransparentOptions): TransparentPlan {
  const platform = o.platform ?? currentPlatform();
  const note = uidNote(o.uid);

  if (platform === "darwin") {
    const content = pfAnchorContent(o);
    return {
      platform,
      anchorContent: content,
      install: [
        `sudo tee ${PF_ANCHOR} >/dev/null <<'EOF'\n${content}EOF`,
        `(cat /etc/pf.conf; printf 'rdr-anchor "aegis"\\nanchor "aegis"\\n') | sudo pfctl -f -`,
        `sudo pfctl -a aegis -f ${PF_ANCHOR}`,
        `sudo pfctl -e`,
      ],
      undo: [`sudo pfctl -a aegis -F all`, `sudo pfctl -f /etc/pf.conf`],
      note,
    };
  }

  return {
    platform,
    install: [`iptables ${iptablesArgs(o, "-A").join(" ")}`],
    undo: [`iptables ${iptablesArgs(o, "-D").join(" ")}`],
    note,
  };
}

/** Run the rules. Linux only (pf is too environment-specific to auto-apply). */
export function apply(o: TransparentOptions, action: "install" | "undo"): void {
  const platform = o.platform ?? currentPlatform();
  if (platform !== "linux") {
    throw new Error("Auto-apply is Linux-only. On macOS, run the printed pf commands.");
  }
  execFileSync("iptables", iptablesArgs(o, action === "install" ? "-A" : "-D"), { stdio: "inherit" });
}

export function isRoot(): boolean {
  return typeof process.getuid === "function" && process.getuid() === 0;
}
