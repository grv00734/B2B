import * as vscode from "vscode";
import type { Server } from "node:http";
import { startServer } from "../../dist/server.js";
import type { AuditEntry } from "../../dist/audit.js";
import { getConfig, setTerminalEnvEnabled } from "./config.js";

/**
 * Owns the lifecycle of the in-process guard proxy. While running it points
 * VS Code's integrated terminals at the proxy so that any agent launched there
 * (Claude Code, Cursor CLI, custom scripts) is routed through Aegis with no
 * manual setup.
 */
export class ProxyController {
  private server: Server | null = null;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
    private readonly onStateChange: () => void,
  ) {}

  get running(): boolean {
    return this.server !== null;
  }

  get baseUrl(): string {
    const cfg = getConfig();
    return `http://${cfg.host}:${cfg.port}`;
  }

  async start(): Promise<void> {
    if (this.server) return;
    const cfg = getConfig();

    try {
      this.server = startServer(cfg, { auditSink: (e) => this.logAudit(e) });
    } catch (err) {
      void vscode.window.showErrorMessage(`Aegis: failed to start guard proxy — ${String(err)}`);
      this.server = null;
      return;
    }

    this.server.on("error", (err: NodeJS.ErrnoException) => {
      const msg =
        err.code === "EADDRINUSE"
          ? `port ${cfg.port} is already in use — change "aegis.proxy.port".`
          : String(err);
      void vscode.window.showErrorMessage(`Aegis: guard proxy error — ${msg}`);
      this.server = null;
      this.applyTerminalEnv(false);
      this.onStateChange();
    });

    this.applyTerminalEnv(true);
    this.output.appendLine(`[aegis] guard proxy started on ${this.baseUrl}  (mode=${cfg.mode})`);
    this.onStateChange();

    if (setTerminalEnvEnabled()) {
      void vscode.window.showInformationMessage(
        `Aegis guard is on. New terminals route AI agents through ${this.baseUrl}.`,
      );
    }
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
    this.applyTerminalEnv(false);
    this.output.appendLine("[aegis] guard proxy stopped");
    this.onStateChange();
  }

  async restart(): Promise<void> {
    if (!this.running) return;
    await this.stop();
    await this.start();
  }

  /** Set or clear the base-URL env vars for integrated terminals. */
  private applyTerminalEnv(on: boolean): void {
    const env = this.context.environmentVariableCollection;
    if (on && setTerminalEnvEnabled()) {
      env.description = "Aegis guard: routes AI agents through the local DLP proxy.";
      env.replace("ANTHROPIC_BASE_URL", this.baseUrl);
      env.replace("OPENAI_BASE_URL", `${this.baseUrl}/v1`);
    } else {
      env.delete("ANTHROPIC_BASE_URL");
      env.delete("OPENAI_BASE_URL");
    }
  }

  private logAudit(e: AuditEntry): void {
    if (e.summary.total === 0) return;
    const types = Object.entries(e.summary.byType)
      .map(([t, n]) => `${t}×${n}`)
      .join(", ");
    this.output.appendLine(
      `[${e.ts}] ${e.action.toUpperCase()} ${e.route} — ${e.summary.total} finding(s): ${types}`,
    );
  }

  dispose(): void {
    if (this.server) this.server.close();
    this.applyTerminalEnv(false);
  }
}
