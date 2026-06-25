import * as vscode from "vscode";
import type { Server } from "node:http";
import { startMitmProxy } from "../../dist/mitm.js";
import { trustInstructions } from "../../dist/ca.js";
import type { AuditEntry } from "../../dist/audit.js";
import { getConfig } from "./config.js";

/**
 * Runs the transparent HTTPS-intercepting proxy ("system proxy"). Unlike the
 * base-URL proxy, this catches apps that hardcode their endpoint — any client
 * that honours HTTPS_PROXY and trusts the Aegis CA. For integrated terminals we
 * set both automatically (incl. NODE_EXTRA_CA_CERTS so Node agents trust the CA
 * without an OS-level install).
 */
export class SystemProxyController {
  private server: Server | null = null;
  private caPath = "";

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
    private readonly onStateChange: () => void,
  ) {}

  get running(): boolean {
    return this.server !== null;
  }

  async start(): Promise<void> {
    if (this.server) return;
    const cfg = getConfig();

    try {
      const handle = startMitmProxy(cfg, { auditSink: (e) => this.logAudit(e) });
      this.server = handle.server;
      this.caPath = handle.ca.caCertPath;
    } catch (err) {
      void vscode.window.showErrorMessage(`Aegis: failed to start system proxy — ${String(err)}`);
      this.server = null;
      return;
    }

    this.server.on("error", (err: NodeJS.ErrnoException) => {
      const msg = err.code === "EADDRINUSE" ? `port ${cfg.mitm.port} is in use.` : String(err);
      void vscode.window.showErrorMessage(`Aegis: system proxy error — ${msg}`);
      this.server = null;
      this.applyEnv(false);
      this.onStateChange();
    });

    this.applyEnv(true);
    this.output.appendLine(`[aegis] system proxy on http://${cfg.host}:${cfg.mitm.port} (CA: ${this.caPath})`);
    this.onStateChange();

    const pick = await vscode.window.showInformationMessage(
      `Aegis system proxy is on (port ${cfg.mitm.port}). VS Code terminals now route HTTPS through it and trust the Aegis CA. ` +
        `For apps outside VS Code, install the CA once.`,
      "Show CA trust steps",
    );
    if (pick === "Show CA trust steps") this.showInstructions();
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
    this.applyEnv(false);
    this.output.appendLine("[aegis] system proxy stopped");
    this.onStateChange();
  }

  showInstructions(): void {
    this.output.appendLine("\n" + trustInstructions(this.caPath || "<run the system proxy first>"));
    this.output.show();
  }

  private applyEnv(on: boolean): void {
    const env = this.context.environmentVariableCollection;
    if (on) {
      const cfg = getConfig();
      const url = `http://${cfg.host}:${cfg.mitm.port}`;
      env.replace("HTTPS_PROXY", url);
      env.replace("HTTP_PROXY", url);
      env.replace("NODE_EXTRA_CA_CERTS", this.caPath);
    } else {
      env.delete("HTTPS_PROXY");
      env.delete("HTTP_PROXY");
      env.delete("NODE_EXTRA_CA_CERTS");
    }
  }

  private logAudit(e: AuditEntry): void {
    if (e.summary.total === 0) return;
    const types = Object.entries(e.summary.byType).map(([t, n]) => `${t}×${n}`).join(", ");
    this.output.appendLine(`[${e.ts}] ${e.action.toUpperCase()} ${e.route} — ${e.summary.total} finding(s): ${types}`);
  }

  dispose(): void {
    if (this.server) this.server.close();
    this.applyEnv(false);
  }
}
