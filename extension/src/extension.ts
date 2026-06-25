import * as vscode from "vscode";
import { Scrubber } from "../../dist/scrub/index.js";
import { Vault } from "../../dist/scrub/placeholders.js";
import type { Server } from "node:http";
import { installShellProfile, uninstallShellProfile } from "../../dist/setup.js";
import { startGui } from "../../dist/gui.js";
import { getConfig, diagnosticsEnabled, autoStartEnabled } from "./config.js";
import { DiagnosticsManager } from "./diagnostics.js";
import { ProxyController } from "./proxy.js";
import { SystemProxyController } from "./systemProxy.js";
import { StatusBar } from "./statusbar.js";

let scrubber: Scrubber;
let guiServer: Server | undefined;
const ONBOARDED_KEY = "aegis.onboarded";

export function activate(context: vscode.ExtensionContext): void {
  scrubber = new Scrubber(getConfig());

  const output = vscode.window.createOutputChannel("Aegis");
  const diagnostics = new DiagnosticsManager(scrubber);
  diagnostics.setEnabled(diagnosticsEnabled());
  const statusBar = new StatusBar();

  const refreshStatus = (): void => {
    const findings = vscode.window.activeTextEditor
      ? diagnostics.countFor(vscode.window.activeTextEditor.document.uri)
      : 0;
    const running = proxy.running || systemProxy.running;
    statusBar.update(running, findings);
    void vscode.commands.executeCommand("setContext", "aegis.proxyRunning", running);
  };

  const proxy = new ProxyController(context, output, refreshStatus);
  const systemProxy = new SystemProxyController(context, output, refreshStatus);

  context.subscriptions.push(output, diagnostics, statusBar, proxy, systemProxy);

  // --- Live scanning of open documents (debounced) ---
  let debounce: ReturnType<typeof setTimeout> | undefined;
  const scheduleScan = (doc: vscode.TextDocument): void => {
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => {
      diagnostics.scan(doc);
      refreshStatus();
    }, 350);
  };

  for (const editor of vscode.window.visibleTextEditors) diagnostics.scan(editor.document);

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => diagnostics.scan(doc)),
    vscode.workspace.onDidChangeTextDocument((e) => scheduleScan(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.clear(doc.uri)),
    vscode.window.onDidChangeActiveTextEditor(refreshStatus),
  );

  // --- React to settings changes ---
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration("aegis")) return;
      scrubber = new Scrubber(getConfig());
      diagnostics.setScrubber(scrubber);
      diagnostics.setEnabled(diagnosticsEnabled());
      for (const editor of vscode.window.visibleTextEditors) diagnostics.scan(editor.document);
      if (proxy.running) void proxy.restart();
      refreshStatus();
    }),
  );

  // --- Code actions (Redact quick-fix) ---
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider("*", diagnostics, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );

  // --- Commands ---
  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.toggleProxy", () =>
      proxy.running ? proxy.stop() : proxy.start(),
    ),
    vscode.commands.registerCommand("aegis.startProxy", () => proxy.start()),
    vscode.commands.registerCommand("aegis.stopProxy", () => proxy.stop()),
    vscode.commands.registerCommand("aegis.startSystemProxy", () => systemProxy.start()),
    vscode.commands.registerCommand("aegis.stopSystemProxy", () => systemProxy.stop()),
    vscode.commands.registerCommand("aegis.showCaInstructions", () => systemProxy.showInstructions()),
    vscode.commands.registerCommand("aegis.protectAllTerminals", () => protectAllTerminals(proxy)),
    vscode.commands.registerCommand("aegis.unprotectAllTerminals", () => {
      const { files } = uninstallShellProfile();
      void vscode.window.showInformationMessage(
        files.length > 0
          ? `Aegis: removed auto-routing from ${files.length} shell profile(s). Open a new terminal to apply.`
          : "Aegis: auto-routing was not installed.",
      );
    }),
    vscode.commands.registerCommand("aegis.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      diagnostics.scan(editor.document);
      refreshStatus();
      const n = diagnostics.countFor(editor.document.uri);
      void vscode.window.showInformationMessage(
        n > 0 ? `Aegis found ${n} confidential item(s) in this file.` : "Aegis: no confidential data found.",
      );
    }),
    vscode.commands.registerCommand("aegis.scanWorkspace", () => scanWorkspace(diagnostics)),
    vscode.commands.registerCommand("aegis.redactSelection", () => redactSelection()),
    vscode.commands.registerCommand("aegis.copyRedacted", () => copyRedacted()),
    vscode.commands.registerCommand("aegis.showAudit", () => output.show()),
    vscode.commands.registerCommand("aegis.openDashboard", () => {
      const cfg = getConfig();
      const guiPort = 8799;
      if (!guiServer) {
        try {
          guiServer = startGui(cfg, guiPort);
        } catch (err) {
          void vscode.window.showErrorMessage(`Aegis: could not start dashboard — ${String(err)}`);
          return;
        }
      }
      void vscode.env.openExternal(vscode.Uri.parse(`http://${cfg.host}:${guiPort}`));
    }),
    vscode.commands.registerCommand("aegis.openDashboardPanel", () => {
      const cfg = getConfig();
      const guiPort = 8799;
      if (!guiServer) {
        try {
          guiServer = startGui(cfg, guiPort);
        } catch (err) {
          void vscode.window.showErrorMessage(`Aegis: could not start dashboard — ${String(err)}`);
          return;
        }
      }
      const url = `http://${cfg.host}:${guiPort}`;
      const panel = vscode.window.createWebviewPanel("aegisDashboard", "Aegis", vscode.ViewColumn.Active, {
        enableScripts: true,
        retainContextWhenHidden: true,
      });
      panel.webview.html =
        `<!doctype html><html><head><meta charset="utf-8"/>` +
        `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; frame-src ${url};"/>` +
        `<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100vh}</style></head>` +
        `<body><iframe src="${url}"></iframe></body></html>`;
    }),
    { dispose: () => guiServer?.close() },
  );

  refreshStatus();
  if (autoStartEnabled()) void proxy.start();
  else if (!context.globalState.get<boolean>(ONBOARDED_KEY)) {
    void context.globalState.update(ONBOARDED_KEY, true);
    void promptOnboarding(proxy);
  }
}

export function deactivate(): void {
  /* subscriptions are disposed by VS Code */
}

/** One-time prompt so protection is discoverable without being forced on. */
async function promptOnboarding(proxy: ProxyController): Promise<void> {
  const choice = await vscode.window.showInformationMessage(
    "Aegis can automatically remove confidential data from anything you send to AI agents. Turn it on?",
    "Protect this window",
    "Protect all terminals",
    "Not now",
  );
  if (choice === "Protect this window") await proxy.start();
  else if (choice === "Protect all terminals") await protectAllTerminals(proxy);
}

/** Write base-URL env vars into the user's shell profile (explicit + reversible). */
async function protectAllTerminals(proxy: ProxyController): Promise<void> {
  const url = proxy.baseUrl;
  const choice = await vscode.window.showWarningMessage(
    `Route every new terminal through the Aegis guard? This adds ANTHROPIC_BASE_URL / OPENAI_BASE_URL ` +
      `(→ ${url}) to your shell profile so any AI agent is automatically protected. Reversible via ` +
      `"Aegis: Stop Protecting Other Terminals".`,
    { modal: true },
    "Enable",
  );
  if (choice !== "Enable") return;

  const { files } = installShellProfile(url);
  if (!proxy.running) await proxy.start();
  void vscode.window.showInformationMessage(
    `Aegis is now protecting all terminals (updated ${files.length} profile(s)). Open a new terminal to apply.`,
  );
}

// --- Command implementations ---

function fullRange(doc: vscode.TextDocument): vscode.Range {
  const lastLine = doc.lineAt(Math.max(0, doc.lineCount - 1));
  return new vscode.Range(new vscode.Position(0, 0), lastLine.range.end);
}

async function redactSelection(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const range = editor.selection.isEmpty ? fullRange(editor.document) : editor.selection;
  const text = editor.document.getText(range);

  const { text: scrubbed, matches } = scrubber.scrub(text, new Vault());
  if (matches.length === 0) {
    void vscode.window.showInformationMessage("Aegis: no confidential data in the selection.");
    return;
  }
  await editor.edit((b) => b.replace(range, scrubbed));
  void vscode.window.showInformationMessage(`Aegis redacted ${matches.length} item(s).`);
}

async function copyRedacted(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const range = editor.selection.isEmpty ? fullRange(editor.document) : editor.selection;
  const text = editor.document.getText(range);

  const { text: scrubbed, matches } = scrubber.scrub(text, new Vault());
  await vscode.env.clipboard.writeText(scrubbed);
  void vscode.window.showInformationMessage(
    `Aegis copied a redacted copy (${matches.length} item(s) removed). Safe to paste into any AI tool.`,
  );
}

async function scanWorkspace(diagnostics: DiagnosticsManager): Promise<void> {
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "Aegis: scanning workspace…" },
    async () => {
      const files = await vscode.workspace.findFiles(
        "**/*",
        "**/{node_modules,.git,dist,build,out,.next,coverage}/**",
        5000,
      );
      let totalFindings = 0;
      let filesWithFindings = 0;
      for (const uri of files) {
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          diagnostics.scan(doc);
          const n = diagnostics.countFor(uri);
          if (n > 0) {
            totalFindings += n;
            filesWithFindings++;
          }
        } catch {
          /* binary or unreadable file — skip */
        }
      }
      void vscode.window.showInformationMessage(
        totalFindings > 0
          ? `Aegis: ${totalFindings} confidential item(s) across ${filesWithFindings} file(s). See the Problems panel.`
          : "Aegis: no confidential data found in the workspace.",
      );
    },
  );
}
