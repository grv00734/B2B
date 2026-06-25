import * as vscode from "vscode";
import { Scrubber } from "../../dist/scrub/index.js";
import type { RawMatch, Severity } from "../../dist/types.js";

const MAX_BYTES = 1_000_000; // skip very large files to keep typing responsive

function toVsSeverity(sev: Severity): vscode.DiagnosticSeverity {
  switch (sev) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Warning;
    case "medium":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Publishes diagnostics highlighting confidential data in open documents, and
 * provides a "Redact" quick-fix. Detection is the same offline engine used by
 * the proxy, so the editor view matches what would actually be scrubbed.
 */
export class DiagnosticsManager implements vscode.CodeActionProvider {
  private collection: vscode.DiagnosticCollection;
  private scrubber: Scrubber;
  private enabled = true;

  constructor(scrubber: Scrubber) {
    this.scrubber = scrubber;
    this.collection = vscode.languages.createDiagnosticCollection("aegis");
  }

  setScrubber(scrubber: Scrubber): void {
    this.scrubber = scrubber;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    if (!enabled) this.collection.clear();
  }

  /** Number of findings currently shown for a document (for the status bar). */
  countFor(uri: vscode.Uri): number {
    return this.collection.get(uri)?.length ?? 0;
  }

  scan(doc: vscode.TextDocument): void {
    if (!this.enabled) return;
    if (doc.uri.scheme !== "file" && doc.uri.scheme !== "untitled") return;
    const text = doc.getText();
    if (text.length > MAX_BYTES) return;

    const matches = this.scrubber.detect(text);
    const diags = matches.map((m) => this.toDiagnostic(doc, m));
    this.collection.set(doc.uri, diags);
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }

  private toDiagnostic(doc: vscode.TextDocument, m: RawMatch): vscode.Diagnostic {
    const range = new vscode.Range(doc.positionAt(m.start), doc.positionAt(m.end));
    const d = new vscode.Diagnostic(
      range,
      `${m.type} (${m.category}) — confidential. Aegis will redact this before it reaches any AI.`,
      toVsSeverity(m.severity),
    );
    d.source = "Aegis";
    d.code = m.type;
    return d;
  }

  // --- CodeActionProvider: offer a redact fix on our diagnostics ---
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== "Aegis") continue;
      const fix = new vscode.CodeAction(`Redact ${String(diag.code)}`, vscode.CodeActionKind.QuickFix);
      fix.diagnostics = [diag];
      fix.edit = new vscode.WorkspaceEdit();
      const placeholder = `[[REDACTED:${String(diag.code)}:X]]`;
      fix.edit.replace(document.uri, diag.range, placeholder);
      actions.push(fix);
    }
    return actions;
  }

  dispose(): void {
    this.collection.dispose();
  }
}
