import * as vscode from "vscode";

/** A single status-bar item reflecting guard state + findings in the active file. */
export class StatusBar {
  private item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "aegis.toggleProxy";
    this.item.show();
  }

  update(proxyRunning: boolean, findingsInFile: number): void {
    const shield = proxyRunning ? "$(shield)" : "$(shield)";
    const state = proxyRunning ? "Guard on" : "Guard off";
    this.item.text = findingsInFile > 0 ? `${shield} Aegis: ${state} ⚠ ${findingsInFile}` : `${shield} Aegis: ${state}`;
    this.item.tooltip = new vscode.MarkdownString(
      [
        `**Aegis — Confidential Data Guard**`,
        ``,
        proxyRunning
          ? `Proxy: **running** — AI agents in new terminals are protected.`
          : `Proxy: **stopped** — click to start.`,
        findingsInFile > 0
          ? `\nThis file has **${findingsInFile}** confidential item(s).`
          : ``,
        `\n_Click to toggle the guard proxy._`,
      ].join("\n"),
    );
    this.item.backgroundColor = proxyRunning
      ? undefined
      : new vscode.ThemeColor("statusBarItem.warningBackground");
  }

  dispose(): void {
    this.item.dispose();
  }
}
