# Aegis — Confidential Data Guard for AI

Stop secrets, PII, and proprietary code from leaking to AI agents — right from VS Code.

Aegis is a privacy guard layer for teams that use **Claude Code, Cursor, Cline, or any
AI agent**. It detects confidential data **100% locally** (nothing is sent to any model to
"check" it) and protects you two ways:

### 1. Live in-editor detection
Confidential data is underlined as you type — API keys, tokens, private keys, emails, SSNs,
credit cards, internal hostnames, your company's codenames, and `CONFIDENTIAL`-marked code.

- **Redact Selection** — replace confidential values with safe placeholders in place.
- **Copy as Redacted** — copy a scrubbed version to paste into any web AI tool safely.
- **Quick-fix** — one-click "Redact" on any flagged value.

### 2. The guard proxy (protects any agent)
Click the **🛡 Aegis** status-bar item to start the local guard. While it runs, Aegis points
VS Code's integrated terminals at itself, so any agent you launch (`claude`, `cursor`, your
own scripts) is automatically routed through it. Confidential data is stripped from each
request **before it leaves your machine** and restored in the response — so the workflow is
unchanged. Your API key is only forwarded, never stored.

**Protect every terminal, not just VS Code's:** run **Aegis: Protect All Terminals**. It adds
`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` to your shell profile (inside clearly-marked, fully
reversible markers) so *any* AI agent in *any* new terminal is cleaned automatically. Undo
with **Aegis: Stop Protecting Other Terminals**.

### 3. The system proxy (catch apps with hardcoded endpoints)
The base-URL approach only covers agents that read those env vars. **Aegis: Start System
Proxy** runs a transparent HTTPS-intercepting proxy: it decrypts only allowlisted AI hosts
(everything else is blind-tunnelled, never decrypted), scrubs in memory, and re-encrypts to
the real provider. VS Code terminals are auto-pointed at it with `HTTPS_PROXY` and
`NODE_EXTRA_CA_CERTS`, so Node agents work immediately. For apps **outside** VS Code, run
**Aegis: Show CA Trust Instructions** and install the root CA once.

> Unlike git-secrets / gitleaks, which only scan commits, Aegis guards the path those tools
> ignore: **what you actually send to the model.**

## Quick start

1. Install the extension.
2. Open the command palette → **Aegis: Start Guard Proxy** (or click the status bar item).
3. Open a terminal in VS Code and run your agent as usual — it's now protected.

Set your company's confidential terms in **Settings → Aegis**:

```jsonc
"aegis.dictionary": ["Project Phoenix", "BigCustomer Inc", "acme-internal.com"],
"aegis.mode": "redact",          // redact | block | warn
"aegis.blockOn": ["secret"]      // hard-block requests containing secrets
```

## Settings

| Setting | Default | What it does |
|---|---|---|
| `aegis.mode` | `redact` | redact + restore, hard-block, or warn-only |
| `aegis.blockOn` | `["secret"]` | categories that always block a request |
| `aegis.detectors.*` | `true` | toggle secrets / pii / network / dictionary / code |
| `aegis.dictionary` | `[]` | your codenames, customers, internal domains |
| `aegis.code.markers` | `CONFIDENTIAL, …` | strings that mark a file confidential |
| `aegis.proxy.port` | `8787` | local guard proxy port |
| `aegis.proxy.autoStart` | `false` | start the guard when VS Code opens |
| `aegis.proxy.setTerminalEnv` | `true` | auto-route integrated terminals through the guard |
| `aegis.diagnostics.enabled` | `true` | live squiggles on confidential data |

## Commands

`Aegis: Toggle/Start/Stop Guard Proxy` · `Start/Stop System Proxy` ·
`Show CA Trust Instructions` · `Protect All Terminals (system-wide)` ·
`Stop Protecting Other Terminals` · `Scan Current File` · `Scan Workspace` ·
`Redact Selection` · `Copy as Redacted` · `Show Activity Log`

## Privacy

Detection is fully local and offline. Matched values are **never** logged — the activity log
records only counts and types. The redact↔restore mapping lives in memory for a single
request and is then discarded.
