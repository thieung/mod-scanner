# Mod Scanner

Static security scanner for Claude Code plugins and mods. Point it at a plugin
folder, a `.zip` or a GitHub URL. It lists what the plugin can do (its
capability manifest) and flags patterns typical of malicious plugins.
**Nothing from the scanned plugin is executed.**

Mods are TypeScript hook modules that run with the same access as Claude Code
itself, with no sandbox. Each one reaches the machine only through the engine
interface `$` (`$.fs`, `$.http`, `$.process`, `$.settings`, `$.env`, …) and the
events it hooks (`tool.call`, `tool.check`, `prompt.compose`, …). That makes
static analysis tractable: resolve every call back to its `$` path and you know
what the mod can do.

## Scope (v0.1)

| In scope | Out of scope (later) |
| --- | --- |
| Mod modules (`hooks/hooks.json` → `modules`) and any other TS/JS in the plugin, parsed with the TypeScript compiler | Running the mod in an instrumented sandbox with honeytokens |
| Classic shell hooks in `hooks.json` / `plugin.json` | LLM review of intent vs. description |
| MCP servers in `.mcp.json` / `plugin.json` | Diffing capabilities between versions (rug-pull detection) |
| Skills, agents, commands, `CLAUDE.md` (prompt injection) | Marketplace crawling, a public verdict database, accounts |
| Shell, Python and other scripts; `package.json` install scripts; shipped binaries | Pre-install gate inside Claude Code |
| Capability manifest, findings with file:line and snippet, 0–100 score, verdict, SHA-256 per plugin | Data-flow through Node APIs in MCP servers (only listed as capabilities) |
| Web app (upload or GitHub URL), CLI with CI exit codes, JSON output | |

## Usage

Requires Node 22.18 or later, which runs the TypeScript source directly.

```bash
cd apps/mod-scanner
npm install

# CLI: folder, zip, or GitHub URL / owner/repo
node src/cli.ts ./path/to/plugin
node src/cli.ts https://github.com/owner/repo/tree/main/plugins/my-mod
node src/cli.ts plugin.zip --json > report.json
node src/cli.ts ./plugin --fail-on medium   # exit 1 on medium or worse (default: high)

# Web app: landing page on http://127.0.0.1:8787, scanner on /scan
npm start                  # PORT, HOST, RATE_LIMIT (scans/min/IP) are configurable

npm test
npm run typecheck
```

### API

| Method | Path | Body |
| --- | --- | --- |
| `POST` | `/api/scan/upload?name=x.zip` | raw zip bytes, at most 10 MB |
| `POST` | `/api/scan/github` | `{ "url": "https://github.com/owner/repo[/tree/ref/path]" }` |
| `GET` | `/healthz` | |

Both scan endpoints return a `ScanReport` (`src/core/types.ts`).

## Verdicts

| Verdict | When |
| --- | --- |
| Malicious indicators | any critical finding |
| High risk | any high finding, or score ≥ 40 |
| Review recommended | any medium finding, or score ≥ 8 |
| No known issues found | otherwise |

There is deliberately no "safe" verdict. A clean result is tied to the exact
SHA-256 that was scanned.

## What it detects

**Mods (`src/core/mod-analyzer.ts`)**

- Data flow from sensitive sources (`$.settings.read`, secret `$.env.get`,
  credential-file `$.fs.read`, `$.session.messages`) to `$.http.fetch`,
  `$.process.*`, `$.mcp.call` or `$.fs.write`, followed through aliases
  (`const { fetch: send } = $.http`), renamed hook parameters and intermediate
  variables.
- `tool.call` hooks that append commands to the model's Bash calls, or rewrite
  file edits or URLs.
- `tool.check` hooks that answer `allow` for risky tools (auto-approve).
- `prompt.compose` / `prompt.*` hooks that inject concealment, code-insertion or
  exfiltration instructions, or URLs.
- Shell or computed commands, keychain access, env hijack (`NODE_OPTIONS`,
  `PATH`, `ANTHROPIC_BASE_URL`, …), writes to persistence paths (`.git/hooks`,
  shell rc files, `.claude/settings.json`, `CLAUDE.md`).
- Hiding: computed `$[...]` access, `eval` / `new Function`, `atob` and base64
  strings (decoded and shown), hex escapes, minified source.
- Gating: date comparisons (time bombs), CI or sandbox checks, per-user or
  per-repo targeting.
- Requests to tunnel, paste, webhook and raw-IP hosts.

**Everything else (`src/core/scan.ts`, `src/core/text-rules.ts`)**

- Shell: pipe-to-shell, reverse shells, decode-and-exec, credential files sent
  over the network, persistence, turning off safety mechanisms.
- Instructions: concealment, overriding instructions, code injection,
  exfiltration, hidden HTML comments, invisible Unicode (zero-width, bidi, tag
  characters), large encoded blobs, `allowed-tools` granting unrestricted Bash.
- MCP: unpinned `npx`/`uvx` packages, plain-HTTP remote servers, servers
  started through a shell.
- `preinstall`/`postinstall` scripts, compiled binaries.

**False-positive controls.** Quoted phrases count as examples, not
instructions. Findings in test files that nothing imports are capped at low. A
plugin calling the service it is named for (`api.telegram.org` in a Telegram
plugin) is not flagged.

## Calibration

Tested against `anthropics/claude-plugins-official` (40 plugins) and
`anthropics/claude-code/plugins` (12 plugins):

- 0 rated malicious or high risk.
- 9 rated review, for unpinned `@latest` MCP packages, unrestricted Bash in
  `allowed-tools`, a minified bundle, and scripts that mention credential paths.

The ten fixtures in `test/fixtures/` (one benign, nine malicious) cover every
rule family. Their domains are `.invalid`, and the fixtures are inert unless
someone installs them as plugins.

## Server hardening

- Uploads and GitHub archives are kept in memory and never written to disk.
- Zip sizes are checked from the central directory before inflating (zip-bomb
  guard).
- Paths containing `..` are dropped.
- The GitHub fetcher only contacts `codeload.github.com` and follows no
  redirects (no SSRF).
- Per-IP rate limit.
- Strict CSP; the UI builds the DOM with `textContent` only.

## Layout

```
src/core/       analysis: types, mod analyzer (TS AST), text/shell rules, plugin scan + scoring
src/sources/    zip, directory and GitHub readers with size limits
src/cli.ts      CLI
src/server.ts   HTTP server + API
public/         landing page (index.html) and scanner UI (scan.html, app.js, style.css)
test/           node:test suite and fixtures
```
