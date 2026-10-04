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

## Two ways to use it

| | Self-hosted | Web version |
| --- | --- | --- |
| Who it is for | Developers, CI pipelines, private or local plugins | Anyone who wants to check a plugin before installing it |
| Input | Folder, `.zip`, GitHub URL or `owner/repo` | GitHub URL (repo, folder or marketplace repo) or `.zip` upload |
| Private repos | Yes (scan a local clone) | No, public GitHub repos only |
| Where code is scanned | Your machine | The visitor's browser |
| Cost | Free | Free for users; the hosted instance runs on Workers Paid, $5/month (see below) |

## Self-hosted

Requires Node 22.18 or later, which runs the TypeScript source directly.

```bash
git clone https://github.com/thieung/mod-scanner && cd mod-scanner
npm install
```

### Scan from the terminal

```bash
# folder, zip, or GitHub URL / owner/repo
node src/cli.ts ./path/to/plugin
node src/cli.ts https://github.com/owner/repo/tree/main/plugins/my-mod
node src/cli.ts plugin.zip --json > report.json

# CI: exit 1 on medium or worse (default: high)
node src/cli.ts ./plugin --fail-on medium
```

To scan a plugin you already installed, point the CLI at its folder under
`~/.claude/plugins/`.

### Run your own web app

```bash
npm start   # builds public/scan-worker.js, then serves http://127.0.0.1:8787 (scanner on /scan)
```

`PORT`, `HOST` and `RATE_LIMIT` (scans per minute per IP) are configurable. The
Node server serves the same pages as the web version and also has server-side
scan endpoints:

### API

| Method | Path | Body |
| --- | --- | --- |
| `POST` | `/api/scan/upload?name=x.zip` | raw zip bytes, at most 10 MB |
| `POST` | `/api/scan/github` | `{ "url": "https://github.com/owner/repo[/tree/ref/path]" }` |
| `GET` | `/api/github?url=…` | returns the repository zip; the browser scans it |
| `GET` | `/healthz` | |

Both scan endpoints return a `ScanReport` (`src/core/types.ts`).

### Develop

```bash
npm test
npm run typecheck
```

## Web version

The web portal (landing page on `/`, scanner on `/scan`) runs on Cloudflare
Workers. Users install nothing.

### Workflow

1. **Input.** On `/scan`, paste a GitHub link: `owner/repo`, a repository URL,
   a `/tree/<ref>/<folder>` link to one plugin, or a marketplace repository
   (one report per plugin). Or drop a plugin `.zip` of at most 10 MB.
2. **Fetch.** For GitHub, the browser calls `GET /api/github?url=…`. The Worker
   downloads the archive from `codeload.github.com` (at most 40 MB) and returns
   the zip. Browsers cannot download it directly because codeload sends no CORS
   headers.
3. **Scan.** The browser loads `scan-worker.js` (first scan only, 3.6 MB, about
   1 MB gzipped) and scans in a Web Worker. Uploaded zips never leave the
   browser, and the Worker never parses plugin code.
4. **Report.** Verdict, findings with file and line, capability manifest and
   SHA-256, downloadable as JSON. The page URL keeps `?url=…`, so a GitHub scan
   can be shared as a link that re-runs the scan when opened.

There is no lookup by plugin name (`name@marketplace`) yet. Paste the
marketplace repository or the plugin's folder link instead.

### Cost

The hosted instance runs on the Workers Paid plan ($5/month). Pricing as listed
on [developers.cloudflare.com](https://developers.cloudflare.com/workers/platform/pricing/)
on 2026-10-04:

| | Free | Paid (hosted instance) |
| --- | --- | --- |
| Price | $0 | $5/month minimum |
| Requests | 100,000 per day | 10 million/month included, then $0.30 per million |
| CPU time | 10 ms per request | 30 million ms/month included (up to 5 minutes per request), then $0.02 per million ms |
| KV | | 10 million reads, 1 million writes, 1 GB included |
| D1 | | 25 billion rows read, 50 million rows written, 5 GB included |

What one scan uses (estimates from the code, not measured on live traffic):

- **Requests.** `run_worker_first` routes every request through the Worker so it
  can add security headers, so page files count as Worker requests. A first
  visit to `/scan` plus one GitHub scan is about 6 requests (page, CSS,
  `i18n.js`, `app.js`, `scan-worker.js`, `/api/github`); a repeat scan from a
  cached browser is 1. A `.zip` upload makes no API request. The 10 million
  included requests cover roughly 1.5 million first-visit scans a month, so the
  $5 base fee is the whole bill at any realistic traffic.
- **CPU.** The Worker only adds headers and passes bytes through. Time spent
  waiting on GitHub does not count as CPU time. Check the real figures in the
  Worker's observability tab (enabled in `wrangler.jsonc`).
- **Unlike the free plan, Paid has no hard cap.** Traffic beyond the included
  amounts is billed instead of refused, so abuse of `/api/github` turns into
  cost. 10 million extra requests cost $3.

### Feasibility and limits

The web version is feasible as built. The expensive part, parsing TypeScript and
running the rules, happens in the visitor's browser, which also means uploaded
zips never reach a server.

The Paid plan also makes scanning inside the Worker possible, because it lifts
the 10 ms CPU limit. On a laptop, scanning `anthropics/claude-plugins-official`
(40 plugins) takes about 0.3–0.4 s of CPU and a single small plugin under 50 ms,
so 30 million CPU ms would cover tens of thousands of large scans a month. The
blocker is memory: a Worker has 128 MB, while a scan accepts a 40 MB archive
that unpacks to up to 150 MB. Server-side scanning would need lower limits or
streaming, and would give up the "uploads stay in your browser" property. It is
not built.

Known limits:

- Public GitHub repositories only; archives up to 40 MB, uploads up to 10 MB.
- The first scan downloads about 1 MB, and large repositories use the visitor's
  CPU, which is slower on phones.
- `/api/github` is a public proxy. Abuse adds billed requests, and GitHub may
  throttle the Worker (GitHub does not publish codeload limits). Add a WAF
  rate-limiting rule on `/api/github` and watch usage in the dashboard.
- No accounts, scan history or stored reports. The Paid plan's KV and D1
  quotas would hold stored reports at small scale without raising the bill, but
  none of this is built.

### Deploy to Cloudflare

**Option 1: connect the repository (recommended).** In the Cloudflare
dashboard, go to Workers & Pages → Create → Import a repository, and pick
this repo. Keep the default deploy command (`npx wrangler deploy`).
`wrangler.jsonc` runs `npm run build:web` first. Every push to `main` then
deploys.

**Option 2: deploy from a terminal.**

```bash
npx wrangler login        # or set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID
npm run deploy            # builds the browser scanner, then wrangler deploy
```

To run locally on the Workers runtime: `npm run dev:cf`.

To add a custom domain: open the Worker → Settings → Domains & Routes. For
abuse protection, add a WAF rate-limiting rule on `/api/github`.

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

## Languages and theme

Both pages have a light/dark switch and a VI/EN switch. Without a saved choice,
the theme follows the system setting and the language follows the browser.
Choices are kept in `localStorage`.

English text lives in the HTML. Vietnamese lives in
`scripts/landing_strings.py`. After changing page copy, update that table and
run:

```bash
python3 scripts/build-i18n.py   # marks the strings in the pages and regenerates public/i18n.js
```

Findings text comes from the scanner rules and is English only for now.

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
src/web/        browser entry: the scan Web Worker
src/worker.ts   Cloudflare Worker: assets + GitHub proxy
src/server.ts   Node server: same pages and proxy, plus the /api/scan/* endpoints
src/cli.ts      CLI
public/         landing page (index.html), scanner UI (scan.html, app.js, style.css),
                theme and language switch (i18n.js)
scripts/        build-i18n.py + landing_strings.py: the English/Vietnamese string table
test/           node:test suite and fixtures
```
