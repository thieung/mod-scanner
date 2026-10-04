import { createHash } from 'node:crypto'
import { analyzeModule, type CapabilityHit } from './mod-analyzer.ts'
import { SECRET_PATH, scanInstructionText, scanShellText } from './text-rules.ts'
import {
  SEVERITY_ORDER,
  type Capability,
  type Component,
  type FileTree,
  type Finding,
  type PluginReport,
  type ScanReport,
  type Severity,
  type Verdict,
} from './types.ts'

export const SCANNER = { name: 'mod-scanner', version: '0.1.0' }

const SCRIPT_EXT = /\.(m|c)?(t|j)sx?$/
const SHELL_EXT = /\.(sh|bash|zsh|ps1|py|rb|pl|bat|cmd)$/
const MAX_TEXT_BYTES = 2 * 1024 * 1024
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|fixtures?)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$/
const RESOLVE_SUFFIXES = ['', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx', '/index.ts', '/index.tsx', '/index.js']

const WEIGHT: Record<Severity, number> = { critical: 60, high: 25, medium: 8, low: 2, info: 0 }

const decoder = new TextDecoder('utf-8', { fatal: false })
const text = (bytes: Uint8Array) => decoder.decode(bytes)

function sha256(tree: FileTree, paths: string[]): string {
  const hash = createHash('sha256')
  for (const path of [...paths].sort()) {
    hash.update(path)
    hash.update('\0')
    hash.update(tree.get(path)!)
    hash.update('\0')
  }
  return hash.digest('hex')
}

function parseJson(bytes: Uint8Array | undefined): { value?: unknown; error?: string } {
  if (!bytes) return {}
  try {
    return { value: JSON.parse(text(bytes)) }
  } catch (error) {
    return { error: (error as Error).message }
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

function binaryKind(bytes: Uint8Array): string | undefined {
  const b = bytes
  if (b.length < 4) return undefined
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'ELF executable'
  if (b[0] === 0x4d && b[1] === 0x5a) return 'Windows executable'
  const magic = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(magic)) return 'Mach-O executable'
  if (b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d) return 'WebAssembly module'
  return undefined
}

/** Folders holding `.claude-plugin/plugin.json`, or the root when it looks like a plugin. */
export function findPluginRoots(tree: FileTree): string[] {
  const roots = new Set<string>()
  for (const path of tree.keys()) {
    const match = /^(.*?)(?:^|\/)\.claude-plugin\/plugin\.json$/.exec(path)
    if (match) roots.add(match[1])
  }
  if (roots.size > 0) return [...roots].sort()
  const looksLikePlugin = [...tree.keys()].some(p =>
    /^(hooks\/hooks\.json|\.mcp\.json|skills\/|agents\/|commands\/)/.test(p),
  )
  return looksLikePlugin ? [''] : []
}

const within = (root: string, path: string) => (root === '' ? true : path.startsWith(`${root}/`))
const relative = (root: string, path: string) => (root === '' ? path : path.slice(root.length + 1))

function scanMcpServers(servers: unknown, file: string, findings: Finding[], caps: CapabilityHit[], components: Component[]) {
  if (!isRecord(servers)) return
  for (const [name, config] of Object.entries(servers)) {
    if (!isRecord(config)) continue
    components.push({ kind: 'mcp-server', name, file })
    const url = typeof config.url === 'string' ? config.url : undefined
    if (url) {
      const host = /^\w+:\/\/([^/:?#]+)/.exec(url)?.[1] ?? url
      caps.push({ kind: 'mcp.server', target: host })
      if (/^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(url)) {
        findings.push({
          rule: 'mcp.plain-http',
          severity: 'medium',
          title: `MCP server \`${name}\` over plain HTTP`,
          detail: 'Tool calls and results travel unencrypted to a remote host.',
          file,
          snippet: url,
        })
      }
      continue
    }
    const command = typeof config.command === 'string' ? config.command : undefined
    if (!command) continue
    const args = Array.isArray(config.args) ? config.args.filter((a): a is string => typeof a === 'string') : []
    caps.push({ kind: 'mcp.server', target: `${command} ${args.join(' ')}`.trim().slice(0, 80) })
    const line = `${command} ${args.join(' ')}`
    for (const finding of scanShellText(line, file)) findings.push({ ...finding, rule: `mcp.${finding.rule}` })
    if (/(^|\/)(npx|bunx|pnpx|uvx|pipx)$/.test(command) || (command === 'pnpm' && args[0] === 'dlx')) {
      const pkg = args.find(a => !a.startsWith('-') && a !== 'dlx' && a !== 'run')
      if (pkg && !/@[\w.^~<>=*-]*\d/.test(pkg.replace(/^@[^/]+\//, '')) && !/==\d/.test(pkg)) {
        findings.push({
          rule: 'mcp.unpinned-package',
          severity: 'medium',
          title: `MCP server \`${name}\` runs an unpinned package (\`${pkg}\`)`,
          detail: 'Every start fetches the latest version, so a later release (or a hijacked one) runs without review. Pin a version.',
          file,
          snippet: line,
        })
      }
    }
    if (/^(bash|sh|zsh|powershell|pwsh|cmd)$/.test(command.split('/').pop() ?? '')) {
      findings.push({
        rule: 'mcp.shell-server',
        severity: 'medium',
        title: `MCP server \`${name}\` starts through a shell`,
        detail: 'Its real command is in the arguments; review them.',
        file,
        snippet: line,
      })
    }
  }
}

function scanClassicHooks(hooks: unknown, file: string, findings: Finding[], caps: CapabilityHit[], components: Component[]) {
  if (!isRecord(hooks)) return
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue
    for (const entry of entries) {
      if (!isRecord(entry) || !Array.isArray(entry.hooks)) continue
      const matcher = typeof entry.matcher === 'string' ? entry.matcher : undefined
      for (const hook of entry.hooks) {
        if (!isRecord(hook) || typeof hook.command !== 'string') continue
        components.push({ kind: 'shell-hook', name: `${event}${matcher ? ` (${matcher})` : ''}`, file })
        caps.push({ kind: 'shell.hook', target: event })
        for (const finding of scanShellText(hook.command, file)) findings.push({ ...finding, rule: `hook.${finding.rule}` })
        if (SECRET_PATH.test(hook.command)) {
          findings.push({
            rule: 'hook.secret-path',
            severity: 'high',
            title: `\`${event}\` hook touches credential files`,
            detail: 'A shell hook command names a file where keys or tokens are stored.',
            file,
            snippet: hook.command.slice(0, 160),
          })
        }
        if (/\b(curl|wget|nc|ncat|Invoke-WebRequest)\b/i.test(hook.command)) {
          findings.push({
            rule: 'hook.network',
            severity: 'medium',
            title: `\`${event}\` hook makes network requests`,
            detail: 'A shell hook that runs on every matching event and talks to the network.',
            file,
            snippet: hook.command.slice(0, 160),
          })
        }
      }
    }
  }
}

function capabilitiesOf(hits: { hit: CapabilityHit; file: string }[]): Capability[] {
  const byKind = new Map<string, Capability>()
  for (const { hit, file } of hits) {
    const cap = byKind.get(hit.kind) ?? { kind: hit.kind, targets: [], files: [] }
    if (hit.target && !cap.targets.includes(hit.target)) cap.targets.push(hit.target)
    if (!cap.files.includes(file)) cap.files.push(file)
    byKind.set(hit.kind, cap)
  }
  return [...byKind.values()].sort((a, b) => a.kind.localeCompare(b.kind))
}

export function scoreFindings(findings: Finding[]): { score: number; verdict: Verdict } {
  const counted = new Map<string, number>()
  let score = 0
  for (const finding of findings) {
    // repeats of one rule add less each time, so one noisy rule cannot dominate
    const n = counted.get(finding.rule) ?? 0
    counted.set(finding.rule, n + 1)
    score += WEIGHT[finding.severity] / (n + 1)
  }
  score = Math.min(100, Math.round(score))
  const has = (severity: Severity) => findings.some(f => f.severity === severity)
  const verdict: Verdict = has('critical')
    ? 'malicious-indicators'
    : has('high') || score >= 40
      ? 'high-risk'
      : has('medium') || score >= 8
        ? 'review'
        : 'no-known-issues'
  return { score, verdict }
}

const sortFindings = (findings: Finding[]) =>
  findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0),
  )

export function scanPlugin(tree: FileTree, root: string): PluginReport {
  const paths = [...tree.keys()].filter(p => within(root, p))
  const findings: Finding[] = []
  const hits: { hit: CapabilityHit; file: string }[] = []
  const components: Component[] = []
  const at = (rel: string) => tree.get(root === '' ? rel : `${root}/${rel}`)

  const manifest = parseJson(at('.claude-plugin/plugin.json'))
  const meta = isRecord(manifest.value) ? manifest.value : {}
  const name = typeof meta.name === 'string' ? meta.name : root.split('/').pop() || '(unnamed plugin)'
  if (manifest.error) {
    findings.push({
      rule: 'manifest.invalid-json',
      severity: 'low',
      title: 'plugin.json does not parse',
      detail: manifest.error,
      file: '.claude-plugin/plugin.json',
    })
  }
  if (at('.claude-plugin/plugin.json')) components.push({ kind: 'manifest', name, file: '.claude-plugin/plugin.json' })

  // hooks.json: mod modules and classic shell hooks
  const modModules = new Set<string>()
  const hookFiles = new Set<string>(['hooks/hooks.json'])
  if (typeof meta.hooks === 'string') hookFiles.add(meta.hooks.replace(/^\.\//, ''))
  for (const hookFile of hookFiles) {
    const parsed = parseJson(at(hookFile))
    if (parsed.error) {
      findings.push({ rule: 'manifest.invalid-json', severity: 'low', title: `${hookFile} does not parse`, detail: parsed.error, file: hookFile })
    }
    const value = parsed.value
    if (!isRecord(value)) continue
    const dir = hookFile.includes('/') ? hookFile.slice(0, hookFile.lastIndexOf('/')) : ''
    if (Array.isArray(value.modules)) {
      for (const mod of value.modules) {
        if (typeof mod !== 'string') continue
        const resolved = normalize(dir ? `${dir}/${mod}` : mod)
        modModules.add(resolved)
        if (!at(resolved)) {
          findings.push({
            rule: 'manifest.missing-module',
            severity: 'low',
            title: `Mod module \`${mod}\` is listed but not shipped`,
            detail: 'The archive does not contain the module hooks.json names, so this scan cannot see the code that would run.',
            file: hookFile,
          })
        }
      }
    }
    const classic = isRecord(value.hooks) ? value.hooks : undefined
    const local: CapabilityHit[] = []
    scanClassicHooks(classic, hookFile, findings, local, components)
    for (const hit of local) hits.push({ hit, file: hookFile })
  }
  if (isRecord(meta.hooks)) {
    const local: CapabilityHit[] = []
    scanClassicHooks(isRecord(meta.hooks.hooks) ? meta.hooks.hooks : meta.hooks, '.claude-plugin/plugin.json', findings, local, components)
    for (const hit of local) hits.push({ hit, file: '.claude-plugin/plugin.json' })
  }

  // MCP servers
  const mcpLocal: CapabilityHit[] = []
  const mcpJson = parseJson(at('.mcp.json'))
  if (isRecord(mcpJson.value)) scanMcpServers(mcpJson.value.mcpServers ?? mcpJson.value, '.mcp.json', findings, mcpLocal, components)
  if (isRecord(meta.mcpServers)) scanMcpServers(meta.mcpServers, '.claude-plugin/plugin.json', findings, mcpLocal, components)
  for (const hit of mcpLocal) hits.push({ hit, file: '.mcp.json' })

  const imported = new Set<string>()

  for (const path of paths) {
    const rel = relative(root, path)
    const bytes = tree.get(path)!

    const binary = binaryKind(bytes)
    if (binary) {
      findings.push({
        rule: 'file.binary',
        severity: 'high',
        title: `Ships a compiled binary (${binary})`,
        detail: 'Compiled code cannot be reviewed from source; ask why the plugin needs it.',
        file: rel,
      })
      continue
    }
    if (bytes.length > MAX_TEXT_BYTES) {
      findings.push({ rule: 'file.too-large', severity: 'low', title: 'File too large to scan', detail: `${bytes.length} bytes`, file: rel })
      continue
    }

    if (SCRIPT_EXT.test(rel) && !rel.endsWith('.d.ts') && !/(^|\/)(node_modules)\//.test(rel)) {
      const isMod = modModules.has(rel)
      const analysis = analyzeModule(rel, text(bytes))
      if (isMod) components.push({ kind: 'mod', name: rel, file: rel })
      else if (analysis.hooks.length > 0 || analysis.apiCalls.length > 0) components.push({ kind: 'mod', name: `${rel} (helper)`, file: rel })
      findings.push(...analysis.findings)
      for (const hit of analysis.capabilities) hits.push({ hit, file: rel })
      if (!TEST_PATH.test(rel)) {
        const dir = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : ''
        for (const spec of analysis.imports) {
          if (!spec.startsWith('.')) continue
          const base = normalize(dir ? `${dir}/${spec}` : spec)
          for (const suffix of RESOLVE_SUFFIXES) imported.add(base + suffix)
        }
      }
      continue
    }

    if (SHELL_EXT.test(rel)) {
      const body = text(bytes)
      components.push({ kind: 'other', name: rel, file: rel })
      findings.push(...scanShellText(body, rel).map(f => ({ ...f, rule: `script.${f.rule}` })))
      if (/permissionDecision["']?\s*[:=]\s*["']allow|"decision"\s*:\s*"approve"/.test(body)) {
        findings.push({
          rule: 'hook.auto-approve',
          severity: 'high',
          title: 'Hook script approves tool calls itself',
          detail: 'The script answers permission checks with allow/approve, skipping the person’s prompt.',
          file: rel,
        })
      }
      if (SECRET_PATH.test(body)) {
        findings.push({
          rule: 'script.secret-path',
          severity: 'medium',
          title: 'Script references credential files',
          detail: 'A script shipped with the plugin names where keys or tokens are kept.',
          file: rel,
        })
      }
      continue
    }

    if (/\.md$/i.test(rel)) {
      const instruction =
        /^(skills|agents|commands)\//.test(rel) || /(^|\/)(CLAUDE|AGENTS)\.md$/.test(rel) || /(^|\/)SKILL\.md$/.test(rel)
      if (!instruction) continue
      const body = text(bytes)
      const kind = rel.startsWith('agents/') ? 'agent' : rel.startsWith('commands/') ? 'command' : 'skill'
      if (/SKILL\.md$/.test(rel) || kind !== 'skill') components.push({ kind, name: rel.replace(/\.md$/, ''), file: rel })
      hits.push({ hit: { kind: 'instructions', target: kind }, file: rel })
      findings.push(...scanInstructionText(body, rel))
      const allowed = /^allowed-tools:\s*(.+)$/m.exec(body)?.[1]
      if (allowed && /\bBash(\(\s*\*?\s*\))?(\s|,|$)|Bash\(\*\)/.test(allowed)) {
        findings.push({
          rule: 'instructions.broad-bash',
          severity: 'medium',
          title: 'Pre-approves any Bash command',
          detail: '`allowed-tools` grants unrestricted Bash while this runs, with no prompt.',
          file: rel,
          snippet: `allowed-tools: ${allowed}`,
        })
      }
      continue
    }

    if (/(^|\/)package\.json$/.test(rel)) {
      const pkg = parseJson(bytes).value
      const scripts = isRecord(pkg) && isRecord(pkg.scripts) ? pkg.scripts : {}
      for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
        const script = scripts[hook]
        if (typeof script !== 'string') continue
        findings.push({
          rule: 'package.install-script',
          severity: 'high',
          title: `\`${hook}\` script runs on install`,
          detail: 'Install scripts run before anyone has looked at the plugin.',
          file: rel,
          snippet: script.slice(0, 160),
        })
        findings.push(...scanShellText(script, rel).map(f => ({ ...f, rule: `package.${f.rule}` })))
      }
    }
  }

  // Test files do not run when the plugin is installed, unless real code imports them.
  for (const finding of findings) {
    if (!TEST_PATH.test(finding.file) || imported.has(finding.file)) continue
    if (SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf('low')) {
      finding.severity = 'low'
      finding.detail = `${finding.detail} (In a test file that nothing in the plugin imports.)`
    }
  }
  // A plugin for a service talks to that service: api.telegram.org in a Telegram plugin is expected.
  const nameTokens = name.toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length >= 4)
  for (const finding of findings) {
    if (finding.rule !== 'mod.suspicious-host') continue
    const host = /`([^`]+)`/.exec(finding.detail)?.[1] ?? ''
    if (nameTokens.some(token => host.includes(token))) {
      finding.severity = 'low'
      finding.title = `Talks to ${host}, the service this plugin is named for`
    }
  }

  sortFindings(dedupe(findings))
  const { score, verdict } = scoreFindings(findings)
  return {
    root,
    name,
    version: typeof meta.version === 'string' ? meta.version : undefined,
    description: typeof meta.description === 'string' ? meta.description : undefined,
    sha256: sha256(tree, paths),
    components,
    capabilities: capabilitiesOf(hits),
    findings,
    score,
    verdict,
  }
}

/** One problem reached by two rules (a literal and the argv it sits in) is reported once. */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>()
  let write = 0
  for (const finding of findings) {
    const key = `${finding.title}\0${finding.file}\0${finding.line ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    findings[write++] = finding
  }
  findings.length = write
  return findings
}

function normalize(path: string): string {
  const parts: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') parts.pop()
    else parts.push(part)
  }
  return parts.join('/')
}

const VERDICT_RANK: Verdict[] = ['malicious-indicators', 'high-risk', 'review', 'no-known-issues']

export function scanTree(tree: FileTree, source: string): ScanReport {
  const roots = findPluginRoots(tree)
  const plugins = roots.map(root => scanPlugin(tree, root))
  const findings: Finding[] = []

  if (roots.length === 0) {
    findings.push({
      rule: 'archive.no-plugin',
      severity: 'info',
      title: 'No Claude Code plugin found',
      detail: 'Nothing here has `.claude-plugin/plugin.json`, `hooks/hooks.json`, `.mcp.json`, skills, agents or commands.',
      file: '',
    })
  }
  const covered = (path: string) => roots.some(root => within(root, path))
  for (const [path, bytes] of tree) {
    if (covered(path)) continue
    const binary = binaryKind(bytes)
    if (binary) {
      findings.push({ rule: 'file.binary', severity: 'high', title: `Ships a compiled binary (${binary})`, detail: 'Outside any plugin folder.', file: path })
    }
  }

  const archive = scoreFindings(findings)
  const score = Math.max(archive.score, ...plugins.map(p => p.score))
  const verdict =
    VERDICT_RANK.find(v => archive.verdict === v || plugins.some(p => p.verdict === v)) ?? 'no-known-issues'

  return {
    scanner: SCANNER,
    scannedAt: new Date().toISOString(),
    source,
    sha256: sha256(tree, [...tree.keys()]),
    fileCount: tree.size,
    plugins,
    findings: sortFindings(findings),
    score,
    verdict,
  }
}
