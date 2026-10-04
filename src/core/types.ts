export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export type Finding = {
  rule: string
  severity: Severity
  title: string
  detail: string
  file: string
  line?: number
  snippet?: string
}

/** What a plugin can do, grouped the way a person reads a permission list. */
export type CapabilityKind =
  | 'fs.read'
  | 'fs.write'
  | 'network'
  | 'process'
  | 'env.read'
  | 'env.write'
  | 'settings.read'
  | 'session.read'
  | 'prompt.modify'
  | 'tool.intercept'
  | 'permission.decide'
  | 'ui'
  | 'store'
  | 'timer'
  | 'model'
  | 'agent'
  | 'tool.register'
  | 'command'
  | 'shell.hook'
  | 'mcp.server'
  | 'instructions'

export type Capability = {
  kind: CapabilityKind
  /** Literal targets seen in the source: hosts, argv[0], env names, events, tools. */
  targets: string[]
  files: string[]
}

export type ComponentKind = 'mod' | 'shell-hook' | 'mcp-server' | 'skill' | 'agent' | 'command' | 'manifest' | 'other'

export type Component = {
  kind: ComponentKind
  name: string
  file: string
}

export type Verdict = 'malicious-indicators' | 'high-risk' | 'review' | 'no-known-issues'

export type PluginReport = {
  root: string
  name: string
  version?: string
  description?: string
  sha256: string
  components: Component[]
  capabilities: Capability[]
  findings: Finding[]
  score: number
  verdict: Verdict
}

export type ScanReport = {
  scanner: { name: string; version: string }
  scannedAt: string
  source: string
  sha256: string
  fileCount: number
  plugins: PluginReport[]
  /** Findings that belong to the archive rather than any one plugin. */
  findings: Finding[]
  score: number
  verdict: Verdict
}

/** A plugin's files, in memory: path relative to the scan root → bytes. */
export type FileTree = Map<string, Uint8Array>
