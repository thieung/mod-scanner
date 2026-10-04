import type { ScanReport, Verdict } from './core/types.ts'

export const VERDICT_LABEL: Record<Verdict, string> = {
  'malicious-indicators': 'Malicious indicators',
  'high-risk': 'High risk',
  review: 'Review recommended',
  'no-known-issues': 'No known issues found',
}

const COLOR = process.stdout.isTTY
  ? { critical: '\x1b[41;97m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[90m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' }
  : { critical: '', high: '', medium: '', low: '', info: '', dim: '', bold: '', reset: '' }

export function formatText(report: ScanReport): string {
  const out: string[] = []
  const c = COLOR
  out.push(`${c.bold}${VERDICT_LABEL[report.verdict]}${c.reset}  score ${report.score}/100  ${c.dim}${report.fileCount} files · sha256 ${report.sha256.slice(0, 16)}…${c.reset}`)
  for (const finding of report.findings) out.push(`  ${finding.severity.toUpperCase()} ${finding.title}`)
  for (const plugin of report.plugins) {
    out.push('')
    out.push(`${c.bold}${plugin.name}${plugin.version ? `@${plugin.version}` : ''}${c.reset}  ${VERDICT_LABEL[plugin.verdict]} (${plugin.score})  ${c.dim}${plugin.root || '.'}${c.reset}`)
    if (plugin.components.length > 0) {
      out.push(`  ${c.dim}components:${c.reset} ${plugin.components.map(x => `${x.kind}:${x.name}`).join(', ')}`)
    }
    if (plugin.capabilities.length > 0) {
      out.push(`  ${c.dim}capabilities:${c.reset}`)
      for (const cap of plugin.capabilities) {
        out.push(`    ${cap.kind.padEnd(18)} ${cap.targets.slice(0, 6).join(', ')}${cap.targets.length > 6 ? ', …' : ''}`)
      }
    }
    if (plugin.findings.length === 0) out.push(`  ${c.dim}no findings${c.reset}`)
    for (const f of plugin.findings) {
      const where = `${f.file}${f.line ? `:${f.line}` : ''}`
      out.push(`  ${c[f.severity]}${f.severity.toUpperCase().padEnd(8)}${c.reset} ${f.title}  ${c.dim}${where} [${f.rule}]${c.reset}`)
      if (f.snippet) out.push(`           ${c.dim}${f.snippet}${c.reset}`)
    }
  }
  out.push('')
  out.push(`${c.dim}Static analysis only: nothing was executed. "No known issues" is not a guarantee of safety.${c.reset}`)
  return out.join('\n')
}
