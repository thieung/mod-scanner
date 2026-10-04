#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises'
import { scanTree } from './core/scan.ts'
import type { FileTree, Severity } from './core/types.ts'
import { formatText } from './format.ts'
import { readDirectory } from './sources/dir.ts'
import { fetchGitHub, parseGitHubUrl } from './sources/github.ts'
import { readZip } from './sources/zip.ts'

const USAGE = `Usage: mod-scanner <plugin-dir | plugin.zip | github-url> [--json] [--fail-on <severity>]

  --json               print the report as JSON
  --fail-on <level>    exit 1 when a finding is at least this severe
                       (critical, high, medium, low); default: high`

const RANK: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

async function load(target: string): Promise<FileTree> {
  if (/^https?:\/\//.test(target) || /^[\w.-]+\/[\w.-]+$/.test(target) && !(await exists(target))) {
    return fetchGitHub(parseGitHubUrl(target))
  }
  const info = await stat(target)
  if (info.isDirectory()) return readDirectory(target)
  return readZip(new Uint8Array(await readFile(target)))
}

async function exists(path: string) {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

async function main(argv: string[]) {
  const args = [...argv]
  const json = args.includes('--json')
  const failIndex = args.indexOf('--fail-on')
  const failOn = (failIndex >= 0 ? args[failIndex + 1] : 'high') as Severity
  const target = args.find((a, i) => !a.startsWith('--') && (failIndex < 0 || i !== failIndex + 1))
  if (!target || args.includes('--help') || !RANK.includes(failOn)) {
    console.error(USAGE)
    process.exit(2)
  }
  const report = scanTree(await load(target), target)
  console.log(json ? JSON.stringify(report, null, 2) : formatText(report))
  const threshold = RANK.indexOf(failOn)
  const all = [...report.findings, ...report.plugins.flatMap(p => p.findings)]
  process.exit(all.some(f => RANK.indexOf(f.severity) <= threshold) ? 1 : 0)
}

main(process.argv.slice(2)).catch(error => {
  console.error(`mod-scanner: ${(error as Error).message}`)
  process.exit(2)
})
