import { scanTree } from '../core/scan.ts'
import { selectSubdir } from '../sources/github.ts'
import { LIMITS, LimitError } from '../sources/limits.ts'
import { readZip } from '../sources/zip.ts'

/**
 * Runs in a Web Worker in the visitor's browser. Receives a zip, scans it and
 * posts the report back; uploads never leave the browser.
 */

type Request = { id: number; bytes: ArrayBuffer; source: string; subdir?: string; fromGitHub?: boolean }
type Scope = { onmessage: ((event: { data: Request }) => void) | null; postMessage(message: unknown): void }

const scope = globalThis as unknown as Scope

scope.onmessage = ({ data }) => {
  try {
    const tree = readZip(new Uint8Array(data.bytes), data.fromGitHub ? LIMITS.downloadBytes : LIMITS.uploadBytes)
    scope.postMessage({ id: data.id, report: scanTree(selectSubdir(tree, data.subdir), data.source) })
  } catch (error) {
    const message = error instanceof LimitError ? error.message : `Scan failed: ${(error as Error).message}`
    scope.postMessage({ id: data.id, error: message })
  }
}
