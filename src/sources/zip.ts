import { unzipSync } from 'fflate'
import type { FileTree } from '../core/types.ts'
import { LIMITS, LimitError, cleanPath } from './limits.ts'

/**
 * Reads a zip into memory. Sizes are checked from the central directory before
 * anything is inflated, which stops zip bombs before they expand.
 */
export function readZip(bytes: Uint8Array, maxBytes = LIMITS.uploadBytes): FileTree {
  if (bytes.length > maxBytes) throw new LimitError(`Archive is over ${maxBytes / 1024 / 1024} MB`)
  let total = 0
  let count = 0
  let entries: Record<string, Uint8Array>
  try {
    entries = unzipSync(bytes, {
      filter: file => {
        if (!cleanPath(file.name)) return false
        if (file.originalSize > LIMITS.fileBytes) return false
        count++
        total += file.originalSize
        if (count > LIMITS.files) throw new LimitError(`Archive has more than ${LIMITS.files} files`)
        if (total > LIMITS.totalBytes) throw new LimitError(`Archive expands past ${LIMITS.totalBytes / 1024 / 1024} MB`)
        return true
      },
    })
  } catch (error) {
    if (error instanceof LimitError) throw error
    throw new LimitError(`Not a readable zip archive: ${(error as Error).message}`)
  }

  const tree: FileTree = new Map()
  for (const [name, data] of Object.entries(entries)) {
    const path = cleanPath(name)
    if (path) tree.set(path, data)
  }
  return stripCommonPrefix(tree)
}

/** GitHub archives and most zips wrap everything in one top folder. */
export function stripCommonPrefix(tree: FileTree): FileTree {
  const firsts = new Set([...tree.keys()].map(p => (p.includes('/') ? p.slice(0, p.indexOf('/')) : '')))
  if (firsts.size !== 1 || firsts.has('')) return tree
  const [prefix] = firsts
  if (prefix === '.claude-plugin') return tree
  const stripped: FileTree = new Map()
  for (const [path, data] of tree) stripped.set(path.slice(prefix.length + 1), data)
  return stripCommonPrefix(stripped)
}
