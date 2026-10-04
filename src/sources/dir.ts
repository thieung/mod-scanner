import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type { FileTree } from '../core/types.ts'
import { LIMITS, LimitError, cleanPath } from './limits.ts'

export async function readDirectory(dir: string): Promise<FileTree> {
  const tree: FileTree = new Map()
  let total = 0
  const walk = async (current: string) => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      const path = cleanPath(relative(dir, full))
      if (entry.isDirectory()) {
        if (cleanPath(`${relative(dir, full)}/x`)) await walk(full)
        continue
      }
      if (!entry.isFile() || !path) continue
      const { size } = await stat(full)
      if (size > LIMITS.fileBytes) continue
      total += size
      if (tree.size >= LIMITS.files || total > LIMITS.totalBytes) throw new LimitError('Directory is too large to scan')
      tree.set(path, new Uint8Array(await readFile(full)))
    }
  }
  await walk(dir)
  return tree
}
