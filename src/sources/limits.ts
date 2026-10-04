/** Bounds on what one scan accepts, so an archive cannot exhaust the server. */
export const LIMITS = {
  uploadBytes: 10 * 1024 * 1024,
  /** GitHub archives hold the whole repository even when one folder is scanned. */
  downloadBytes: 40 * 1024 * 1024,
  totalBytes: 150 * 1024 * 1024,
  fileBytes: 5 * 1024 * 1024,
  files: 20000,
}

export class LimitError extends Error {}

const SKIP_DIR = /(^|\/)(\.git|node_modules|__MACOSX)(\/|$)/

/** Paths are only ever map keys, never written to disk; this keeps them tidy. */
export function cleanPath(path: string): string | undefined {
  const normalized = path.replace(/\\/g, '/').replace(/^\/+/, '')
  if (normalized === '' || normalized.endsWith('/')) return undefined
  if (normalized.split('/').some(part => part === '..')) return undefined
  if (SKIP_DIR.test(normalized)) return undefined
  return normalized
}
