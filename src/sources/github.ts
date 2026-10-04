import type { FileTree } from '../core/types.ts'
import { LIMITS, LimitError } from './limits.ts'
import { readZip } from './zip.ts'

export type GitHubTarget = { owner: string; repo: string; ref?: string; subdir?: string }

const NAME = /^[A-Za-z0-9_.-]{1,100}$/

/** Accepts `owner/repo`, or a github.com URL with an optional `/tree/<ref>/<path>`. */
export function parseGitHubUrl(input: string): GitHubTarget {
  const trimmed = input.trim().replace(/\.git$/, '').replace(/\/+$/, '')
  let path: string
  if (/^[\w.-]+\/[\w.-]+$/.test(trimmed)) {
    path = trimmed
  } else {
    let url: URL
    try {
      url = new URL(trimmed)
    } catch {
      throw new LimitError('Enter a GitHub URL like https://github.com/owner/repo')
    }
    if (url.protocol !== 'https:' || url.hostname !== 'github.com') throw new LimitError('Only https://github.com URLs are supported')
    path = url.pathname.replace(/^\//, '')
  }
  const [owner, repo, kind, ref, ...rest] = path.split('/')
  if (!owner || !repo || !NAME.test(owner) || !NAME.test(repo)) throw new LimitError('Could not read owner/repo from the URL')
  if (kind !== undefined && kind !== 'tree') throw new LimitError('Link to the repository or a /tree/<ref>/<folder> path')
  if (ref !== undefined && !/^[\w./-]{1,200}$/.test(ref)) throw new LimitError('Unsupported ref')
  const subdir = rest.length > 0 ? rest.join('/') : undefined
  return { owner, repo, ref, subdir }
}

/**
 * Downloads the repository archive from codeload.github.com. Only that host is
 * ever contacted, so the URL a person types cannot point the server elsewhere.
 */
export async function fetchGitHub(target: GitHubTarget, fetchImpl: typeof fetch = fetch): Promise<FileTree> {
  const ref = target.ref ?? 'HEAD'
  const url = `https://codeload.github.com/${target.owner}/${target.repo}/zip/${ref === 'HEAD' ? 'HEAD' : `refs/heads/${ref}`}`
  let response = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(20_000) })
  if (response.status === 404 && ref !== 'HEAD') {
    // a tag or commit rather than a branch
    response = await fetchImpl(`https://codeload.github.com/${target.owner}/${target.repo}/zip/${ref}`, {
      redirect: 'error',
      signal: AbortSignal.timeout(20_000),
    })
  }
  if (response.status === 404) throw new LimitError('Repository not found or not public')
  if (!response.ok) throw new LimitError(`GitHub returned ${response.status}`)
  const declared = Number(response.headers.get('content-length') ?? 0)
  if (declared > LIMITS.downloadBytes) throw new LimitError('Repository archive is too large')

  const reader = response.body!.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.length
    if (size > LIMITS.downloadBytes) {
      await reader.cancel()
      throw new LimitError('Repository archive is too large')
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }

  const tree = readZip(bytes, LIMITS.downloadBytes)
  if (!target.subdir) return tree
  const prefix = `${target.subdir.replace(/^\/+|\/+$/g, '')}/`
  const sub: FileTree = new Map()
  for (const [path, data] of tree) if (path.startsWith(prefix)) sub.set(path.slice(prefix.length), data)
  if (sub.size === 0) throw new LimitError(`No files under ${target.subdir}`)
  return sub
}
