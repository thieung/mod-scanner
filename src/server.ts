import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join } from 'node:path'
import { SCANNER, scanTree } from './core/scan.ts'
import { fetchGitHub, parseGitHubUrl } from './sources/github.ts'
import { LIMITS, LimitError } from './sources/limits.ts'
import { readZip } from './sources/zip.ts'

const PUBLIC = join(import.meta.dirname, '..', 'public')
const PORT = Number(process.env.PORT ?? 8787)
const HOST = process.env.HOST ?? '127.0.0.1'

const STATIC: Record<string, string> = {
  '/': 'index.html',
  '/scan': 'scan.html',
  '/app.js': 'app.js',
  '/style.css': 'style.css',
}
const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
}

const SECURITY_HEADERS = {
  'content-security-policy':
    "default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
}

/** A fixed window per client address; enough to stop one client hogging the scanner. */
const RATE = { windowMs: 60_000, max: Number(process.env.RATE_LIMIT ?? 20) }
const hits = new Map<string, { start: number; count: number }>()

function limited(req: IncomingMessage): boolean {
  const key = req.socket.remoteAddress ?? 'unknown'
  const now = Date.now()
  const entry = hits.get(key)
  if (!entry || now - entry.start > RATE.windowMs) {
    hits.set(key, { start: now, count: 1 })
    if (hits.size > 10_000) for (const [k, v] of hits) if (now - v.start > RATE.windowMs) hits.delete(k)
    return false
  }
  entry.count++
  return entry.count > RATE.max
}

/** The landing page carries its styles inline and shows no scan data, so it may allow inline styles. */
const LANDING_HEADERS = {
  ...SECURITY_HEADERS,
  'content-security-policy': SECURITY_HEADERS['content-security-policy'].replace("style-src 'self'", "style-src 'self' 'unsafe-inline'"),
}

function send(
  res: ServerResponse,
  status: number,
  body: string | Uint8Array,
  type = 'application/json; charset=utf-8',
  headers: Record<string, string> = SECURITY_HEADERS,
) {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', ...headers })
  res.end(body)
}

const json = (res: ServerResponse, status: number, value: unknown) => send(res, status, JSON.stringify(value))

async function readBody(req: IncomingMessage, max: number): Promise<Uint8Array> {
  const declared = Number(req.headers['content-length'] ?? 0)
  if (declared > max) throw new LimitError(`Upload is over ${max / 1024 / 1024} MB`)
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    size += (chunk as Buffer).length
    if (size > max) throw new LimitError(`Upload is over ${max / 1024 / 1024} MB`)
    chunks.push(chunk as Buffer)
  }
  return new Uint8Array(Buffer.concat(chunks))
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', 'http://localhost')

  if (req.method === 'GET' && url.pathname in STATIC) {
    const file = STATIC[url.pathname]
    send(res, 200, await readFile(join(PUBLIC, file)), TYPES[extname(file)], file === 'index.html' ? LANDING_HEADERS : SECURITY_HEADERS)
    return
  }
  if (req.method === 'GET' && url.pathname === '/healthz') {
    json(res, 200, { ok: true, ...SCANNER })
    return
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/scan/')) {
    if (limited(req)) {
      json(res, 429, { error: 'Too many scans from this address; try again in a minute.' })
      return
    }
    try {
      if (url.pathname === '/api/scan/upload') {
        const name = (url.searchParams.get('name') ?? 'upload.zip').slice(0, 200)
        const tree = readZip(await readBody(req, LIMITS.uploadBytes))
        json(res, 200, scanTree(tree, name))
        return
      }
      if (url.pathname === '/api/scan/github') {
        const body = JSON.parse(new TextDecoder().decode(await readBody(req, 4096))) as { url?: unknown }
        if (typeof body.url !== 'string') throw new LimitError('Send { "url": "https://github.com/owner/repo" }')
        const target = parseGitHubUrl(body.url)
        const tree = await fetchGitHub(target)
        const source = `github.com/${target.owner}/${target.repo}${target.ref ? `@${target.ref}` : ''}${target.subdir ? `/${target.subdir}` : ''}`
        json(res, 200, scanTree(tree, source))
        return
      }
    } catch (error) {
      if (error instanceof LimitError || error instanceof SyntaxError) {
        json(res, 400, { error: error.message })
        return
      }
      if ((error as Error).name === 'TimeoutError') {
        json(res, 504, { error: 'GitHub did not answer in time' })
        return
      }
      throw error
    }
  }

  json(res, 404, { error: 'Not found' })
}

const server = createServer((req, res) => {
  handle(req, res).catch(error => {
    console.error(error)
    if (!res.headersSent) json(res, 500, { error: 'Scan failed' })
    else res.end()
  })
})
server.requestTimeout = 60_000
server.headersTimeout = 15_000

server.listen(PORT, HOST, () => {
  console.log(`${SCANNER.name} ${SCANNER.version} on http://${HOST}:${PORT}`)
})
