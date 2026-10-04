import { githubProxy } from './github-proxy.ts'
import { SECURITY_HEADERS, headersFor } from './http-headers.ts'

/**
 * Cloudflare Worker: serves the pages from static assets and proxies GitHub
 * archives. Scanning itself runs in the visitor's browser (public/scan-worker.js),
 * so no plugin code or upload ever reaches this Worker.
 */

type Env = { ASSETS: { fetch(request: Request): Promise<Response> } }

function withHeaders(response: Response, headers: Record<string, string>): Response {
  const out = new Response(response.body, response)
  for (const [name, value] of Object.entries(headers)) out.headers.set(name, value)
  return out
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname === '/api/github') {
      if (request.method !== 'GET') return new Response(null, { status: 405, headers: { allow: 'GET' } })
      return withHeaders(await githubProxy(url), SECURITY_HEADERS)
    }
    if (url.pathname.startsWith('/api/')) {
      return withHeaders(
        new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'content-type': 'application/json' } }),
        SECURITY_HEADERS,
      )
    }
    return withHeaders(await env.ASSETS.fetch(request), headersFor(url.pathname))
  },
}
