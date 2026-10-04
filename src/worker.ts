import { githubProxy } from './github-proxy.ts'
import { SECURITY_HEADERS, headersFor } from './http-headers.ts'
import { verifyTurnstile } from './turnstile.ts'

/**
 * Cloudflare Worker: serves the pages from static assets and proxies GitHub
 * archives. Scanning itself runs in the visitor's browser (public/scan-worker.js),
 * so no plugin code or upload ever reaches this Worker.
 */

type RateLimiter = { limit(options: { key: string }): Promise<{ success: boolean }> }

type Env = {
  ASSETS: { fetch(request: Request): Promise<Response> }
  /** Per-IP limit on /api/github, from `ratelimits` in wrangler.jsonc. */
  GITHUB_LIMITER?: RateLimiter
  /** Public site key, handed to the browser through /api/config. */
  TURNSTILE_SITE_KEY?: string
  /** When set, every /api/github call needs a valid Turnstile token. */
  TURNSTILE_SECRET_KEY?: string
}

function withHeaders(response: Response, headers: Record<string, string>): Response {
  const out = new Response(response.body, response)
  for (const [name, value] of Object.entries(headers)) out.headers.set(name, value)
  return out
}

const json = (status: number, value: unknown) =>
  withHeaders(
    new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }),
    SECURITY_HEADERS,
  )

/** The GitHub proxy is the only endpoint that costs anything, so only it is limited. */
async function refuseGitHub(request: Request, env: Env): Promise<Response | undefined> {
  const ip = request.headers.get('cf-connecting-ip')
  if (env.GITHUB_LIMITER && !(await env.GITHUB_LIMITER.limit({ key: ip ?? 'unknown' })).success) {
    return json(429, { error: 'Too many scans from this address; try again in a minute.' })
  }
  if (env.TURNSTILE_SECRET_KEY && !(await verifyTurnstile(request.headers.get('x-turnstile-token'), env.TURNSTILE_SECRET_KEY, ip))) {
    return json(403, { error: 'The browser check failed; reload the page and try again.' })
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname === '/api/config') return json(200, { turnstileSiteKey: env.TURNSTILE_SITE_KEY || null })
    if (url.pathname === '/api/github') {
      if (request.method !== 'GET') return new Response(null, { status: 405, headers: { allow: 'GET' } })
      return (await refuseGitHub(request, env)) ?? withHeaders(await githubProxy(url), SECURITY_HEADERS)
    }
    if (url.pathname.startsWith('/api/')) return json(404, { error: 'Not found' })
    return withHeaders(await env.ASSETS.fetch(request), headersFor(url.pathname))
  },
}
