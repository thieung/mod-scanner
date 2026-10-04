import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { zipSync } from 'fflate'
import { githubProxy } from '../src/github-proxy.ts'
import worker from '../src/worker.ts'

const zip = zipSync({ 'repo-main/plugins/x/.claude-plugin/plugin.json': new TextEncoder().encode('{"name":"x"}') })

function fakeFetch(calls: string[], status = 200): typeof fetch {
  return (async (input: string | URL | Request) => {
    calls.push(String(input))
    return new Response(status === 200 ? zip : 'nope', { status })
  }) as typeof fetch
}

describe('github proxy', () => {
  test('downloads only from codeload and passes the folder along', async () => {
    const calls: string[] = []
    const res = await githubProxy(new URL('https://scan.test/api/github?url=https://github.com/acme/mods/tree/main/plugins/x'), fakeFetch(calls))
    assert.equal(res.status, 200)
    assert.deepEqual(calls, ['https://codeload.github.com/acme/mods/zip/refs/heads/main'])
    assert.equal(decodeURIComponent(res.headers.get('x-scan-subdir')!), 'plugins/x')
    assert.equal(decodeURIComponent(res.headers.get('x-scan-source')!), 'github.com/acme/mods@main/plugins/x')
    assert.equal((await res.arrayBuffer()).byteLength, zip.byteLength)
  })

  test('refuses other hosts without fetching', async () => {
    const calls: string[] = []
    const res = await githubProxy(new URL('https://scan.test/api/github?url=https://evil.example/a/b'), fakeFetch(calls))
    assert.equal(res.status, 400)
    assert.deepEqual(calls, [])
  })

  test('does not follow a redirect away from codeload', async () => {
    const calls: string[] = []
    const redirecting = (async (input: string | URL | Request, init?: RequestInit) => {
      calls.push(String(input))
      assert.equal(init?.redirect, 'manual')
      return new Response(null, { status: 302, headers: { location: 'https://evil.example/x.zip' } })
    }) as typeof fetch
    const res = await githubProxy(new URL('https://scan.test/api/github?url=acme/mods'), redirecting)
    assert.equal(res.status, 400)
    assert.deepEqual(calls, ['https://codeload.github.com/acme/mods/zip/HEAD'])
  })

  test('reports a missing repository', async () => {
    const res = await githubProxy(new URL('https://scan.test/api/github?url=acme/missing'), fakeFetch([], 404))
    assert.equal(res.status, 400)
    assert.match((await res.json()).error, /not found/)
  })
})

describe('cloudflare worker', () => {
  const env = { ASSETS: { fetch: async (req: Request) => new Response(`asset ${new URL(req.url).pathname}`) } }

  test('serves assets with security headers', async () => {
    const landing = await worker.fetch(new Request('https://scan.test/'), env)
    assert.match(landing.headers.get('content-security-policy')!, /style-src 'self' 'unsafe-inline'/)
    const scan = await worker.fetch(new Request('https://scan.test/scan'), env)
    assert.equal(await scan.text(), 'asset /scan')
    assert.doesNotMatch(scan.headers.get('content-security-policy')!, /unsafe-inline/)
    assert.equal(scan.headers.get('x-content-type-options'), 'nosniff')
  })

  test('unknown API paths and non-GET proxy calls are refused', async () => {
    assert.equal((await worker.fetch(new Request('https://scan.test/api/scan/upload', { method: 'POST' }), env)).status, 404)
    assert.equal((await worker.fetch(new Request('https://scan.test/api/github?url=a/b', { method: 'POST' }), env)).status, 405)
  })
})

describe('github proxy guard', () => {
  const assets = { fetch: async () => new Response('asset') }
  const request = () =>
    new Request('https://scan.test/api/github?url=acme/mods', { headers: { 'cf-connecting-ip': '203.0.113.7', 'x-turnstile-token': 'tok' } })

  /** Stubs global fetch: siteverify answers `verified`, codeload returns the zip. */
  async function withFetch(verified: boolean, body: () => Promise<void>) {
    const calls: { url: string; body?: string }[] = []
    const original = globalThis.fetch
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      calls.push({ url, body: init?.body ? String(init.body) : undefined })
      if (url.includes('siteverify')) return Response.json({ success: verified })
      return new Response(zip)
    }) as typeof fetch
    try {
      await body()
    } finally {
      globalThis.fetch = original
    }
    return calls
  }

  test('hands the site key to the browser only when configured', async () => {
    const off = await worker.fetch(new Request('https://scan.test/api/config'), { ASSETS: assets })
    assert.deepEqual(await off.json(), { turnstileSiteKey: null })
    const on = await worker.fetch(new Request('https://scan.test/api/config'), { ASSETS: assets, TURNSTILE_SITE_KEY: 'site-key' })
    assert.deepEqual(await on.json(), { turnstileSiteKey: 'site-key' })
  })

  test('refuses an address over the limit before contacting anyone', async () => {
    const keys: string[] = []
    const GITHUB_LIMITER = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: false }) }
    const calls = await withFetch(true, async () => {
      const res = await worker.fetch(request(), { ASSETS: assets, GITHUB_LIMITER, TURNSTILE_SECRET_KEY: 'secret' })
      assert.equal(res.status, 429)
    })
    assert.deepEqual(keys, ['203.0.113.7'])
    assert.deepEqual(calls, [])
  })

  test('refuses a missing or rejected Turnstile token without downloading', async () => {
    const calls = await withFetch(false, async () => {
      const missing = new Request('https://scan.test/api/github?url=acme/mods')
      assert.equal((await worker.fetch(missing, { ASSETS: assets, TURNSTILE_SECRET_KEY: 'secret' })).status, 403)
      assert.equal((await worker.fetch(request(), { ASSETS: assets, TURNSTILE_SECRET_KEY: 'secret' })).status, 403)
    })
    assert.deepEqual(calls.map(c => new URL(c.url).hostname), ['challenges.cloudflare.com'])
  })

  test('downloads once the token checks out', async () => {
    const calls = await withFetch(true, async () => {
      const res = await worker.fetch(request(), { ASSETS: assets, TURNSTILE_SECRET_KEY: 'secret' })
      assert.equal(res.status, 200)
      assert.equal((await res.arrayBuffer()).byteLength, zip.byteLength)
    })
    const verify = new URLSearchParams(calls[0].body)
    assert.equal(verify.get('response'), 'tok')
    assert.equal(verify.get('remoteip'), '203.0.113.7')
    assert.equal(new URL(calls[1].url).hostname, 'codeload.github.com')
  })
})
