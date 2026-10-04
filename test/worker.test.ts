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
