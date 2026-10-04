import { describeTarget, downloadGitHubZip, parseGitHubUrl } from './sources/github.ts'
import { LimitError } from './sources/limits.ts'

/**
 * GET /api/github?url=… : downloads a public repository's archive and hands the
 * zip to the browser, which does the scanning. Browsers cannot fetch codeload
 * themselves (no CORS headers), so this is the only server-side step.
 */
export async function githubProxy(url: URL, fetchImpl: typeof fetch = fetch): Promise<Response> {
  const json = (status: number, error: string) =>
    new Response(JSON.stringify({ error }), { status, headers: { 'content-type': 'application/json; charset=utf-8' } })
  const input = url.searchParams.get('url')
  if (!input) return json(400, 'Add ?url=https://github.com/owner/repo')
  try {
    const target = parseGitHubUrl(input)
    const bytes = await downloadGitHubZip(target, fetchImpl)
    return new Response(bytes, {
      headers: {
        'content-type': 'application/zip',
        'cache-control': 'public, max-age=300',
        'x-scan-source': encodeURIComponent(describeTarget(target)),
        'x-scan-subdir': encodeURIComponent(target.subdir ?? ''),
      },
    })
  } catch (error) {
    if (error instanceof LimitError) return json(400, error.message)
    if ((error as Error).name === 'TimeoutError') return json(504, 'GitHub did not answer in time')
    return json(502, 'Could not download the repository from GitHub')
  }
}
