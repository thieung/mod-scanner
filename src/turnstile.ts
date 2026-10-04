const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

/**
 * Checks a Cloudflare Turnstile token. Tokens are single-use and expire after
 * five minutes, so the browser fetches a fresh one for every GitHub scan.
 */
export async function verifyTurnstile(
  token: string | null,
  secret: string,
  ip: string | null,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  if (!token || token.length > 2048) return false
  const body = new URLSearchParams({ secret, response: token })
  if (ip) body.set('remoteip', ip)
  try {
    const response = await fetchImpl(SITEVERIFY, { method: 'POST', body, signal: AbortSignal.timeout(10_000) })
    if (!response.ok) return false
    const result = (await response.json()) as { success?: unknown }
    return result.success === true
  } catch {
    return false
  }
}
