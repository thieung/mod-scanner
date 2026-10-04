/** Response headers shared by the Node server and the Cloudflare Worker. */

const CSP = [
  "default-src 'none'",
  // Cloudflare Turnstile guards the GitHub proxy on the hosted Worker.
  "script-src 'self' https://challenges.cloudflare.com",
  'frame-src https://challenges.cloudflare.com',
  "worker-src 'self'",
  "style-src 'self' https://fonts.googleapis.com",
  'font-src https://fonts.gstatic.com',
  "connect-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ')

export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
}

/** The landing page carries its styles inline and shows no scan data, so it may allow inline styles. */
export const LANDING_HEADERS: Record<string, string> = {
  ...SECURITY_HEADERS,
  'content-security-policy': CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'"),
}

export function headersFor(pathname: string): Record<string, string> {
  return pathname === '/' || pathname === '/index.html' ? LANDING_HEADERS : SECURITY_HEADERS
}
