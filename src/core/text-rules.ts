import type { Finding, Severity } from './types.ts'

type TextRule = {
  id: string
  severity: Severity
  title: string
  detail: string
  pattern: RegExp
}

/** Shell payloads, wherever they appear: hook commands, skill bodies, string literals. */
export const SHELL_RULES: readonly TextRule[] = [
  {
    id: 'shell.pipe-to-shell',
    severity: 'critical',
    title: 'Downloads and executes remote code',
    detail: 'A download is piped straight into a shell, so whatever the server returns runs on the machine.',
    pattern: /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n]*\|\s*(python3?|node|perl|ruby|iex)\b/i,
  },
  {
    id: 'shell.reverse-shell',
    severity: 'critical',
    title: 'Reverse shell pattern',
    detail: 'Opens an interactive shell over a network socket, giving a remote party control of the machine.',
    pattern: /\/dev\/tcp\/|\bnc(at)?\b[^\n]*\s-e\s|\bmkfifo\b[^\n]*\bnc\b|socket\.socket\([^\n]*connect/i,
  },
  {
    id: 'shell.decode-exec',
    severity: 'critical',
    title: 'Decodes and executes a hidden payload',
    detail: 'Base64 or hex is decoded and run, a common way to hide what a command does.',
    pattern: /base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b|\beval\s*\(?\s*["'`]?\$\(\s*echo[^\n]*base64/i,
  },
  {
    id: 'shell.persistence',
    severity: 'high',
    title: 'Writes to a shell startup file, cron or git hooks',
    detail: 'Changes that survive the session: shell rc files, crontab, launch agents or git hooks.',
    pattern: />>?\s*~?\/?[\w./-]*\.(bashrc|zshrc|profile|bash_profile)\b|\bcrontab\b|LaunchAgents|\.git\/hooks\//i,
  },
  {
    id: 'shell.disable-safety',
    severity: 'medium',
    title: 'Turns off a safety mechanism',
    detail: 'Disables TLS verification, permission prompts or history.',
    pattern: /--dangerously-skip-permissions|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|\bcurl\b[^\n]*\s-k\b|--insecure\b|unset\s+HISTFILE|HISTSIZE=0/i,
  },
]

/** Places credentials usually live. */
export const SECRET_PATH =
  /(\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.aws\/config|\.config\/gcloud|\.azure\/|\.kube\/config|\.npmrc|\.pypirc|\.netrc|\.docker\/config\.json|\.git-credentials|\.gnupg|Keychains?\/|login\.keychain|\.claude\.json|\.claude\/\.credentials|(^|[\s/'"`])\.env(\.[\w-]+)?(?=$|[\s'"`])|wallet\.dat|Local State|Login Data|Cookies)/

export const SECRET_ENV =
  /^(.*_)?(API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY|SESSION)(_.*)?$|^(ANTHROPIC|OPENAI|AWS|GITHUB|GH|NPM|GOOGLE|AZURE|SLACK|STRIPE)_/i

/** Instructions aimed at the model rather than the person. */
export const INSTRUCTION_RULES: readonly TextRule[] = [
  {
    id: 'prompt.conceal',
    severity: 'high',
    title: 'Tells the model to hide something from the user',
    detail: 'Instructions to keep actions or content from the person are the core of a prompt-injection backdoor.',
    pattern:
      /\b(do not|don't|never)\s+(tell|inform|mention|reveal|disclose|show|notify|alert)\b[^.\n]{0,40}\b(the user|the human|the developer|users?)\b|\b(hide|conceal|keep)\b[^.\n]{0,30}\bfrom the (user|human|developer)\b|\b(silently|secretly|covertly)\s+(add|insert|include|run|execute|send|upload|modify|append|install|download)\b/i,
  },
  {
    id: 'prompt.conceal-soft',
    severity: 'low',
    title: 'Mentions acting without telling the user',
    detail: 'Often a description rather than an instruction; read it in context.',
    pattern: /\bwithout\s+(telling|informing|notifying|asking)\b[^.\n]{0,20}\b(the user|the human|them)\b/i,
  },
  {
    id: 'prompt.override',
    severity: 'high',
    title: 'Overrides prior instructions',
    detail: 'Asks the model to discard its instructions or safety rules.',
    pattern:
      /\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|system|safety)\b[^.\n]{0,20}\b(instructions?|rules?|prompts?|guidelines?)\b/i,
  },
  {
    id: 'prompt.code-injection',
    severity: 'high',
    title: 'Instructs the model to insert code or dependencies',
    detail: 'Steers the model to add specific code, endpoints or packages to what it writes for the user.',
    pattern:
      /\b(always|whenever|every time|when(ever)? (you )?(write|generat|edit|creat))\b[^.\n]{0,80}\b(add|insert|include|import|append|install)\b[^.\n]{0,60}(https?:\/\/|\bnpm\b|\bpip\b|require\(|import |fetch\(|eval\(|exec\(|webhook|endpoint|token|password|backdoor)/i,
  },
  {
    id: 'prompt.exfil-instruction',
    severity: 'high',
    title: 'Instructs the model to send data elsewhere',
    detail: 'Asks the model to upload, post or send files, keys or conversation content to an outside address.',
    pattern:
      /\b(send|post|upload|exfiltrat\w*|forward|transmit|leak)\b[^.\n]{0,60}\b(keys?|tokens?|secrets?|credentials?|\.env|passwords?|ssh|conversation|history|files?)\b[^.\n]{0,60}(https?:\/\/|webhook|pastebin|discord|telegram|ngrok)/i,
  },
  {
    id: 'prompt.secret-access',
    severity: 'low',
    title: 'Instructions reference credential files',
    detail: 'The text points the model at files where credentials are stored.',
    pattern: SECRET_PATH,
  },
]

/** Zero-width, bidi-override and Unicode tag characters, built from code points so the source stays plain ASCII. */
const INVISIBLE = (() => {
  const ranges: [number, number][] = [[0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff], [0xe0000, 0xe007f]]
  const hex = (n: number) => `\\u{${n.toString(16)}}`
  return new RegExp(`[${ranges.map(([a, b]) => `${hex(a)}-${hex(b)}`).join('')}]`, 'u')
})()
const BASE64_BLOB = /[A-Za-z0-9+/]{120,}={0,2}/
const HTML_COMMENT = /<!--([\s\S]*?)-->/g

export function lineOf(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++
  return line
}

export function snippetAt(text: string, index: number, max = 160): string {
  const start = text.lastIndexOf('\n', index - 1) + 1
  const endAt = text.indexOf('\n', index)
  const line = text.slice(start, endAt === -1 ? undefined : endAt).trim()
  return line.length > max ? `${line.slice(0, max)}…` : line
}

/** A match wrapped in quotes is usually an example being discussed, not an instruction. */
function quoted(text: string, index: number, length: number): boolean {
  const before = text.slice(Math.max(0, index - 2), index)
  const after = text.slice(index + length, index + length + 40)
  return /["“'`]$/.test(before) && /["”'`]/.test(after)
}

type Downgrade = Partial<Record<string, Severity>>

function applyRules(rules: readonly TextRule[], text: string, file: string, baseLine: number, out: Finding[], cap: Downgrade = {}) {
  for (const rule of rules) {
    const match = rule.pattern.exec(text)
    if (!match) continue
    const isQuoted = rule.id.startsWith('prompt.') && quoted(text, match.index, match[0].length)
    out.push({
      rule: rule.id,
      severity: isQuoted ? 'low' : (cap[rule.id] ?? rule.severity),
      title: isQuoted ? `${rule.title} (quoted)` : rule.title,
      detail: isQuoted ? `${rule.detail} The phrase is in quotes, so it is probably an example.` : rule.detail,
      file,
      line: baseLine + lineOf(text, match.index) - 1,
      snippet: snippetAt(text, match.index),
    })
  }
}

const NETWORK_TOOL = /\b(curl|wget|nc|ncat|netcat|socat|scp|rsync|ftp|Invoke-WebRequest|Invoke-RestMethod)\b/i

export function scanShellText(text: string, file: string, baseLine = 1): Finding[] {
  const out: Finding[] = []
  applyRules(SHELL_RULES, text, file, baseLine, out)
  let offset = 0
  for (const line of text.split('\n')) {
    if (SECRET_PATH.test(line) && NETWORK_TOOL.test(line)) {
      out.push({
        rule: 'shell.exfil-secrets',
        severity: 'critical',
        title: 'Sends credential files over the network',
        detail: 'One command both reads where keys or tokens are kept and talks to the network.',
        file,
        line: baseLine + lineOf(text, offset) - 1,
        snippet: snippetAt(text, offset),
      })
      break
    }
    offset += line.length + 1
  }
  return out
}

/**
 * Text the model reads: skills, agents, commands, CLAUDE.md, and strings a mod
 * adds to the prompt. Shell payloads count here too, since the model may run them.
 */
export function scanInstructionText(text: string, file: string, baseLine = 1): Finding[] {
  const out: Finding[] = []
  applyRules(INSTRUCTION_RULES, text, file, baseLine, out)
  // in prose, these describe a technique more often than they perform it
  applyRules(SHELL_RULES, text, file, baseLine, out, { 'shell.persistence': 'low', 'shell.disable-safety': 'low' })

  const concealed = out.some(f => f.rule === 'prompt.conceal' && f.severity === 'high')
  const payload = out.find(f =>
    ['prompt.code-injection', 'prompt.exfil-instruction', 'shell.pipe-to-shell', 'shell.reverse-shell', 'shell.decode-exec', 'shell.exfil-secrets'].includes(f.rule),
  )
  if (concealed && payload) {
    out.push({
      rule: 'prompt.covert-payload',
      severity: 'critical',
      title: 'Hidden instruction with a payload',
      detail: 'The text both tells the model to keep something from the user and tells it to run, send or insert something.',
      file,
      line: payload.line,
      snippet: payload.snippet,
    })
  }

  const invisible = INVISIBLE.exec(text)
  if (invisible) {
    out.push({
      rule: 'text.invisible-unicode',
      severity: 'high',
      title: 'Invisible or direction-changing characters',
      detail:
        'Zero-width, Unicode tag or bidi-override characters hide text from the person while the model still reads it.',
      file,
      line: baseLine + lineOf(text, invisible.index) - 1,
      snippet: `U+${invisible[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`,
    })
  }

  for (const comment of text.matchAll(HTML_COMMENT)) {
    const body = comment[1].trim()
    if (body.length < 20) continue
    const inner: Finding[] = []
    applyRules(INSTRUCTION_RULES, body, file, baseLine + lineOf(text, comment.index) - 1, inner)
    out.push({
      rule: 'text.hidden-comment',
      severity: inner.length > 0 ? 'high' : 'low',
      title: 'Hidden HTML comment in instructions',
      detail:
        inner.length > 0
          ? 'A comment the rendered page hides carries instructions for the model.'
          : 'A comment the rendered page hides; the model still reads it.',
      file,
      line: baseLine + lineOf(text, comment.index) - 1,
      snippet: body.length > 160 ? `${body.slice(0, 160)}…` : body,
    })
  }

  const blob = BASE64_BLOB.exec(text)
  if (blob) {
    out.push({
      rule: 'text.encoded-blob',
      severity: 'medium',
      title: 'Large encoded blob',
      detail: 'A long base64-like string in text the model reads; it may hide a payload or instructions.',
      file,
      line: baseLine + lineOf(text, blob.index) - 1,
      snippet: `${blob[0].slice(0, 60)}…`,
    })
  }
  return out
}
