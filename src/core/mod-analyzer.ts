import ts from 'typescript'
import type { CapabilityKind, Finding, Severity } from './types.ts'
import { SECRET_ENV, SECRET_PATH, scanInstructionText, scanShellText } from './text-rules.ts'

/**
 * Static analysis of one mod hooks module. Nothing here executes the module:
 * it is parsed with the TypeScript compiler and walked.
 *
 * A mod reaches the machine only through the engine interface `$` (no DOM, no
 * Node), so every call on `$` is a capability and the analysis is a matter of
 * resolving each call, including through aliases, back to its `$` path.
 */

export type CapabilityHit = { kind: CapabilityKind; target?: string }

export type HookInfo = { event: string; matcher: Record<string, string>; line: number }

export type ModAnalysis = {
  findings: Finding[]
  capabilities: CapabilityHit[]
  hooks: HookInfo[]
  apiCalls: string[]
  /** Module specifiers this file imports, as written. */
  imports: string[]
}

const DYNAMIC = Symbol('dynamic')
type Chain = string[] | typeof DYNAMIC | null

const API_CAPABILITY: Record<string, CapabilityKind> = {
  'fs.read': 'fs.read',
  'fs.list': 'fs.read',
  'fs.exists': 'fs.read',
  'fs.stat': 'fs.read',
  'fs.ancestors': 'fs.read',
  'fs.write': 'fs.write',
  'http.fetch': 'network',
  'process.run': 'process',
  'process.spawn': 'process',
  'env.get': 'env.read',
  'env.set': 'env.write',
  'settings.read': 'settings.read',
  'session.messages': 'session.read',
  'session.turns': 'session.read',
  'session.send': 'prompt.modify',
  'session.append': 'prompt.modify',
  'session.authorize': 'permission.decide',
  'prompt.submit': 'prompt.modify',
  'prompt.compose': 'prompt.modify',
  'prompt.fill': 'prompt.modify',
  'store.get': 'store',
  'store.set': 'store',
  'store.delete': 'store',
  'store.keys': 'store',
  'model.complete': 'model',
  'model.fork': 'model',
  'model.classify': 'model',
  'agent.spawn': 'agent',
  'agent.register': 'agent',
  'tool.register': 'tool.register',
  'tool.call': 'tool.intercept',
  'tool.check': 'permission.decide',
  'mcp.call': 'network',
  'mcp.connect': 'network',
  'command.register': 'command',
}

const EVENT_CAPABILITY: Record<string, CapabilityKind> = {
  'tool.call': 'tool.intercept',
  'tool.check': 'permission.decide',
  'tool.describe': 'tool.intercept',
  'tool.register': 'tool.register',
  'process.spawn': 'process',
  'session.receive': 'session.read',
  'session.send': 'session.read',
  'session.append': 'session.read',
  'session.authorize': 'permission.decide',
  'agent.offer': 'agent',
  'agent.spawn': 'agent',
  'command.run': 'command',
}

const PROMPT_EVENTS = new Set([
  'prompt.compose',
  'prompt.section',
  'prompt.context',
  'prompt.submit',
  'prompt.fill',
  'prompt.edit',
  'prompt.attachment',
  'prompt.suggest',
  'skill.prompt',
])

/** Sources whose data should never reach the network without the person knowing. */
const SENSITIVE_SOURCES = new Set(['settings.read', 'session.messages', 'session.turns', 'store.get'])
const SOURCES = new Set(['fs.read', 'env.get', ...SENSITIVE_SOURCES])
const SINKS = new Set(['http.fetch', 'process.run', 'process.spawn', 'fs.write', 'mcp.call', 'tool.call'])

const RISKY_TOOLS = /^(Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|Task|Agent|mcp__.*|\*)$/
const SHELL_BINARIES =
  /^(sh|bash|zsh|dash|fish|ksh|pwsh|powershell|cmd|curl|wget|nc|ncat|netcat|socat|python3?|node|perl|ruby|osascript|security|ssh|scp|base64|openssl)$/
const SUSPICIOUS_HOST =
  /(^\d{1,3}(\.\d{1,3}){3}$)|ngrok|webhook\.site|requestbin|pipedream|pastebin|hastebin|transfer\.sh|discord(app)?\.com$|api\.telegram\.org|burpcollaborator|interact\.sh|oast\.|\.onion$|trycloudflare\.com|serveo|localtunnel|loca\.lt/i
const PERSISTENCE_PATH =
  /(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.git\/hooks|crontab|LaunchAgents|\.claude\/settings(\.local)?\.json|(^|\/)CLAUDE\.md$|\.claude\/(plugins|agents|commands|skills)\/|\.mcp\.json$|authorized_keys)/
const HIJACK_ENV = /^(PATH|NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES|GIT_SSH_COMMAND|BASH_ENV|ENV|PYTHONSTARTUP|PROMPT_COMMAND|HTTPS?_PROXY|NODE_TLS_REJECT_UNAUTHORIZED|ANTHROPIC_BASE_URL)$/
/** Node modules a script outside the mod runtime (an MCP server, a hook script) uses to reach the machine. */
const NODE_CAPABILITY: Record<string, CapabilityKind> = {
  child_process: 'process',
  fs: 'fs.read',
  'fs/promises': 'fs.read',
  http: 'network',
  https: 'network',
  net: 'network',
  tls: 'network',
  dgram: 'network',
  dns: 'network',
  os: 'env.read',
  worker_threads: 'process',
  vm: 'process',
}

const GATE_ENV = /^(CI|GITHUB_ACTIONS|GITLAB_CI|BUILDKITE|JENKINS_URL|CIRCLECI|TRAVIS|SANDBOX|DOCKER|CONTAINER)$/

function scriptKind(file: string): ts.ScriptKind {
  if (/\.tsx$/.test(file)) return ts.ScriptKind.TSX
  if (/\.jsx$/.test(file)) return ts.ScriptKind.JSX
  if (/\.(m|c)?js$/.test(file)) return ts.ScriptKind.JS
  return ts.ScriptKind.TS
}

function unwrap(node: ts.Expression): ts.Expression {
  let current = node
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAwaitExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression
  }
  return current
}

function literalText(node: ts.Node | undefined): string | undefined {
  if (!node) return undefined
  if (ts.isStringLiteralLike(node)) return node.text
  if (ts.isTemplateExpression(node)) {
    return node.head.text + node.templateSpans.map(span => `\${…}${span.literal.text}`).join('')
  }
  return undefined
}

function hostOf(url: string): string | undefined {
  const match = /^(https?|wss?):\/\/([^/:?#\s$]+)/i.exec(url)
  return match?.[2].toLowerCase()
}

export function analyzeModule(file: string, text: string): ModAnalysis {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind(file))
  const findings: Finding[] = []
  const capabilities: CapabilityHit[] = []
  const hooks: HookInfo[] = []
  const apiCalls = new Set<string>()
  const lines = text.split('\n')

  const lineOf = (node: ts.Node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
  const snippetOf = (node: ts.Node) => {
    const line = (lines[lineOf(node) - 1] ?? '').trim()
    return line.length > 160 ? `${line.slice(0, 160)}…` : line
  }
  const seen = new Set<string>()
  const report = (rule: string, severity: Severity, title: string, detail: string, node: ts.Node) => {
    const key = `${rule}:${lineOf(node)}`
    if (seen.has(key)) return
    seen.add(key)
    findings.push({ rule, severity, title, detail, file, line: lineOf(node), snippet: snippetOf(node) })
  }

  // --- who is `on`, who is `$` -------------------------------------------------

  const onNames = new Set(['on'])
  const engineNames = new Set(['$'])
  const functionsByName = new Map<string, ts.FunctionLikeDeclaration>()

  const paramName = (fn: ts.SignatureDeclarationBase, index: number) => {
    const param = fn.parameters[index]
    return param && ts.isIdentifier(param.name) ? param.name.text : undefined
  }

  const visitDeclarations = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = unwrap(node.initializer)
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
        functionsByName.set(node.name.text, init)
        if (node.name.text === 'register') {
          const name = paramName(init, 0)
          if (name) onNames.add(name)
        }
      }
    }
    if (ts.isFunctionDeclaration(node) && node.name) {
      functionsByName.set(node.name.text, node)
      if (node.name.text === 'register') {
        const name = paramName(node, 0)
        if (name) onNames.add(name)
      }
    }
    ts.forEachChild(node, visitDeclarations)
  }
  visitDeclarations(sf)

  type Hook = { event: string; matcher: Record<string, string>; fn?: ts.FunctionLikeDeclaration; call: ts.CallExpression }
  const hookList: Hook[] = []

  const resolveFunction = (node: ts.Expression | undefined): ts.FunctionLikeDeclaration | undefined => {
    if (!node) return undefined
    const inner = unwrap(node)
    if (ts.isArrowFunction(inner) || ts.isFunctionExpression(inner)) return inner
    if (ts.isIdentifier(inner)) return functionsByName.get(inner.text)
    return undefined
  }

  const visitHooks = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && onNames.has(node.expression.text)) {
      const event = literalText(node.arguments[0])
      if (event !== undefined) {
        const matcher: Record<string, string> = {}
        const matcherNode = node.arguments.length >= 3 ? node.arguments[1] : undefined
        if (matcherNode && ts.isObjectLiteralExpression(matcherNode)) {
          for (const prop of matcherNode.properties) {
            if (ts.isPropertyAssignment(prop) && (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name))) {
              const value = literalText(prop.initializer)
              if (value !== undefined) matcher[prop.name.text] = value
            }
          }
        }
        const fn = resolveFunction(node.arguments[node.arguments.length - 1])
        if (fn) {
          const engine = paramName(fn, 0)
          if (engine) engineNames.add(engine)
        }
        hookList.push({ event, matcher, fn, call: node })
        hooks.push({ event, matcher, line: lineOf(node) })
      }
    }
    if (ts.isFunctionLike(node) && paramName(node, 0) === '$') engineNames.add('$')
    ts.forEachChild(node, visitHooks)
  }
  visitHooks(sf)

  // --- resolve expressions to `$` paths, through aliases ------------------------

  const aliases = new Map<string, string[]>()

  const resolveChain = (node: ts.Expression): Chain => {
    const inner = unwrap(node)
    if (ts.isIdentifier(inner)) {
      if (engineNames.has(inner.text)) return []
      return aliases.get(inner.text) ?? null
    }
    if (ts.isPropertyAccessExpression(inner)) {
      const base = resolveChain(inner.expression)
      if (base === null || base === DYNAMIC) return base
      return [...base, inner.name.text]
    }
    if (ts.isElementAccessExpression(inner)) {
      const base = resolveChain(inner.expression)
      if (base === null || base === DYNAMIC) return base
      const key = literalText(inner.argumentExpression)
      if (key !== undefined && ts.isStringLiteralLike(inner.argumentExpression)) return [...base, key]
      return DYNAMIC
    }
    if (ts.isCallExpression(inner) && ts.isPropertyAccessExpression(inner.expression)) {
      // `$.http.fetch.bind($.http)` keeps pointing at fetch
      if (inner.expression.name.text === 'bind') return resolveChain(inner.expression.expression)
    }
    return null
  }

  const bindAliases = (name: ts.BindingName, chain: string[]) => {
    if (ts.isIdentifier(name)) {
      aliases.set(name.text, chain)
      return
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        const key = element.propertyName
          ? ts.isIdentifier(element.propertyName) || ts.isStringLiteral(element.propertyName)
            ? element.propertyName.text
            : undefined
          : ts.isIdentifier(element.name)
            ? element.name.text
            : undefined
        if (key !== undefined) bindAliases(element.name, [...chain, key])
      }
    }
  }

  // two passes so an alias of an alias declared later still resolves
  for (let pass = 0; pass < 2; pass++) {
    const visitAliases = (node: ts.Node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const chain = resolveChain(node.initializer)
        if (Array.isArray(chain)) bindAliases(node.name, chain)
      }
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left)
      ) {
        const chain = resolveChain(node.right)
        if (Array.isArray(chain)) aliases.set(node.left.text, chain)
      }
      ts.forEachChild(node, visitAliases)
    }
    visitAliases(sf)
  }

  // --- every call on `$` --------------------------------------------------------

  type ApiCall = { api: string; node: ts.CallExpression }
  const calls: ApiCall[] = []

  const firstLiteralArg = (call: ts.CallExpression) => literalText(call.arguments[0])

  const argvOf = (call: ts.CallExpression, api: string): string[] | undefined => {
    let argvNode: ts.Expression | undefined = call.arguments[0]
    if (api === 'process.spawn' && argvNode && ts.isObjectLiteralExpression(argvNode)) {
      const prop = argvNode.properties.find(
        p => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'argv',
      ) as ts.PropertyAssignment | undefined
      argvNode = prop?.initializer
    }
    if (argvNode && ts.isArrayLiteralExpression(argvNode)) {
      return argvNode.elements.map(el => literalText(el) ?? '…')
    }
    return undefined
  }

  const visitCalls = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const chain = resolveChain(node.expression)
      if (chain === DYNAMIC) {
        report(
          'mod.dynamic-engine-access',
          'high',
          'Computed access to the engine interface',
          'A `$` member is chosen at run time (`$[name]`), which hides from review which capability the mod uses.',
          node,
        )
      } else if (chain && chain.length > 0) {
        const api = chain.slice(0, 2).join('.')
        calls.push({ api, node })
        apiCalls.add(api)
      }
    }
    if (ts.isElementAccessExpression(node) && !ts.isCallExpression(node.parent)) {
      const chain = resolveChain(node)
      if (chain === DYNAMIC) {
        report(
          'mod.dynamic-engine-access',
          'high',
          'Computed access to the engine interface',
          'A `$` member is chosen at run time (`$[name]`), which hides from review which capability the mod uses.',
          node,
        )
      }
    }
    ts.forEachChild(node, visitCalls)
  }
  visitCalls(sf)

  for (const { api, node } of calls) {
    const kind = API_CAPABILITY[api]
    const literal = firstLiteralArg(node)

    if (api === 'http.fetch') {
      const host = literal ? hostOf(literal) : undefined
      capabilities.push({ kind: 'network', target: host ?? (literal ?? '(computed URL)') })
      if (!literal) {
        report(
          'mod.network-computed-url',
          'medium',
          'Network request to a computed URL',
          'The destination is built at run time, so it cannot be reviewed from the source.',
          node,
        )
      }
      if (host && SUSPICIOUS_HOST.test(host)) {
        report(
          'mod.suspicious-host',
          'high',
          'Request to a host typical of data collection or tunnels',
          `\`${host}\` is a raw IP, tunnel, paste or webhook service often used to receive stolen data.`,
          node,
        )
      }
      const init = node.arguments[1]
      if (init && ts.isObjectLiteralExpression(init)) {
        const hasSocket = init.properties.some(
          p => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'socketPath',
        )
        if (hasSocket) capabilities.push({ kind: 'network', target: 'unix socket' })
      }
      continue
    }

    if (api === 'process.run' || api === 'process.spawn') {
      const argv = argvOf(node, api)
      const bin = argv?.[0]?.split('/').pop()
      capabilities.push({ kind: 'process', target: bin ?? '(computed command)' })
      if (!argv) {
        report(
          'mod.process-computed',
          'high',
          'Runs a command built at run time',
          'The command line is not a literal, so what runs cannot be reviewed from the source.',
          node,
        )
      } else if (bin && SHELL_BINARIES.test(bin)) {
        const viaShell = /^(sh|bash|zsh|dash|fish|ksh|pwsh|powershell|cmd)$/.test(bin)
        report(
          bin === 'security' ? 'mod.keychain-access' : 'mod.shell-exec',
          bin === 'security' || viaShell ? 'high' : 'medium',
          bin === 'security' ? 'Reads the macOS keychain' : `Runs \`${bin}\``,
          viaShell
            ? 'Starts a shell, which can run anything its arguments say.'
            : `\`${bin}\` can reach the network or run code; check what it is given.`,
          node,
        )
        const joined = argv.join(' ')
        for (const finding of scanShellText(joined, file, lineOf(node))) findings.push(finding)
      }
      continue
    }

    if (api === 'env.get' || api === 'env.set') {
      capabilities.push({ kind: kind!, target: literal ?? '(computed name)' })
      if (api === 'env.get' && literal && SECRET_ENV.test(literal)) {
        report(
          'mod.reads-secret-env',
          'medium',
          `Reads secret environment variable \`${literal}\``,
          'The variable usually holds a credential.',
          node,
        )
      }
      if (api === 'env.set' && literal && HIJACK_ENV.test(literal)) {
        report(
          'mod.env-hijack',
          'high',
          `Changes \`${literal}\` for every later command`,
          'This variable changes which programs run, what they load or where traffic goes, for the session and all it starts.',
          node,
        )
      }
      continue
    }

    if (api === 'fs.read' || api === 'fs.list' || api === 'fs.exists' || api === 'fs.stat') {
      capabilities.push({ kind: 'fs.read', target: literal })
      if (literal && SECRET_PATH.test(literal)) {
        report(
          'mod.reads-secrets',
          'high',
          `Reads a credential file (\`${literal}\`)`,
          'The path is where keys or tokens are stored.',
          node,
        )
      }
      continue
    }

    if (api === 'fs.write') {
      capabilities.push({ kind: 'fs.write', target: literal })
      if (literal && PERSISTENCE_PATH.test(literal)) {
        report(
          'mod.persistence',
          'high',
          `Writes to \`${literal}\``,
          'Writing here changes what runs or what the model is told in later sessions, outside this mod.',
          node,
        )
      }
      continue
    }

    if (api === 'tool.call') {
      const tool = literal
      capabilities.push({ kind: tool === 'Bash' ? 'process' : 'tool.intercept', target: tool ?? '(computed tool)' })
      if (tool && RISKY_TOOLS.test(tool)) {
        report(
          'mod.calls-tool',
          tool === 'Bash' ? 'medium' : 'low',
          `Calls the \`${tool}\` tool directly`,
          'The mod runs a tool itself, outside the model’s turn.',
          node,
        )
      }
      continue
    }

    if (api === 'session.authorize') {
      report(
        'mod.session-authorize',
        'high',
        'Changes what the session is authorized to do',
        'The mod grants or changes the session’s authorization itself.',
        node,
      )
    }

    if (kind) capabilities.push({ kind, target: literal })
    else if (api.startsWith('ui.') || api.startsWith('audio.')) capabilities.push({ kind: 'ui' })
    else if (api.startsWith('clock.')) capabilities.push({ kind: 'timer' })
  }

  // --- hooks ---------------------------------------------------------------

  const containsLiteral = (node: ts.Node, test: (text: string) => boolean): boolean => {
    let hit = false
    const walk = (n: ts.Node) => {
      if (hit) return
      const text = literalText(n)
      if (text !== undefined && test(text)) hit = true
      else ts.forEachChild(n, walk)
    }
    walk(node)
    return hit
  }

  for (const hook of hookList) {
    const capability = EVENT_CAPABILITY[hook.event]
    const target = hook.matcher.tool ?? hook.matcher.component ?? hook.event
    if (capability) capabilities.push({ kind: capability, target })
    if (PROMPT_EVENTS.has(hook.event)) capabilities.push({ kind: 'prompt.modify', target: hook.event })
    if (hook.event.startsWith('ui.')) capabilities.push({ kind: 'ui', target: hook.matcher.component ?? hook.event })
    if (hook.event === 'command.run') capabilities.push({ kind: 'command', target: hook.matcher.name })

    const fn = hook.fn
    if (!fn || !fn.body) continue
    const nextName = paramName(fn, 2)
    const tool = hook.matcher.tool

    if (hook.event === 'tool.call') {
      const visit = (node: ts.Node) => {
        if (
          ts.isCallExpression(node) &&
          ts.isIdentifier(node.expression) &&
          node.expression.text === nextName &&
          node.arguments[0] &&
          ts.isObjectLiteralExpression(node.arguments[0])
        ) {
          for (const prop of node.arguments[0].properties) {
            if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) continue
            const field = prop.name.text
            if (field === 'command' && (tool === undefined || tool === 'Bash')) {
              const value = prop.initializer
              const injects = containsLiteral(
                value,
                text => /(&&|\|\||;|\||`|\$\()/.test(text) || scanShellText(text, file).length > 0 || /\b(curl|wget|nc|bash|sh)\b/.test(text),
              )
              const onlyTidies =
                !injects &&
                !containsLiteral(value, text => text.trim().length > 0) &&
                /\.command\b/.test(value.getText(sf))
              if (injects) {
                report(
                  'mod.bash-rewrite-inject',
                  'critical',
                  'Appends extra shell commands to the model’s Bash calls',
                  'The command the person approves is not the command that runs: the mod adds its own.',
                  prop,
                )
              } else if (!onlyTidies) {
                report(
                  'mod.bash-rewrite',
                  'medium',
                  'Rewrites the model’s Bash commands',
                  'The command that runs differs from the one the model asked for; check that the change is harmless.',
                  prop,
                )
              }
            }
            if ((field === 'content' || field === 'new_string' || field === 'file_path') && tool !== 'Bash') {
              report(
                'mod.tool-input-rewrite',
                'medium',
                `Rewrites \`${field}\` of file edits`,
                'What gets written to disk differs from what the model produced.',
                prop,
              )
            }
            if (field === 'url' || field === 'prompt') {
              report(
                'mod.tool-input-rewrite',
                'medium',
                `Rewrites \`${field}\` of tool calls`,
                'The tool runs with input the model did not choose.',
                prop,
              )
            }
          }
        }
        ts.forEachChild(node, visit)
      }
      visit(fn.body)
    }

    if (hook.event === 'tool.check' || hook.event === 'tool.call') {
      const visit = (node: ts.Node) => {
        if (ts.isObjectLiteralExpression(node)) {
          for (const prop of node.properties) {
            if (
              ts.isPropertyAssignment(prop) &&
              ts.isIdentifier(prop.name) &&
              prop.name.text === 'decision' &&
              literalText(prop.initializer) === 'allow'
            ) {
              const risky = tool === undefined || RISKY_TOOLS.test(tool)
              report(
                'mod.auto-approve',
                risky ? 'high' : 'low',
                `Auto-approves ${tool ? `\`${tool}\`` : 'every tool'} without asking`,
                risky
                  ? 'Permission prompts and deny rules for this tool can be skipped: the mod answers `allow` itself.'
                  : 'The mod answers `allow` for a read-only tool.',
                prop,
              )
            }
          }
        }
        ts.forEachChild(node, visit)
      }
      visit(fn.body)
    }

    if (PROMPT_EVENTS.has(hook.event) || hook.event === 'session.send' || hook.event === 'session.append') {
      const visit = (node: ts.Node) => {
        const text = literalText(node)
        if (text !== undefined && text.length >= 12) {
          for (const finding of scanInstructionText(text, file, lineOf(node))) {
            findings.push({ ...finding, rule: `mod.${finding.rule}`, detail: `${finding.detail} (added to the prompt by \`${hook.event}\`)` })
          }
          const url = /https?:\/\/[^\s"'`)]+/.exec(text)?.[0]
          const host = url ? hostOf(url) : undefined
          if (host) {
            report(
              'mod.prompt-url',
              'medium',
              `Puts a URL into the prompt (${host})`,
              'The model is handed an address it may fetch, post to or write into code.',
              node,
            )
          }
          return
        }
        ts.forEachChild(node, visit)
      }
      visit(fn.body)
    }

    if (hook.event === 'ui.render') {
      const component = hook.matcher.component ?? ''
      if (/permission|approv|confirm|trust|dialog/i.test(component)) {
        report(
          'mod.ui-spoof',
          'medium',
          `Redraws the \`${component}\` element`,
          'A mod that draws permission or confirmation UI can show the person something other than what will happen.',
          hook.call,
        )
      }
    }

    if (hook.event === 'process.spawn') {
      report(
        'mod.intercepts-processes',
        'low',
        'Sees the output of every process other plugins start',
        'The hook sits above every `$.process.spawn`, so it reads (and can change) their output.',
        hook.call,
      )
    }
  }

  // --- data flow: sensitive source → sink ---------------------------------------

  type Taint = { source: string; sensitive: boolean }
  const tainted = new Map<string, Taint>()

  const callApi = (node: ts.CallExpression) => calls.find(c => c.node === node)?.api

  const sourceOf = (node: ts.Node): Taint | undefined => {
    let found: Taint | undefined
    const walk = (n: ts.Node) => {
      if (found?.sensitive) return
      if (ts.isCallExpression(n)) {
        const api = callApi(n)
        if (api && SOURCES.has(api)) {
          const literal = firstLiteralArg(n)
          const sensitive =
            SENSITIVE_SOURCES.has(api) ||
            (api === 'fs.read' && literal !== undefined && SECRET_PATH.test(literal)) ||
            (api === 'fs.read' && literal === undefined) ||
            (api === 'env.get' && literal !== undefined && SECRET_ENV.test(literal))
          const taint = { source: literal ? `$.${api}("${literal}")` : `$.${api}()`, sensitive }
          if (!found || sensitive) found = taint
        }
      }
      if (ts.isIdentifier(n)) {
        const taint = tainted.get(n.text)
        if (taint && (!found || taint.sensitive)) found = taint
      }
      ts.forEachChild(n, walk)
    }
    walk(node)
    return found
  }

  for (let pass = 0; pass < 4; pass++) {
    const walk = (node: ts.Node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const taint = sourceOf(node.initializer)
        if (taint) {
          const names: string[] = []
          const collect = (name: ts.BindingName) => {
            if (ts.isIdentifier(name)) names.push(name.text)
            else for (const el of name.elements) if (!ts.isOmittedExpression(el)) collect(el.name)
          }
          collect(node.name)
          for (const name of names) {
            const prior = tainted.get(name)
            if (!prior || (!prior.sensitive && taint.sensitive)) tainted.set(name, taint)
          }
        }
      }
      if (ts.isBinaryExpression(node) && ts.isIdentifier(node.left)) {
        const op = node.operatorToken.kind
        if (op === ts.SyntaxKind.EqualsToken || op === ts.SyntaxKind.PlusEqualsToken) {
          const taint = sourceOf(node.right)
          if (taint) tainted.set(node.left.text, taint)
        }
      }
      ts.forEachChild(node, walk)
    }
    walk(sf)
  }

  let flowFound = false
  for (const { api, node } of calls) {
    if (!SINKS.has(api)) continue
    for (const arg of node.arguments) {
      const taint = sourceOf(arg)
      if (!taint) continue
      // reading a file and writing it back is not a flow worth reporting on its own
      if (api === 'fs.write' && !taint.sensitive) continue
      flowFound = flowFound || api !== 'fs.write'
      const outward = api === 'http.fetch' || api === 'mcp.call'
      report(
        'mod.data-flow',
        taint.sensitive && api !== 'fs.write' ? 'critical' : outward ? 'medium' : 'high',
        `Data from \`${taint.source}\` reaches \`$.${api}\``,
        outward
          ? 'What the mod reads is sent off the machine.'
          : api === 'fs.write'
            ? 'Sensitive data is copied to another file.'
            : 'What the mod reads is passed to a command it runs.',
        node,
      )
      break
    }
  }

  const readsSensitive = calls.some(c => {
    if (SENSITIVE_SOURCES.has(c.api)) return c.api !== 'store.get'
    const literal = firstLiteralArg(c.node)
    return (
      (c.api === 'fs.read' && literal !== undefined && SECRET_PATH.test(literal)) ||
      (c.api === 'env.get' && literal !== undefined && SECRET_ENV.test(literal))
    )
  })
  const reachesOut = calls.some(c => c.api === 'http.fetch' || c.api === 'mcp.call' || c.api === 'process.run' || c.api === 'process.spawn')
  if (readsSensitive && reachesOut && !flowFound) {
    findings.push({
      rule: 'mod.secret-and-network',
      severity: 'high',
      title: 'Reads secrets and can reach the network',
      detail:
        'The module reads settings, secret variables, credential files or the conversation, and also makes requests or runs commands. No direct flow was traced; review how the two connect.',
      file,
    })
  }

  // --- code-hiding and gating ---------------------------------------------

  const usesSink = calls.some(c => SINKS.has(c.api))

  const visitMisc = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression
      const name = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : undefined
      const owner =
        ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) ? callee.expression.text : undefined

      if (ts.isIdentifier(callee) && (name === 'eval' || name === 'Function')) {
        report('mod.eval', 'high', `Runs code from a string (\`${name}\`)`, 'Code built at run time cannot be reviewed from the source.', node)
      }
      if (callee.kind === ts.SyntaxKind.ImportKeyword) {
        report('mod.dynamic-import', 'medium', 'Loads code at run time (`import()`)', 'What is loaded is decided at run time.', node)
      }
      if (ts.isIdentifier(callee) && name === 'require') {
        report('mod.require', 'medium', 'Uses `require`', 'Mods have no Node environment; `require` suggests code meant for somewhere else.', node)
      }
      if (name === 'atob' || (owner === 'String' && name === 'fromCharCode') || (owner === 'Buffer' && name === 'from' && literalText(node.arguments[1]) === 'base64')) {
        const encoded = name === 'fromCharCode' ? undefined : literalText(node.arguments[0])
        let decoded: string | undefined
        if (encoded) {
          decoded = Buffer.from(encoded, 'base64').toString('utf8')
          if (!/^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded)) decoded = undefined
        }
        const host = decoded ? hostOf(decoded) : undefined
        const dangerous = decoded !== undefined && (host !== undefined || scanShellText(decoded, file).length > 0)
        report(
          'mod.decode',
          dangerous ? 'high' : 'medium',
          dangerous ? 'Hides a URL or command in an encoded string' : 'Decodes hidden strings at run time',
          decoded
            ? `Decodes to: ${decoded.slice(0, 120)}${host && SUSPICIOUS_HOST.test(host) ? ' (a raw IP, tunnel or drop host)' : ''}`
            : 'Encoded strings hide URLs, commands or instructions from review.',
          node,
        )
        if (host) capabilities.push({ kind: 'network', target: host })
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
      report('mod.eval', 'high', 'Runs code from a string (`new Function`)', 'Code built at run time cannot be reviewed from the source.', node)
    }

    const text = literalText(node)
    if (text !== undefined && !ts.isImportDeclaration(node.parent) && !ts.isExportDeclaration(node.parent)) {
      if (/[A-Za-z0-9+/]{80,}={0,2}/.test(text)) {
        let decoded = ''
        try {
          decoded = Buffer.from(text, 'base64').toString('utf8')
        } catch {}
        const readable = decoded.length > 0 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded)
        if (readable) {
          report(
            'mod.encoded-string',
            /https?:\/\/|\b(curl|wget|bash|eval|exec|fetch)\b/.test(decoded) ? 'high' : 'medium',
            'Base64 string that decodes to readable text',
            `Decodes to: ${decoded.slice(0, 100)}${decoded.length > 100 ? '…' : ''}`,
            node,
          )
        }
      }
      if (/(\\x[0-9a-f]{2}){8,}/i.test(node.getText(sf))) {
        report('mod.encoded-string', 'medium', 'Hex-escaped string', 'Escaped strings hide their content from review.', node)
      }
      const host = hostOf(text)
      if (host) {
        capabilities.push({ kind: 'network', target: host })
        if (SUSPICIOUS_HOST.test(host)) {
          report(
            'mod.suspicious-host',
            'high',
            'Contains a host typical of data collection or tunnels',
            `\`${host}\` is a raw IP, tunnel, paste or webhook service often used to receive stolen data.`,
            node,
          )
        }
      }
      for (const finding of scanShellText(text, file, lineOf(node))) {
        findings.push({ ...finding, rule: `mod.${finding.rule}` })
      }
      if (SECRET_PATH.test(text) && !ts.isCallExpression(node.parent)) {
        report('mod.secret-path', 'low', 'Mentions a credential path', `\`${text.slice(0, 80)}\` names where credentials are kept.`, node)
      }
    }

    // time gates: Date.now() / new Date() compared with a constant
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind
      const comparison =
        op === ts.SyntaxKind.GreaterThanToken ||
        op === ts.SyntaxKind.GreaterThanEqualsToken ||
        op === ts.SyntaxKind.LessThanToken ||
        op === ts.SyntaxKind.LessThanEqualsToken
      if (comparison) {
        const sides = `${node.left.getText(sf)} ${node.right.getText(sf)}`
        const timeSide = /Date\.now\(\)|new Date\(\)|\.getTime\(\)|\.getFullYear\(\)|\.getMonth\(\)|clock\.now/.test(sides)
        const constant = /\b1[5-9]\d{11}\b|new Date\(\s*["'`\d]|Date\.parse\(\s*["'`]|\b20[2-9]\d\b/.test(sides)
        if (timeSide && constant) {
          report(
            'mod.time-gate',
            usesSink ? 'high' : 'medium',
            'Behaviour switches on at a fixed date',
            'Code that only acts after a date is a classic way to pass review and act later.',
            node,
          )
        }
      }
      if (op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken) {
        const sides = `${node.left.getText(sf)} ${node.right.getText(sf)}`
        if (/(Math\.random\(\))/.test(sides) === false && /\b(hostname|username|USER|repo|cwd)\b/.test(sides) && /["'`][\w.-]{3,}["'`]/.test(sides)) {
          report(
            'mod.target-gate',
            'low',
            'Behaviour depends on a specific user, host or repository',
            'The mod acts differently for one named target; check why.',
            node,
          )
        }
      }
    }
    ts.forEachChild(node, visitMisc)
  }
  visitMisc(sf)

  for (const { api, node } of calls) {
    if (api !== 'env.get') continue
    const literal = firstLiteralArg(node)
    if (literal && GATE_ENV.test(literal)) {
      report(
        'mod.environment-gate',
        usesSink ? 'medium' : 'low',
        `Checks whether it runs in \`${literal}\``,
        'Malware checks for CI or sandboxes to behave well under analysis.',
        node,
      )
    }
  }

  const imports: string[] = []
  const visitImports = (node: ts.Node) => {
    let specifier: string | undefined
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (!(ts.isImportDeclaration(node) && node.importClause?.isTypeOnly)) specifier = literalText(node.moduleSpecifier)
    } else if (
      ts.isCallExpression(node) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))
    ) {
      specifier = literalText(node.arguments[0])
    }
    if (specifier !== undefined) {
      imports.push(specifier)
      const kind = NODE_CAPABILITY[specifier.replace(/^node:/, '')]
      if (kind) capabilities.push({ kind, target: `node:${specifier.replace(/^node:/, '')}` })
    }
    ts.forEachChild(node, visitImports)
  }
  visitImports(sf)

  // module size and shape
  const longest = lines.reduce((max, line) => Math.max(max, line.length), 0)
  if (longest > 2000) {
    findings.push({
      rule: 'mod.minified',
      severity: 'medium',
      title: 'Minified or packed source',
      detail: `A line of ${longest} characters: shipped source this dense cannot be reviewed. Ask for the original.`,
      file,
    })
  }

  for (const diagnostic of (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? []) {
    findings.push({
      rule: 'mod.parse-error',
      severity: 'low',
      title: 'Source does not parse cleanly',
      detail: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
      file,
      line: diagnostic.start !== undefined ? sf.getLineAndCharacterOfPosition(diagnostic.start).line + 1 : undefined,
    })
    break
  }

  return { findings, capabilities, hooks, apiCalls: [...apiCalls].sort(), imports }
}
