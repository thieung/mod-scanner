'use strict'

const VERDICT = {
  'malicious-indicators': ['Malicious indicators', 'Patterns typical of malware were found. Do not install.'],
  'high-risk': ['High risk', 'It can do things that need a close look before installing.'],
  review: ['Review recommended', 'Nothing clearly malicious, but some behaviour deserves a look.'],
  'no-known-issues': ['No known issues found', 'No known malicious pattern in this exact version.'],
}

const CAPABILITY = {
  'fs.read': ['Reads files', false],
  'fs.write': ['Writes files', true],
  network: ['Network access', true],
  process: ['Runs commands', true],
  'env.read': ['Reads environment variables', false],
  'env.write': ['Changes environment variables', true],
  'settings.read': ['Reads Claude Code settings', true],
  'session.read': ['Reads the conversation', true],
  'prompt.modify': ['Changes prompts', true],
  'tool.intercept': ['Intercepts tool calls', true],
  'permission.decide': ['Answers permission prompts', true],
  ui: ['Draws UI', false],
  store: ['Keeps data across sessions', false],
  timer: ['Runs on a timer', false],
  model: ['Calls the model', false],
  agent: ['Starts subagents', false],
  'tool.register': ['Adds tools for the model', false],
  command: ['Adds slash commands', false],
  'shell.hook': ['Shell hooks on events', true],
  'mcp.server': ['MCP servers', true],
  instructions: ['Instructions for the model', false],
}

const $ = sel => document.querySelector(sel)
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value
    else node.setAttribute(key, value)
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue
    node.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
  return node
}

const status = $('#status')
const report = $('#report')
let busy = false

function setStatus(text, isError = false) {
  status.textContent = text
  status.classList.toggle('error', isError)
}

for (const tab of document.querySelectorAll('[data-tab]')) {
  tab.addEventListener('click', () => {
    for (const other of document.querySelectorAll('[data-tab]')) other.setAttribute('aria-selected', String(other === tab))
    for (const panel of document.querySelectorAll('[data-panel]')) panel.hidden = panel.dataset.panel !== tab.dataset.tab
  })
}

async function run(request, label) {
  if (busy) return
  busy = true
  for (const button of document.querySelectorAll('button.primary')) button.disabled = true
  setStatus(`Scanning ${label}…`)
  report.hidden = true
  try {
    const response = await request()
    const body = await response.json().catch(() => ({ error: `Server returned ${response.status}` }))
    if (!response.ok) throw new Error(body.error || `Server returned ${response.status}`)
    setStatus('')
    render(body)
    const url = new URL(location.href)
    if (label.startsWith('http') || /^[\w.-]+\/[\w.-]+/.test(label)) url.searchParams.set('url', label)
    else url.searchParams.delete('url')
    history.replaceState(null, '', url)
  } catch (error) {
    setStatus(error.message, true)
  } finally {
    busy = false
    for (const button of document.querySelectorAll('button.primary')) button.disabled = false
  }
}

$('#github-form').addEventListener('submit', event => {
  event.preventDefault()
  const url = $('#github-url').value.trim()
  if (!url) return
  run(
    () => fetch('/api/scan/github', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) }),
    url,
  )
})

function scanFile(file) {
  if (!file) return
  if (file.size > 10 * 1024 * 1024) {
    setStatus('That file is over 10 MB.', true)
    return
  }
  run(
    () => fetch(`/api/scan/upload?name=${encodeURIComponent(file.name)}`, { method: 'POST', headers: { 'content-type': 'application/zip' }, body: file }),
    file.name,
  )
}

const drop = $('#drop')
$('#zip').addEventListener('change', event => scanFile(event.target.files[0]))
drop.addEventListener('dragover', event => {
  event.preventDefault()
  drop.classList.add('over')
})
drop.addEventListener('dragleave', () => drop.classList.remove('over'))
drop.addEventListener('drop', event => {
  event.preventDefault()
  drop.classList.remove('over')
  scanFile(event.dataTransfer.files[0])
})

function findingItem(f) {
  return el(
    'li',
    { class: 'finding' },
    el('header', {}, el('span', { class: `pill ${f.severity}` }, f.severity), el('strong', {}, f.title)),
    el('p', {}, f.detail),
    f.snippet ? el('pre', {}, f.snippet) : null,
    el('div', { class: 'where' }, `${f.file || '(archive)'}${f.line ? `:${f.line}` : ''} · ${f.rule}`),
  )
}

function renderPlugin(plugin) {
  const [label] = VERDICT[plugin.verdict]
  const caps = plugin.capabilities.length
    ? el(
        'div',
        { class: 'caps' },
        plugin.capabilities.map(cap => {
          const [name, risky] = CAPABILITY[cap.kind] || [cap.kind, false]
          return el(
            'div',
            { class: `cap${risky ? ' risky' : ''}` },
            el('strong', {}, name),
            el('span', {}, cap.targets.length ? cap.targets.slice(0, 8).join(', ') + (cap.targets.length > 8 ? ', …' : '') : cap.files.join(', ')),
          )
        }),
      )
    : el('p', { class: 'empty' }, 'No capabilities detected.')

  return el(
    'section',
    { class: 'card plugin' },
    el('h3', {}, `${plugin.name}${plugin.version ? ` @ ${plugin.version}` : ''}`, el('span', { class: `pill v-${plugin.verdict}` }, `${label} · ${plugin.score}`)),
    plugin.description ? el('p', { class: 'desc' }, plugin.description) : null,
    el('div', { class: 'meta mono' }, `${plugin.root || '.'} · sha256 ${plugin.sha256}`),
    el('h4', {}, 'What it can do'),
    caps,
    el('h4', {}, 'What it ships'),
    plugin.components.length
      ? el('div', { class: 'components' }, plugin.components.map(c => el('span', {}, `${c.kind}: ${c.name}`)))
      : el('p', { class: 'empty' }, 'No components found.'),
    el('h4', {}, `Findings (${plugin.findings.length})`),
    plugin.findings.length
      ? el('ul', { class: 'findings' }, plugin.findings.map(findingItem))
      : el('p', { class: 'empty' }, 'No findings.'),
  )
}

function render(data) {
  const [title, summary] = VERDICT[data.verdict]
  const download = el('button', { class: 'ghost', type: 'button' }, 'Download JSON')
  download.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const link = el('a', { href: URL.createObjectURL(blob), download: `mod-scan-${data.sha256.slice(0, 12)}.json` })
    link.click()
    setTimeout(() => URL.revokeObjectURL(link.href), 1000)
  })

  const sections = [
    el(
      'div',
      { class: `verdict v-${data.verdict}` },
      el('div', { class: 'score' }, String(data.score), el('small', {}, '/100')),
      el(
        'div',
        {},
        el('h2', {}, title),
        el('p', {}, summary),
        el('p', { class: 'mono' }, `${data.source} · ${data.fileCount} files · ${data.plugins.length} plugin${data.plugins.length === 1 ? '' : 's'}`),
      ),
      el('div', { class: 'actions' }, download),
    ),
    data.findings.length ? el('section', { class: 'card' }, el('ul', { class: 'findings' }, data.findings.map(findingItem))) : null,
    ...data.plugins.map(renderPlugin),
  ]
  report.replaceChildren(...sections.filter(Boolean))
  report.hidden = false
}

const initial = new URL(location.href).searchParams.get('url')
if (initial) {
  $('#github-url').value = initial
  $('#github-form').requestSubmit()
}
