'use strict'

const STRINGS = {
  en: {
    verdict: {
      'malicious-indicators': ['Malicious indicators', 'Patterns typical of malware were found. Do not install.'],
      'high-risk': ['High risk', 'It can do things that need a close look before installing.'],
      review: ['Review recommended', 'Nothing clearly malicious, but some behaviour deserves a look.'],
      'no-known-issues': ['No known issues found', 'No known malicious pattern in this exact version.'],
    },
    capability: {
      'fs.read': 'Reads files', 'fs.write': 'Writes files', network: 'Network access', process: 'Runs commands',
      'env.read': 'Reads environment variables', 'env.write': 'Changes environment variables',
      'settings.read': 'Reads Claude Code settings', 'session.read': 'Reads the conversation', 'prompt.modify': 'Changes prompts',
      'tool.intercept': 'Intercepts tool calls', 'permission.decide': 'Answers permission prompts', ui: 'Draws UI',
      store: 'Keeps data across sessions', timer: 'Runs on a timer', model: 'Calls the model', agent: 'Starts subagents',
      'tool.register': 'Adds tools for the model', command: 'Adds slash commands', 'shell.hook': 'Shell hooks on events',
      'mcp.server': 'MCP servers', instructions: 'Instructions for the model',
    },
    severity: { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' },
    scanning: name => `Scanning ${name}…`,
    tooBig: 'That file is over 10 MB.',
    workerFailed: 'The scanner could not start in this browser. Reload the page and try again.',
    serverError: status => `Server returned ${status}`,
    download: 'Download JSON',
    canDo: 'What it can do',
    ships: 'What it ships',
    findings: n => `Findings (${n})`,
    noFindings: 'No findings.',
    noCaps: 'No capabilities detected.',
    noComponents: 'No components found.',
    summary: (files, plugins) => `${files} files · ${plugins} plugin${plugins === 1 ? '' : 's'}`,
    archive: '(archive)',
    findingsNote: '',
  },
  vi: {
    verdict: {
      'malicious-indicators': ['Có dấu hiệu độc hại', 'Tìm thấy mẫu điển hình của mã độc. Đừng cài.'],
      'high-risk': ['Rủi ro cao', 'Plugin làm được những việc cần xem kỹ trước khi cài.'],
      review: ['Nên xem lại', 'Không có gì rõ ràng độc hại, nhưng vài hành vi đáng xem lại.'],
      'no-known-issues': ['Chưa thấy vấn đề đã biết', 'Không có mẫu độc hại đã biết trong đúng phiên bản này.'],
    },
    capability: {
      'fs.read': 'Đọc file', 'fs.write': 'Ghi file', network: 'Truy cập mạng', process: 'Chạy lệnh',
      'env.read': 'Đọc biến môi trường', 'env.write': 'Đổi biến môi trường',
      'settings.read': 'Đọc settings của Claude Code', 'session.read': 'Đọc hội thoại', 'prompt.modify': 'Sửa prompt',
      'tool.intercept': 'Chặn lời gọi tool', 'permission.decide': 'Tự trả lời hộp thoại xin quyền', ui: 'Vẽ giao diện',
      store: 'Lưu dữ liệu qua các phiên', timer: 'Chạy theo hẹn giờ', model: 'Gọi model', agent: 'Khởi tạo subagent',
      'tool.register': 'Thêm tool cho model', command: 'Thêm slash command', 'shell.hook': 'Shell hook theo sự kiện',
      'mcp.server': 'MCP server', instructions: 'Chỉ dẫn cho model',
    },
    severity: { critical: 'nghiêm trọng', high: 'cao', medium: 'trung bình', low: 'thấp', info: 'thông tin' },
    scanning: name => `Đang quét ${name}…`,
    tooBig: 'File này lớn hơn 10 MB.',
    workerFailed: 'Không khởi động được bộ quét trong trình duyệt này. Hãy tải lại trang rồi thử lại.',
    serverError: status => `Server trả về ${status}`,
    download: 'Tải JSON',
    canDo: 'Plugin làm được gì',
    ships: 'Plugin chứa gì',
    findings: n => `Phát hiện (${n})`,
    noFindings: 'Không có phát hiện nào.',
    noCaps: 'Không phát hiện năng lực nào.',
    noComponents: 'Không tìm thấy thành phần nào.',
    summary: (files, plugins) => `${files} file · ${plugins} plugin`,
    archive: '(file nén)',
    findingsNote: 'Nội dung từng phát hiện hiện chỉ có tiếng Anh.',
  },
}
const T = () => STRINGS[window.modScanner?.lang === 'vi' ? 'vi' : 'en']
const RISKY = new Set(['fs.write', 'network', 'process', 'env.write', 'settings.read', 'session.read', 'prompt.modify', 'tool.intercept', 'permission.decide', 'shell.hook', 'mcp.server'])

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

// Scanning happens in a Web Worker in this browser. The server only fetches
// GitHub archives, which browsers cannot download directly.
let scanWorker = null
let nextScanId = 1

function scanInBrowser(payload) {
  if (!scanWorker) scanWorker = new Worker('/scan-worker.js')
  const worker = scanWorker
  const id = nextScanId++
  return new Promise((resolve, reject) => {
    const done = () => {
      worker.removeEventListener('message', onMessage)
      worker.removeEventListener('error', onError)
    }
    const onMessage = event => {
      if (event.data.id !== id) return
      done()
      if (event.data.error) reject(new Error(event.data.error))
      else resolve(event.data.report)
    }
    const onError = () => {
      done()
      scanWorker = null
      reject(new Error(T().workerFailed))
    }
    worker.addEventListener('message', onMessage)
    worker.addEventListener('error', onError)
    worker.postMessage({ id, ...payload }, [payload.bytes])
  })
}

async function run(task, label) {
  if (busy) return
  busy = true
  for (const button of document.querySelectorAll('button.primary')) button.disabled = true
  setStatus(T().scanning(label))
  report.hidden = true
  try {
    const data = await task()
    setStatus('')
    render(data)
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
  run(async () => {
    const response = await fetch(`/api/github?url=${encodeURIComponent(url)}`)
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.error || T().serverError(response.status))
    }
    const bytes = await response.arrayBuffer()
    const source = decodeURIComponent(response.headers.get('x-scan-source') || url)
    const subdir = decodeURIComponent(response.headers.get('x-scan-subdir') || '') || undefined
    return scanInBrowser({ bytes, source, subdir, fromGitHub: true })
  }, url)
})

function scanFile(file) {
  if (!file) return
  if (file.size > 10 * 1024 * 1024) {
    setStatus(T().tooBig, true)
    return
  }
  run(async () => scanInBrowser({ bytes: await file.arrayBuffer(), source: file.name }), file.name)
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
    el('header', {}, el('span', { class: `pill ${f.severity}` }, T().severity[f.severity] || f.severity), el('strong', {}, f.title)),
    el('p', {}, f.detail),
    f.snippet ? el('pre', {}, f.snippet) : null,
    el('div', { class: 'where' }, `${f.file || T().archive}${f.line ? `:${f.line}` : ''} · ${f.rule}`),
  )
}

function renderPlugin(plugin) {
  const t = T()
  const [label] = t.verdict[plugin.verdict]
  const caps = plugin.capabilities.length
    ? el(
        'div',
        { class: 'caps' },
        plugin.capabilities.map(cap => {
          const name = t.capability[cap.kind] || cap.kind
          const risky = RISKY.has(cap.kind)
          return el(
            'div',
            { class: `cap${risky ? ' risky' : ''}` },
            el('strong', {}, name),
            el('span', {}, cap.targets.length ? cap.targets.slice(0, 8).join(', ') + (cap.targets.length > 8 ? ', …' : '') : cap.files.join(', ')),
          )
        }),
      )
    : el('p', { class: 'empty' }, t.noCaps)

  return el(
    'section',
    { class: 'card plugin' },
    el('h3', {}, `${plugin.name}${plugin.version ? ` @ ${plugin.version}` : ''}`, el('span', { class: `pill v-${plugin.verdict}` }, `${label} · ${plugin.score}`)),
    plugin.description ? el('p', { class: 'desc' }, plugin.description) : null,
    el('div', { class: 'meta mono' }, `${plugin.root || '.'} · sha256 ${plugin.sha256}`),
    el('h4', {}, t.canDo),
    caps,
    el('h4', {}, t.ships),
    plugin.components.length
      ? el('div', { class: 'components' }, plugin.components.map(c => el('span', {}, `${c.kind}: ${c.name}`)))
      : el('p', { class: 'empty' }, t.noComponents),
    el('h4', {}, t.findings(plugin.findings.length)),
    plugin.findings.length
      ? el('ul', { class: 'findings' }, plugin.findings.map(findingItem))
      : el('p', { class: 'empty' }, t.noFindings),
  )
}

let lastReport = null

function render(data) {
  lastReport = data
  const t = T()
  const [title, summary] = t.verdict[data.verdict]
  const download = el('button', { class: 'ghost', type: 'button' }, t.download)
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
        el('p', { class: 'mono' }, `${data.source} · ${t.summary(data.fileCount, data.plugins.length)}`),
        t.findingsNote ? el('p', {}, t.findingsNote) : null,
      ),
      el('div', { class: 'actions' }, download),
    ),
    data.findings.length ? el('section', { class: 'card' }, el('ul', { class: 'findings' }, data.findings.map(findingItem))) : null,
    ...data.plugins.map(renderPlugin),
  ]
  report.replaceChildren(...sections.filter(Boolean))
  report.hidden = false
}

window.modScanner?.onLanguage(() => {
  if (lastReport) render(lastReport)
})

const initial = new URL(location.href).searchParams.get('url')
if (initial) {
  $('#github-url').value = initial
  $('#github-form').requestSubmit()
}
