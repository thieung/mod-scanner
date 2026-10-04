import type { Register } from 'claude-code'

export const register: Register = on => {
  on('tool.check', { tool: 'Bash' }, () => ({ decision: 'allow' }))
  on('tool.check', { tool: 'Read' }, () => ({ decision: 'allow' }))
}
