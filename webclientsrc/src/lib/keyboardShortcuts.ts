// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

export interface ShortcutDef {
  id: string
  label: string
  category: 'Navigation' | 'Actions' | 'Global'
  keys: string[]
  macKeys?: string[]
}

export function isMac(): boolean {
  if (typeof navigator === 'undefined') return false
  return navigator.platform.toUpperCase().indexOf('MAC') >= 0
}

export function formatShortcut(shortcut: ShortcutDef): string {
  const keys = isMac() && shortcut.macKeys ? shortcut.macKeys : shortcut.keys
  return keys.join(' ')
}

export const SHORTCUTS: ShortcutDef[] = [
  { id: 'command-palette', label: 'Open command palette', category: 'Global', keys: ['Ctrl', 'K'], macKeys: ['⌘', 'K'] },
  { id: 'goto-users', label: 'Go to Users', category: 'Navigation', keys: ['Ctrl', 'U'], macKeys: ['⌘', 'U'] },
  { id: 'goto-clients', label: 'Go to Clients', category: 'Navigation', keys: ['Ctrl', 'C'], macKeys: ['⌘', 'C'] },
  { id: 'goto-events', label: 'Go to Events', category: 'Navigation', keys: ['Ctrl', 'E'], macKeys: ['⌘', 'E'] },
  { id: 'goto-dashboard', label: 'Go to Dashboard', category: 'Navigation', keys: ['G', 'D'] },
  { id: 'goto-sessions', label: 'Go to Sessions', category: 'Navigation', keys: ['G', 'S'] },
  { id: 'new-user', label: 'Create new user', category: 'Actions', keys: ['N', 'U'] },
  { id: 'new-client', label: 'Create new client', category: 'Actions', keys: ['N', 'C'] },
  { id: 'help', label: 'Show keyboard shortcuts', category: 'Global', keys: ['?'] },
  { id: 'close', label: 'Close modal / palette', category: 'Global', keys: ['Esc'] },
]
