// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createPortal } from 'react-dom'
import { motion, AnimatePresence } from 'framer-motion'
import Fuse from 'fuse.js'
import { cn } from '@/lib/utils'
import { Search, CornerDownLeft, Command } from 'lucide-react'
import FocusTrap from '../ui/FocusTrap'
import { isMac, SHORTCUTS, formatShortcut } from '../../lib/keyboardShortcuts'

interface CommandItem {
  id: string
  label: string
  section: 'Navigate' | 'Actions' | 'Recent' | 'Help'
  shortcut?: string
  onSelect: () => void
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

export default function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const navigate = useNavigate()
  const id = useId()
  const inputId = `cmdk-input-${id}`
  const listId = `cmdk-list-${id}`
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const mac = isMac()

  const recentPages = useMemo(() => {
    if (typeof window === 'undefined') return []
    try {
      const raw = localStorage.getItem('issuerd-recent-pages')
      return raw ? (JSON.parse(raw) as string[]) : []
    } catch {
      return []
    }
  }, [open])

  const commands = useMemo<CommandItem[]>(() => {
    const nav: CommandItem[] = [
      {
        id: 'nav-dashboard',
        label: 'Go to Dashboard',
        section: 'Navigate',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'goto-dashboard')!),
        onSelect: () => navigate('/dashboard'),
      },
      {
        id: 'nav-users',
        label: 'Go to Users',
        section: 'Navigate',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'goto-users')!),
        onSelect: () => navigate('/users'),
      },
      {
        id: 'nav-clients',
        label: 'Go to Clients',
        section: 'Navigate',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'goto-clients')!),
        onSelect: () => navigate('/clients'),
      },
      {
        id: 'nav-events',
        label: 'Go to Events',
        section: 'Navigate',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'goto-events')!),
        onSelect: () => navigate('/events'),
      },
      {
        id: 'nav-sessions',
        label: 'Go to Sessions',
        section: 'Navigate',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'goto-sessions')!),
        onSelect: () => navigate('/sessions'),
      },
      {
        id: 'nav-realms',
        label: 'Go to Realms',
        section: 'Navigate',
        onSelect: () => navigate('/realms'),
      },
    ]

    const actions: CommandItem[] = [
      {
        id: 'act-new-user',
        label: 'Create new user',
        section: 'Actions',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'new-user')!),
        onSelect: () => navigate('/users', { state: { openCreate: true } }),
      },
      {
        id: 'act-new-client',
        label: 'Create new client',
        section: 'Actions',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'new-client')!),
        onSelect: () => navigate('/clients', { state: { openCreate: true } }),
      },
      {
        id: 'act-rotate-keys',
        label: 'Rotate realm keys',
        section: 'Actions',
        onSelect: () => navigate('/keys'),
      },
      {
        id: 'act-view-sessions',
        label: 'View my sessions',
        section: 'Actions',
        onSelect: () => navigate('/sessions'),
      },
      {
        id: 'act-export-events',
        label: 'Export event log',
        section: 'Actions',
        onSelect: () => navigate('/events'),
      },
    ]

    const recent: CommandItem[] = recentPages.map((path, idx) => ({
      id: `recent-${idx}`,
      label: `Recent: ${labelForPath(path)}`,
      section: 'Recent',
      onSelect: () => navigate(path),
    }))

    const help: CommandItem[] = [
      {
        id: 'help-shortcuts',
        label: 'Show keyboard shortcuts',
        section: 'Help',
        shortcut: formatShortcut(SHORTCUTS.find((s) => s.id === 'help')!),
        onSelect: () => {
          onClose()
          window.dispatchEvent(new CustomEvent('issuerd:show-shortcuts'))
        },
      },
    ]

    return [...nav, ...actions, ...recent, ...help]
  }, [navigate, recentPages, onClose])

  const filtered = useMemo(() => {
    if (!query.trim()) return commands
    const fuse = new Fuse(commands, { keys: ['label', 'section'], threshold: 0.4 })
    return fuse.search(query).map((r) => r.item)
  }, [commands, query])

  const grouped = useMemo(() => {
    const sections: Record<string, CommandItem[]> = {}
    const order = ['Navigate', 'Actions', 'Recent', 'Help']
    order.forEach((s) => (sections[s] = []))
    filtered.forEach((item) => {
      sections[item.section] ??= []
      sections[item.section].push(item)
    })
    return order
      .map((section) => ({ section, items: sections[section] }))
      .filter((g) => g.items.length > 0)
  }, [filtered])

  const flatItems = useMemo(() => grouped.flatMap((g) => g.items), [grouped])

  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  useEffect(() => {
    if (open) {
      const t = setTimeout(() => inputRef.current?.focus(), 50)
      return () => clearTimeout(t)
    } else {
      setQuery('')
      setSelectedIndex(0)
    }
  }, [open])

  function handleKeyDown(e: React.KeyboardEvent) {
    if (flatItems.length === 0) return
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setSelectedIndex((i) => (i + 1) % flatItems.length)
        break
      case 'ArrowUp':
        e.preventDefault()
        setSelectedIndex((i) => (i - 1 + flatItems.length) % flatItems.length)
        break
      case 'Enter':
        e.preventDefault()
        flatItems[selectedIndex]?.onSelect()
        onClose()
        break
      case 'Escape':
        e.preventDefault()
        onClose()
        break
    }
  }

  function execute(item: CommandItem) {
    item.onSelect()
    onClose()
  }

  if (typeof document === 'undefined') return null

  return createPortal(
    <AnimatePresence>
      {open && (
        <FocusTrap active onEscape={onClose}>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-[300] bg-black/60 flex items-start justify-center pt-[15vh] px-4"
            onClick={(e) => {
              if (e.target === e.currentTarget) onClose()
            }}
          >
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="w-full max-w-2xl bg-surface-dark border border-border-custom rounded-xl shadow-modal overflow-hidden"
              role="dialog"
              aria-modal="true"
              aria-label="Command palette"
            >
              <div className="flex items-center gap-3 px-4 py-3 border-b border-border-custom">
                <Search className="w-5 h-5 text-text-tertiary" />
                <input
                  ref={inputRef}
                  id={inputId}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Type a command or search..."
                  className="flex-1 bg-transparent text-text-primary placeholder:text-text-tertiary outline-none text-sm"
                  aria-controls={listId}
                  aria-activedescendant={flatItems[selectedIndex]?.id}
                />
                <div className="flex items-center gap-1 text-text-tertiary">
                  <kbd className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-white/[0.05] border border-border-custom text-[11px]">
                    <Command className="w-3 h-3" />
                    {mac ? 'K' : 'K'}
                  </kbd>
                </div>
              </div>

              <div
                id={listId}
                className="max-h-[50vh] overflow-auto py-2"
                role="listbox"
                aria-label="Command results"
              >
                {flatItems.length === 0 ? (
                  <div className="px-4 py-8 text-center text-sm text-text-tertiary">
                    No commands found.
                  </div>
                ) : (
                  grouped.map((group) => (
                    <div key={group.section} className="mb-2">
                      <div className="px-4 py-1 text-[11px] font-semibold uppercase tracking-wider text-text-tertiary">
                        {group.section}
                      </div>
                      {group.items.map((item) => {
                        const globalIndex = flatItems.indexOf(item)
                        const isSelected = globalIndex === selectedIndex
                        return (
                          <button
                            key={item.id}
                            id={item.id}
                            role="option"
                            aria-selected={isSelected}
                            onClick={() => execute(item)}
                            onMouseEnter={() => setSelectedIndex(globalIndex)}
                            className={cn(
                              'w-full flex items-center justify-between px-4 py-2.5 text-sm transition-colors text-left',
                              isSelected
                                ? 'bg-cyan-neon/10 text-cyan-neon'
                                : 'text-text-secondary hover:bg-white/[0.03] hover:text-text-primary'
                            )}
                          >
                            <span>{item.label}</span>
                            <span className="flex items-center gap-2">
                              {item.shortcut && (
                                <kbd className="hidden sm:inline-flex px-1.5 py-0.5 rounded bg-white/[0.05] border border-border-custom text-[11px] text-text-tertiary">
                                  {item.shortcut}
                                </kbd>
                              )}
                              {isSelected && <CornerDownLeft className="w-3.5 h-3.5 text-cyan-neon" />}
                            </span>
                          </button>
                        )
                      })}
                    </div>
                  ))
                )}
              </div>

              <div className="hidden sm:flex items-center justify-between px-4 py-2 border-t border-border-custom text-[11px] text-text-tertiary">
                <span>
                  {flatItems.length} result{flatItems.length === 1 ? '' : 's'}
                </span>
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 rounded bg-white/[0.05] border border-border-custom">↑↓</kbd> to navigate
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 rounded bg-white/[0.05] border border-border-custom">↵</kbd> to select
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1 rounded bg-white/[0.05] border border-border-custom">Esc</kbd> to close
                  </span>
                </div>
              </div>
            </motion.div>
          </motion.div>
        </FocusTrap>
      )}
    </AnimatePresence>,
    document.body
  )
}

function labelForPath(path: string): string {
  const map: Record<string, string> = {
    '/dashboard': 'Dashboard',
    '/users': 'Users',
    '/clients': 'Clients',
    '/events': 'Events & Logs',
    '/sessions': 'Sessions',
    '/realms': 'Realms',
    '/roles': 'Roles',
    '/groups': 'Groups',
    '/identity-providers': 'Identity Providers',
    '/keys': 'Keys',
    '/auth-flows': 'Auth Flows',
  }
  return map[path] ?? path
}
