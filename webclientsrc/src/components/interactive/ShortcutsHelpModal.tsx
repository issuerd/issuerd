// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { createPortal } from 'react-dom'
import { Search, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import FocusTrap from '../ui/FocusTrap'
import { SHORTCUTS, formatShortcut, isMac } from '../../lib/keyboardShortcuts'

interface ShortcutsHelpModalProps {
  open: boolean
  onClose: () => void
}

export default function ShortcutsHelpModal({ open, onClose }: ShortcutsHelpModalProps) {
  const [filter, setFilter] = useState('')

  useEffect(() => {
    if (open) setFilter('')
  }, [open])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return SHORTCUTS
    return SHORTCUTS.filter(
      (s) =>
        s.label.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q) ||
        formatShortcut(s).toLowerCase().includes(q)
    )
  }, [filter])

  const grouped = useMemo(() => {
    const cats: Record<string, typeof SHORTCUTS> = {}
    filtered.forEach((s) => {
      cats[s.category] ??= []
      cats[s.category].push(s)
    })
    return cats
  }, [filtered])

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
            className="fixed inset-0 z-[300] bg-black/60 flex items-center justify-center p-4"
            onClick={(e) => {
              if (e.target === e.currentTarget) onClose()
            }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 6 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="w-full max-w-lg bg-surface-dark border border-border-custom rounded-xl shadow-modal overflow-hidden"
              role="dialog"
              aria-modal="true"
              aria-labelledby="shortcuts-title"
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-border-custom">
                <h2 id="shortcuts-title" className="font-display text-lg text-white">
                  Keyboard Shortcuts
                </h2>
                <button
                  onClick={onClose}
                  className="p-1 hover:bg-white/5 rounded-lg transition-colors text-text-tertiary hover:text-text-primary"
                  aria-label="Close"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="px-6 py-4">
                <div className="relative mb-4">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                  <input
                    type="text"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Search shortcuts..."
                    className="w-full h-10 pl-9 pr-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none"
                    autoFocus
                  />
                </div>

                <div className="max-h-[50vh] overflow-auto space-y-4 pr-1">
                  {Object.entries(grouped).map(([category, items]) => (
                    <div key={category}>
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-text-tertiary mb-2">
                        {category}
                      </div>
                      <div className="space-y-1">
                        {items.map((shortcut) => {
                          const keys = formatShortcut(shortcut).split(' ')
                          return (
                            <div
                              key={shortcut.id}
                              className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-white/[0.03]"
                            >
                              <span className="text-sm text-text-secondary">{shortcut.label}</span>
                              <span className="flex items-center gap-1">
                                {keys.map((k, i) => (
                                  <kbd
                                    key={i}
                                    className={cn(
                                      'px-1.5 py-0.5 rounded border border-border-custom bg-white/[0.05] text-[11px] font-mono text-text-primary',
                                      k.length === 1 && 'min-w-[1.5rem] text-center'
                                    )}
                                  >
                                    {k}
                                  </kbd>
                                ))}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                  {filtered.length === 0 && (
                    <div className="text-center text-sm text-text-tertiary py-4">
                      No shortcuts match your search.
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-border-custom text-[11px] text-text-tertiary flex items-center justify-between">
                  <span>Current OS: {isMac() ? 'macOS' : 'Windows/Linux'}</span>
                  <span>Symbols adapt to your OS automatically.</span>
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
