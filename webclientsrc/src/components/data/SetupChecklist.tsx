// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useEffect } from 'react'
import { Check, X, ChevronDown, Globe } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'

interface ChecklistItem {
  id: string
  label: string
  description: string
  completed: boolean
  icon: React.ElementType
  action: () => void
}

interface SetupChecklistProps {
  realm: string
  items: ChecklistItem[]
}

export default function SetupChecklist({ realm, items }: SetupChecklistProps) {
  const storageKey = `issuerd-setup-checklist-dismissed-${realm}`
  const [dismissed, setDismissed] = useState(false)
  const [expanded, setExpanded] = useState(true)

  useEffect(() => {
    try {
      const stored = localStorage.getItem(storageKey)
      if (stored === 'true') setDismissed(true)
    } catch { /* ignore */ }
  }, [storageKey])

  if (dismissed) return null

  const completedCount = items.filter((i) => i.completed).length
  const totalCount = items.length
  const progress = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0
  const allDone = completedCount === totalCount

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 rounded-lg bg-cyan-neon/10 border border-cyan-neon/20 flex items-center justify-center shrink-0">
            <Globe className="w-5 h-5 text-cyan-neon" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-medium text-text-primary">Realm Setup</h3>
            <p className="text-xs text-text-tertiary truncate">
              {completedCount} of {totalCount} steps completed
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {/* Progress bar */}
          <div className="hidden sm:flex items-center gap-2">
            <div className="w-24 h-1.5 bg-white/5 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full transition-all duration-500',
                  allDone ? 'bg-matrix-green' : 'bg-cyan-neon'
                )}
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-xs text-text-tertiary">{progress}%</span>
          </div>

          <button
            onClick={() => setExpanded((e) => !e)}
            className="p-1.5 hover:bg-white/5 rounded-lg transition-colors text-text-tertiary"
            aria-label={expanded ? 'Collapse' : 'Expand'}
          >
            <ChevronDown className={cn('w-4 h-4 transition-transform', expanded && 'rotate-180')} aria-hidden="true" />
          </button>
          <button
            onClick={() => {
              setDismissed(true)
              try {
                localStorage.setItem(storageKey, 'true')
              } catch { /* ignore */ }
            }}
            className="p-1.5 hover:bg-white/5 rounded-lg transition-colors text-text-tertiary hover:text-text-primary"
            aria-label="Dismiss"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* Items */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-2">
              {items.map((item) => (
                <button
                  key={item.id}
                  onClick={item.action}
                  className={cn(
                    'w-full flex items-center gap-3 p-3 rounded-lg border transition-all text-left',
                    item.completed
                      ? 'bg-matrix-green/5 border-matrix-green/10 hover:bg-matrix-green/10'
                      : 'bg-white/[0.02] border-border-custom hover:bg-white/[0.04] hover:border-border-hover'
                  )}
                >
                  <div
                    className={cn(
                      'w-6 h-6 rounded-full flex items-center justify-center shrink-0',
                      item.completed
                        ? 'bg-matrix-green/20 text-matrix-green'
                        : 'bg-white/5 text-text-tertiary'
                    )}
                  >
                    {item.completed ? <Check className="w-3.5 h-3.5" aria-hidden="true" /> : <item.icon className="w-3.5 h-3.5" aria-hidden="true" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className={cn('text-sm', item.completed ? 'text-text-secondary line-through' : 'text-text-primary')}>
                      {item.label}
                    </div>
                    <div className="text-xs text-text-tertiary">{item.description}</div>
                  </div>
                  {!item.completed && (
                    <span className="text-xs text-cyan-neon shrink-0">Go →</span>
                  )}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
