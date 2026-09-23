// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { ChevronDown } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

interface FormSectionProps {
  title: string
  description?: string
  children: React.ReactNode
  defaultOpen?: boolean
  sectionId: string
  configuredCount?: number
  totalCount?: number
}

export default function FormSection({
  title,
  description,
  children,
  defaultOpen = true,
  sectionId,
  configuredCount,
  totalCount,
}: FormSectionProps) {
  const storageKey = `issuerd-form-section-${sectionId}`
  const [open, setOpen] = useState(() => {
    try {
      const stored = localStorage.getItem(storageKey)
      return stored !== null ? stored === 'true' : defaultOpen
    } catch {
      return defaultOpen
    }
  })

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, String(open))
    } catch {
      // ignore
    }
  }, [open, storageKey])

  const showBadge =
    configuredCount !== undefined && totalCount !== undefined && !open

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-white/[0.02] transition-colors"
        aria-expanded={open}
      >
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <span className="font-display text-sm font-medium text-text-primary">
              {title}
            </span>
            {showBadge && (
              <span className="px-1.5 py-0.5 rounded-full bg-cyan-neon/10 text-cyan-neon text-[10px] font-semibold uppercase tracking-wider">
                {configuredCount} of {totalCount} configured
              </span>
            )}
          </div>
          {description && (
            <span className="text-xs text-text-tertiary">{description}</span>
          )}
        </div>
        <ChevronDown
          className={cn(
            'w-5 h-5 text-text-tertiary transition-transform duration-200 shrink-0 ml-4',
            open && 'rotate-180'
          )}
          aria-hidden="true"
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 pt-1 flex flex-col gap-4">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
