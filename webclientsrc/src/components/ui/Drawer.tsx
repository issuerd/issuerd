// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import FocusTrap from './FocusTrap'

export type DrawerPlacement = 'left' | 'right'

interface DrawerProps {
  open: boolean
  onClose: () => void
  title?: React.ReactNode
  children: React.ReactNode
  placement?: DrawerPlacement
  width?: string
  className?: string
  showClose?: boolean
}

export default function Drawer({
  open,
  onClose,
  title,
  children,
  placement = 'right',
  width = '480px',
  className,
  showClose = true,
}: DrawerProps) {
  const prevOpenRef = useRef(open)

  useEffect(() => {
    if (typeof document === 'undefined') return
    if (open) {
      document.body.style.overflow = 'hidden'
    } else if (prevOpenRef.current) {
      document.body.style.overflow = ''
    }
    prevOpenRef.current = open
    return () => {
      document.body.style.overflow = ''
    }
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const isRight = placement === 'right'

  return (
    <>
      {typeof document !== 'undefined' &&
        createPortal(
          <AnimatePresence>
            {open && (
              <div className="fixed inset-0 z-modal-overlay" aria-modal="true" role="dialog">
                {/* Backdrop */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="absolute inset-0 bg-black/60"
                  onClick={onClose}
                />

                {/* Drawer panel */}
                <FocusTrap active={open}>
                  <motion.div
                    initial={{ x: isRight ? '100%' : '-100%' }}
                    animate={{ x: 0 }}
                    exit={{ x: isRight ? '100%' : '-100%' }}
                    transition={{ type: 'tween', duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    className={cn(
                      'absolute top-0 bottom-0 bg-surface-dark border-border-custom shadow-2xl flex flex-col',
                      isRight ? 'right-0 border-l' : 'left-0 border-r',
                      className
                    )}
                    style={{ width }}
                  >
                    {/* Header */}
                    {(title || showClose) && (
                      <div className="flex items-center justify-between px-5 py-4 border-b border-border-custom shrink-0">
                        {title && (
                          <h2 className="font-display text-base font-medium text-text-primary">
                            {title}
                          </h2>
                        )}
                        {showClose && (
                          <button
                            onClick={onClose}
                            className="p-1.5 hover:bg-white/5 rounded-lg transition-colors text-text-tertiary hover:text-text-primary ml-auto"
                            aria-label="Close drawer"
                          >
                            <X className="w-5 h-5" />
                          </button>
                        )}
                      </div>
                    )}

                    {/* Content */}
                    <div className="flex-1 overflow-y-auto p-5">{children}</div>
                  </motion.div>
                </FocusTrap>
              </div>
            )}
          </AnimatePresence>,
          document.body
        )}
    </>
  )
}
