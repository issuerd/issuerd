// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useRef, useCallback } from 'react'

export type ShortcutHandler = (e: KeyboardEvent) => void

interface ShortcutBinding {
  sequence: string[]
  handler: ShortcutHandler
  preventDefault?: boolean
}

export function useKeyboardShortcuts(bindings: ShortcutBinding[]) {
  const sequenceRef = useRef<string[]>([])
  const timerRef = useRef<number | null>(null)

  const clearSequence = useCallback(() => {
    sequenceRef.current = []
    if (timerRef.current) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Ignore shortcuts when typing in inputs/textareas
      const target = e.target as HTMLElement
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        // Allow Esc and ? even in inputs
        if (e.key !== 'Escape' && e.key !== '?') return
      }

      const key = normalizeKey(e)
      sequenceRef.current.push(key)

      // Reset sequence after 1 second of inactivity
      if (timerRef.current) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(clearSequence, 1000)

      for (const binding of bindings) {
        const seq = binding.sequence
        if (seq.length > sequenceRef.current.length) continue
        const recent = sequenceRef.current.slice(-seq.length)
        if (arraysEqual(recent, seq)) {
          if (binding.preventDefault !== false) e.preventDefault()
          binding.handler(e)
          clearSequence()
          return
        }
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [bindings, clearSequence])

  return clearSequence
}

function normalizeKey(e: KeyboardEvent): string {
  if (e.key === 'Escape') return 'Esc'
  if (e.key === 'Meta') return '⌘'
  if (e.ctrlKey && e.key !== 'Control') return `Ctrl+${e.key.toUpperCase()}`
  if (e.metaKey && e.key !== 'Meta') return `⌘+${e.key.toUpperCase()}`
  return e.key.length === 1 ? e.key.toUpperCase() : e.key
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  return a.every((val, idx) => val === b[idx])
}
