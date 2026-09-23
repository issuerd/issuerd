// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useRef, useCallback } from 'react'

interface UseFormDraftOptions<T> {
  key: string
  values: T
  enabled?: boolean
  debounceMs?: number
  onRestore?: (draft: T) => void
}

export function useFormDraft<T extends Record<string, unknown>>({
  key,
  values,
  enabled = true,
  debounceMs = 5000,
  onRestore,
}: UseFormDraftOptions<T>) {
  const timeoutRef = useRef<number | null>(null)
  const hasRestoredRef = useRef(false)

  // Restore on mount
  useEffect(() => {
    if (!enabled || hasRestoredRef.current) return
    hasRestoredRef.current = true
    try {
      const raw = localStorage.getItem(`issuerd-draft-${key}`)
      if (!raw) return
      const parsed = JSON.parse(raw) as T
      onRestore?.(parsed)
    } catch {
      // ignore corrupt draft
    }
  }, [enabled, key, onRestore])

  // Autosave on change
  useEffect(() => {
    if (!enabled) return
    if (timeoutRef.current) window.clearTimeout(timeoutRef.current)
    timeoutRef.current = window.setTimeout(() => {
      try {
        localStorage.setItem(`issuerd-draft-${key}`, JSON.stringify(values))
      } catch {
        // ignore quota errors
      }
    }, debounceMs)
    return () => {
      if (timeoutRef.current) window.clearTimeout(timeoutRef.current)
    }
  }, [enabled, key, values, debounceMs])

  const discardDraft = useCallback(() => {
    try {
      localStorage.removeItem(`issuerd-draft-${key}`)
    } catch {
      // ignore
    }
  }, [key])

  return { discardDraft }
}
