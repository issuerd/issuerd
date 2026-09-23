// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useFormDraft } from './useFormDraft'

describe('useFormDraft', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  it('restores draft on mount', () => {
    const onRestore = vi.fn()
    localStorage.setItem('issuerd-draft-test', JSON.stringify({ name: 'Alice' }))
    renderHook(() => useFormDraft({ key: 'test', values: { name: '' }, onRestore }))
    expect(onRestore).toHaveBeenCalledWith({ name: 'Alice' })
  })

  it('does not restore when no draft exists', () => {
    const onRestore = vi.fn()
    renderHook(() => useFormDraft({ key: 'test', values: { name: '' }, onRestore }))
    expect(onRestore).not.toHaveBeenCalled()
  })

  it('does not restore when enabled is false', () => {
    const onRestore = vi.fn()
    localStorage.setItem('issuerd-draft-test', JSON.stringify({ name: 'Alice' }))
    renderHook(() => useFormDraft({ key: 'test', values: { name: '' }, enabled: false, onRestore }))
    expect(onRestore).not.toHaveBeenCalled()
  })

  it('autosaves values after debounce', async () => {
    renderHook(() => useFormDraft({ key: 'test', values: { name: 'Bob' } }))
    vi.advanceTimersByTime(6000)
    await waitFor(() => {
      expect(localStorage.getItem('issuerd-draft-test')).toBe(JSON.stringify({ name: 'Bob' }))
    })
  })

  it('does not autosave when enabled is false', async () => {
    renderHook(() => useFormDraft({ key: 'test', values: { name: 'Bob' }, enabled: false }))
    vi.advanceTimersByTime(6000)
    await waitFor(() => {
      expect(localStorage.getItem('issuerd-draft-test')).toBeNull()
    })
  })

  it('discardDraft removes localStorage entry', () => {
    localStorage.setItem('issuerd-draft-test', JSON.stringify({ name: 'Charlie' }))
    const { result } = renderHook(() => useFormDraft({ key: 'test', values: { name: '' } }))
    result.current.discardDraft()
    expect(localStorage.getItem('issuerd-draft-test')).toBeNull()
  })
})
