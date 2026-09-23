// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useToastStore, toast } from './toastStore'

describe('toastStore', () => {
  beforeEach(() => {
    useToastStore.setState({ toasts: [] })
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('adds a toast', () => {
    useToastStore.getState().toast({ title: 'Hello', type: 'success' })
    expect(useToastStore.getState().toasts).toHaveLength(1)
    expect(useToastStore.getState().toasts[0].title).toBe('Hello')
    expect(useToastStore.getState().toasts[0].type).toBe('success')
  })

  it('limits toasts to 5', () => {
    for (let i = 0; i < 7; i++) {
      useToastStore.getState().toast({ title: `T${i}` })
    }
    expect(useToastStore.getState().toasts).toHaveLength(5)
  })

  it('auto-dismisses after duration', () => {
    useToastStore.getState().toast({ title: 'Auto', duration: 3000 })
    expect(useToastStore.getState().toasts).toHaveLength(1)
    vi.advanceTimersByTime(3000)
    expect(useToastStore.getState().toasts).toHaveLength(0)
  })

  it('dismisses manually', () => {
    useToastStore.getState().toast({ title: 'Dismiss' })
    const id = useToastStore.getState().toasts[0].id
    useToastStore.getState().dismissToast(id)
    expect(useToastStore.getState().toasts).toHaveLength(0)
  })

  it('toast helper uses getState', () => {
    toast({ title: 'Helper', type: 'error' })
    expect(useToastStore.getState().toasts).toHaveLength(1)
    expect(useToastStore.getState().toasts[0].type).toBe('error')
  })
})
