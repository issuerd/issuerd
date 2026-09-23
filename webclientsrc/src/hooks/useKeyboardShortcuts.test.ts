// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useKeyboardShortcuts } from './useKeyboardShortcuts'

describe('useKeyboardShortcuts', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('triggers single-key shortcut', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'A' }))
    expect(handler).toHaveBeenCalled()
  })

  it('triggers chord shortcut', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['G', 'D'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'G' }))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'D' }))
    expect(handler).toHaveBeenCalled()
  })

  it('ignores shortcuts while typing in input', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler }]))
    const input = document.createElement('input')
    document.body.appendChild(input)
    input.focus()
    const event = new KeyboardEvent('keydown', { key: 'A', bubbles: true })
    Object.defineProperty(event, 'target', { value: input, enumerable: true })
    input.dispatchEvent(event)
    expect(handler).not.toHaveBeenCalled()
    document.body.removeChild(input)
  })

  it('resets sequence after timeout', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['G', 'D'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'G' }))
    vi.advanceTimersByTime(1100)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'D' }))
    expect(handler).not.toHaveBeenCalled()
  })

  it('calls preventDefault by default', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler }]))
    const event = new KeyboardEvent('keydown', { key: 'A', cancelable: true })
    const spy = vi.spyOn(event, 'preventDefault')
    window.dispatchEvent(event)
    expect(spy).toHaveBeenCalled()
  })

  it('does not call preventDefault when preventDefault is false', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler, preventDefault: false }]))
    const event = new KeyboardEvent('keydown', { key: 'A', cancelable: true })
    const spy = vi.spyOn(event, 'preventDefault')
    window.dispatchEvent(event)
    expect(spy).not.toHaveBeenCalled()
  })

  it('normalizes Escape key to Esc', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['Esc'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(handler).toHaveBeenCalled()
  })

  it('normalizes Ctrl+Key to Ctrl+UPPERCASE', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['Ctrl+K'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))
    expect(handler).toHaveBeenCalled()
  })

  it('normalizes Meta+Key to ⌘+UPPERCASE', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['⌘+K'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))
    expect(handler).toHaveBeenCalled()
  })

  it('normalizes single character to uppercase', () => {
    const handler = vi.fn()
    renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler }]))
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }))
    expect(handler).toHaveBeenCalled()
  })

  it('removes event listener on unmount', () => {
    const handler = vi.fn()
    const { unmount } = renderHook(() => useKeyboardShortcuts([{ sequence: ['A'], handler }]))
    unmount()
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'A' }))
    expect(handler).not.toHaveBeenCalled()
  })
})
