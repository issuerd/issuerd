// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { isMac, formatShortcut, SHORTCUTS } from './keyboardShortcuts'

describe('isMac', () => {
  let originalPlatform: PropertyDescriptor | undefined

  beforeEach(() => {
    originalPlatform = Object.getOwnPropertyDescriptor(navigator, 'platform')
  })

  afterEach(() => {
    if (originalPlatform) {
      Object.defineProperty(navigator, 'platform', originalPlatform)
    } else {
      // @ts-ignore
      delete navigator.platform
    }
  })

  it('returns true on Mac platforms', () => {
    Object.defineProperty(navigator, 'platform', {
      value: 'MacIntel',
      configurable: true,
    })
    expect(isMac()).toBe(true)
  })

  it('returns false on iPhone', () => {
    Object.defineProperty(navigator, 'platform', {
      value: 'iPhone',
      configurable: true,
    })
    expect(isMac()).toBe(false)
  })

  it('returns false on Windows', () => {
    Object.defineProperty(navigator, 'platform', {
      value: 'Win32',
      configurable: true,
    })
    expect(isMac()).toBe(false)
  })

  it('returns false when navigator is undefined', () => {
    const originalNavigator = globalThis.navigator
    // @ts-ignore
    globalThis.navigator = undefined
    expect(isMac()).toBe(false)
    globalThis.navigator = originalNavigator
  })
})

describe('formatShortcut', () => {
  it('uses macKeys on Mac', () => {
    const originalPlatform = navigator.platform
    Object.defineProperty(navigator, 'platform', {
      value: 'MacIntel',
      configurable: true,
    })
    const formatted = formatShortcut({ id: 'test', label: 'Test', category: 'Global', keys: ['Ctrl', 'K'], macKeys: ['⌘', 'K'] })
    expect(formatted).toBe('⌘ K')
    Object.defineProperty(navigator, 'platform', {
      value: originalPlatform,
      configurable: true,
    })
  })

  it('falls back to keys on non-Mac', () => {
    const originalPlatform = navigator.platform
    Object.defineProperty(navigator, 'platform', {
      value: 'Win32',
      configurable: true,
    })
    const formatted = formatShortcut({ id: 'test', label: 'Test', category: 'Global', keys: ['Ctrl', 'K'], macKeys: ['⌘', 'K'] })
    expect(formatted).toBe('Ctrl K')
    Object.defineProperty(navigator, 'platform', {
      value: originalPlatform,
      configurable: true,
    })
  })
})

describe('SHORTCUTS', () => {
  it('contains command palette shortcut', () => {
    expect(SHORTCUTS.some((s) => s.id === 'command-palette')).toBe(true)
  })
})
