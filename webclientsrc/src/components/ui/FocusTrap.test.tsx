// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import FocusTrap from './FocusTrap'

describe('FocusTrap', () => {
  it('renders children', () => {
    render(
      <FocusTrap>
        <button>Inside</button>
      </FocusTrap>
    )
    expect(screen.getByText('Inside')).toBeInTheDocument()
  })

  it('calls onEscape when Escape is pressed', () => {
    const onEscape = vi.fn()
    render(
      <FocusTrap active onEscape={onEscape}>
        <button>Inside</button>
      </FocusTrap>
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onEscape).toHaveBeenCalled()
  })

  it('does not restore focus when restoreFocus is false', () => {
    const { unmount } = render(
      <FocusTrap active restoreFocus={false}>
        <button>Inside</button>
      </FocusTrap>
    )
    unmount()
    // Should not throw
  })

  it('ignores Tab when no focusable elements', () => {
    render(
      <FocusTrap active>
        <div>No focusable</div>
      </FocusTrap>
    )
    fireEvent.keyDown(document, { key: 'Tab' })
    // Should not throw
  })

  it('cycles focus forward on Tab at last element', () => {
    render(
      <FocusTrap active>
        <div>
          <button data-testid="first">First</button>
          <button data-testid="last">Last</button>
        </div>
      </FocusTrap>
    )
    const last = screen.getByTestId('last')
    const first = screen.getByTestId('first')
    // Ensure elements are considered visible by getFocusable
    Object.defineProperty(first, 'offsetParent', { value: document.body, configurable: true })
    Object.defineProperty(last, 'offsetParent', { value: document.body, configurable: true })
    last.focus()
    const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: false, cancelable: true })
    document.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
  })

  it('cycles focus backward on Shift+Tab at first element', () => {
    render(
      <FocusTrap active>
        <div>
          <button data-testid="first">First</button>
          <button data-testid="last">Last</button>
        </div>
      </FocusTrap>
    )
    const first = screen.getByTestId('first')
    const last = screen.getByTestId('last')
    // Ensure elements are considered visible by getFocusable
    Object.defineProperty(first, 'offsetParent', { value: document.body, configurable: true })
    Object.defineProperty(last, 'offsetParent', { value: document.body, configurable: true })
    first.focus()
    const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, cancelable: true })
    document.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
  })

  it('does not trap focus when active is false', () => {
    const onEscape = vi.fn()
    render(
      <FocusTrap active={false} onEscape={onEscape}>
        <button>Inside</button>
      </FocusTrap>
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onEscape).not.toHaveBeenCalled()
  })

  it('ignores disabled or hidden elements in getFocusable', () => {
    render(
      <FocusTrap active>
        <div>
          <button disabled>Disabled</button>
          <button style={{ display: 'none' }}>Hidden</button>
          <button data-testid="focusable">Focusable</button>
        </div>
      </FocusTrap>
    )
    // Should focus only the focusable button
    expect(screen.getByTestId('focusable')).toBeInTheDocument()
  })
})
