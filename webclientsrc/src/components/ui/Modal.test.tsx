// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import Modal from './Modal'

const originalActiveElementGetter = Object.getOwnPropertyDescriptor(
  HTMLDocument.prototype,
  'activeElement'
)?.get

function withActiveElement(element: Element, fn: () => void) {
  if (!originalActiveElementGetter) {
    fn()
    return
  }
  Object.defineProperty(HTMLDocument.prototype, 'activeElement', {
    get() {
      return element
    },
    configurable: true,
  })
  try {
    fn()
  } finally {
    Object.defineProperty(HTMLDocument.prototype, 'activeElement', {
      get: originalActiveElementGetter,
      configurable: true,
    })
  }
}

describe('Modal', () => {
  it('renders when open', () => {
    render(
      <Modal open title="Test" onClose={() => {}}>
        <div data-testid="content">Content</div>
      </Modal>
    )
    expect(screen.getByText('Test')).toBeInTheDocument()
    expect(screen.getByTestId('content')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    render(
      <Modal open={false} title="Test" onClose={() => {}}>
        <div data-testid="content">Content</div>
      </Modal>
    )
    expect(screen.queryByTestId('content')).not.toBeInTheDocument()
  })

  it('calls onClose when close button clicked', () => {
    const onClose = vi.fn()
    render(
      <Modal open title="Test" onClose={onClose}>
        Content
      </Modal>
    )
    fireEvent.click(screen.getByLabelText('Close'))
    expect(onClose).toHaveBeenCalled()
  })

  it('calls onClose on Escape', () => {
    const onClose = vi.fn()
    render(
      <Modal open title="Test" onClose={onClose}>
        Content
      </Modal>
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('renders footer', () => {
    render(
      <Modal open title="Test" onClose={() => {}} footer={<button>Action</button>}>
        Content
      </Modal>
    )
    expect(screen.getByText('Action')).toBeInTheDocument()
  })

  it('does not throw when empty content', () => {
    const onClose = vi.fn()
    render(
      <Modal open title="Test" onClose={onClose}>
        <div>Content</div>
      </Modal>
    )
    fireEvent.keyDown(document, { key: 'Tab' })
    // Should not throw
  })

  it('calls onClose when overlay is clicked', () => {
    const onClose = vi.fn()
    render(
      <Modal open title="Test" onClose={onClose}>
        Content
      </Modal>
    )
    const overlay = screen.getByRole('dialog').parentElement
    expect(overlay).toBeInTheDocument()
    if (overlay) fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalled()
  })

  it('sets body overflow to hidden when open', () => {
    document.body.style.overflow = ''
    render(
      <Modal open title="Test" onClose={() => {}}>
        Content
      </Modal>
    )
    expect(document.body.style.overflow).toBe('hidden')
  })

  it('traps Tab focus within modal', () => {
    render(
      <Modal open title="Test" onClose={() => {}}>
        <div>
          <button data-testid="first">First</button>
          <button data-testid="last">Last</button>
        </div>
      </Modal>
    )
    const last = screen.getByTestId('last')
    const first = screen.getByTestId('first')
    ;[last, first].forEach((el) => {
      Object.defineProperty(el, 'offsetParent', { value: document.body, configurable: true })
    })
    withActiveElement(last, () => {
      const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: false, cancelable: true })
      document.dispatchEvent(event)
      expect(event.defaultPrevented).toBe(true)
    })
  })

  it('cycles to last element on Shift+Tab from first', () => {
    render(
      <Modal open title="Test" onClose={() => {}}>
        <div>
          <button data-testid="first">First</button>
          <button data-testid="last">Last</button>
        </div>
      </Modal>
    )
    const first = screen.getByTestId('first')
    const last = screen.getByTestId('last')
    ;[last, first].forEach((el) => {
      Object.defineProperty(el, 'offsetParent', { value: document.body, configurable: true })
    })
    withActiveElement(first, () => {
      const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, cancelable: true })
      document.dispatchEvent(event)
      expect(event.defaultPrevented).toBe(true)
    })
  })

  it('does not throw when no focusable elements', () => {
    render(
      <Modal open title="Test" onClose={() => {}}>
        <div>No focusable</div>
      </Modal>
    )
    fireEvent.keyDown(document, { key: 'Tab' })
    // Should not throw
  })

  it('restores focus on close', () => {
    const trigger = document.createElement('button')
    document.body.appendChild(trigger)
    trigger.focus()
    const { rerender } = render(
      <Modal open title="Test" onClose={() => {}}>
        <button>Inside</button>
      </Modal>
    )
    rerender(
      <Modal open={false} title="Test" onClose={() => {}}>
        <button>Inside</button>
      </Modal>
    )
    expect(document.activeElement).toBe(trigger)
    document.body.removeChild(trigger)
  })
})
