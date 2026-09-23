// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import Drawer from './Drawer'

describe('Drawer', () => {
  it('renders when open', () => {
    render(
      <Drawer open onClose={() => {}} title="Test">
        <div data-testid="content">Content</div>
      </Drawer>
    )
    expect(screen.getByText('Test')).toBeInTheDocument()
    expect(screen.getByTestId('content')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    render(
      <Drawer open={false} onClose={() => {}}>
        <div data-testid="content">Content</div>
      </Drawer>
    )
    expect(screen.queryByTestId('content')).not.toBeInTheDocument()
  })

  it('calls onClose when close button clicked', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose} title="Test" showClose>
        Content
      </Drawer>
    )
    fireEvent.click(screen.getByLabelText('Close drawer'))
    expect(onClose).toHaveBeenCalled()
  })


  it('calls onClose on Escape', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose}>
        Content
      </Drawer>
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('calls onClose when overlay is clicked', () => {
    const onClose = vi.fn()
    render(
      <Drawer open onClose={onClose} title="Test">
        <div data-testid="content">Content</div>
      </Drawer>
    )
    const overlay = screen.getByRole('dialog').firstElementChild
    if (overlay) fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalled()
  })

  it('closes and reopens correctly', async () => {
    const { rerender } = render(
      <Drawer open onClose={() => {}} title="Test">
        <div data-testid="content">Content</div>
      </Drawer>
    )
    expect(screen.getByTestId('content')).toBeInTheDocument()
    rerender(
      <Drawer open={false} onClose={() => {}} title="Test">
        <div data-testid="content">Content</div>
      </Drawer>
    )
    await waitFor(() => expect(screen.queryByTestId('content')).not.toBeInTheDocument())
    rerender(
      <Drawer open onClose={() => {}} title="Test">
        <div data-testid="content">Content</div>
      </Drawer>
    )
    expect(screen.getByTestId('content')).toBeInTheDocument()
  })
})
