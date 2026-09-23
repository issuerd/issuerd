// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ShortcutsHelpModal from './ShortcutsHelpModal'

describe('ShortcutsHelpModal', () => {
  it('renders shortcut categories when open', () => {
    render(<ShortcutsHelpModal open onClose={() => {}} />)
    expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument()
    expect(screen.getByText('Navigation')).toBeInTheDocument()
    expect(screen.getByText('Global')).toBeInTheDocument()
    expect(screen.getByText('Open command palette')).toBeInTheDocument()
  })

  it('filters shortcuts by search', async () => {
    const user = userEvent.setup()
    render(<ShortcutsHelpModal open onClose={() => {}} />)
    const input = screen.getByPlaceholderText('Search shortcuts...')
    await user.type(input, 'palette')
    expect(screen.getByText('Open command palette')).toBeInTheDocument()
    expect(screen.queryByText('Go to Users')).not.toBeInTheDocument()
  })

  it('calls onClose when close button clicked', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<ShortcutsHelpModal open onClose={onClose} />)
    await user.click(screen.getByLabelText('Close'))
    expect(onClose).toHaveBeenCalled()
  })

  it('calls onClose when overlay is clicked', async () => {
    const onClose = vi.fn()
    render(<ShortcutsHelpModal open onClose={onClose} />)
    const overlay = screen.getByRole('dialog').parentElement
    if (overlay) fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalled()
  })

  it('shows empty state when search has no matches', async () => {
    const user = userEvent.setup()
    render(<ShortcutsHelpModal open onClose={() => {}} />)
    const input = screen.getByPlaceholderText('Search shortcuts...')
    await user.type(input, 'zzznonexistent')
    expect(screen.getByText('No shortcuts match your search.')).toBeInTheDocument()
  })

  it('clears filter when reopened', () => {
    const { rerender } = render(<ShortcutsHelpModal open onClose={() => {}} />)
    const input = screen.getByPlaceholderText('Search shortcuts...') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'test' } })
    expect(input.value).toBe('test')
    rerender(<ShortcutsHelpModal open={false} onClose={() => {}} />)
    rerender(<ShortcutsHelpModal open onClose={() => {}} />)
    expect((screen.getByPlaceholderText('Search shortcuts...') as HTMLInputElement).value).toBe('')
  })
})
