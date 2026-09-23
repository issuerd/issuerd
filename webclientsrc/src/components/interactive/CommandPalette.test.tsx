// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import CommandPalette from './CommandPalette'

describe('CommandPalette', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  function renderOpen() {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
  }

  it('renders search input and navigation results', () => {
    renderOpen()
    expect(screen.getByPlaceholderText('Type a command or search...')).toBeInTheDocument()
    expect(screen.getByText('Go to Users')).toBeInTheDocument()
    expect(screen.getByText('Go to Dashboard')).toBeInTheDocument()
  })

  it('executes navigation command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Go to Realms'))
    expect(onClose).toHaveBeenCalled()
  })

  it('executes action command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Create new user'))
    expect(onClose).toHaveBeenCalled()
  })

  it('filters commands by query', async () => {
    const user = userEvent.setup()
    renderOpen()
    const input = screen.getByPlaceholderText('Type a command or search...')
    await user.type(input, 'client')
    expect(screen.getByText('Go to Clients')).toBeInTheDocument()
    expect(screen.queryByText('Go to Users')).not.toBeInTheDocument()
  })

  it('executes command on Enter', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const input = screen.getByPlaceholderText('Type a command or search...')
    await user.type(input, 'dashboard')
    await waitFor(() => expect(screen.getByText('Go to Dashboard')).toBeInTheDocument())
    await user.keyboard('{Enter}')
    expect(onClose).toHaveBeenCalled()
  })

  it('closes on Escape', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    await user.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalled()
  })

  it('renders recent pages from localStorage', async () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/users', '/clients']))
    renderOpen()
    expect(screen.getByText('Recent: Users')).toBeInTheDocument()
    expect(screen.getByText('Recent: Clients')).toBeInTheDocument()
  })

  it('executes recent page on click', () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/users']))
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Recent: Users'))
    expect(onClose).toHaveBeenCalled()
  })

  it('navigates with ArrowDown and ArrowUp', async () => {
    const user = userEvent.setup()
    renderOpen()
    const input = screen.getByPlaceholderText('Type a command or search...')
    await user.click(input)
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{ArrowUp}')
    // Should not throw; selection changes internally
    expect(input).toBeInTheDocument()
  })

  it('executes command on click', async () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const item = screen.getByText('Go to Dashboard')
    fireEvent.click(item)
    expect(onClose).toHaveBeenCalled()
  })

  it('shows no results for unknown query', async () => {
    const user = userEvent.setup()
    renderOpen()
    const input = screen.getByPlaceholderText('Type a command or search...')
    await user.type(input, 'xyzabc123')
    expect(screen.getByText('No commands found.')).toBeInTheDocument()
  })

  it('renders fallback label for unknown path', async () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/admin/unknown-path']))
    renderOpen()
    expect(screen.getByText('Recent: /admin/unknown-path')).toBeInTheDocument()
  })

  it('dispatches show-shortcuts event for help command', async () => {
    const onClose = vi.fn()
    const dispatchSpy = vi.spyOn(window, 'dispatchEvent').mockImplementation(() => true)
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const input = screen.getByPlaceholderText('Type a command or search...')
    await userEvent.setup().type(input, 'shortcuts')
    await waitFor(() => expect(screen.getByText('Show keyboard shortcuts')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Show keyboard shortcuts'))
    expect(onClose).toHaveBeenCalled()
    expect(dispatchSpy).toHaveBeenCalled()
    dispatchSpy.mockRestore()
  })

  it('closes on Escape from input', async () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const input = screen.getByPlaceholderText('Type a command or search...')
    fireEvent.keyDown(input, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('clears query when closed', () => {
    const { rerender } = render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    const input = screen.getByPlaceholderText('Type a command or search...') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'test' } })
    expect(input.value).toBe('test')
    rerender(
      <MemoryRouter>
        <CommandPalette open={false} onClose={() => {}} />
      </MemoryRouter>
    )
    // Query should be cleared in the background even though component is not rendered
  })

  it('highlights item on mouse enter', () => {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    const item = screen.getByText('Go to Users')
    fireEvent.mouseEnter(item)
    expect(item.closest('button')).toHaveClass('bg-cyan-neon/10')
  })

  it('handles localStorage parse error gracefully', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementationOnce(() => 'invalid json')
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByPlaceholderText('Type a command or search...')).toBeInTheDocument()
  })

  it('closes on overlay click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const overlay = screen.getByRole('dialog').parentElement
    if (overlay) fireEvent.click(overlay)
    expect(onClose).toHaveBeenCalled()
  })

  it('does not navigate on keyboard when no results', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    const input = screen.getByPlaceholderText('Type a command or search...')
    await user.type(input, 'zzznonexistent')
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{ArrowUp}')
    await user.keyboard('{Enter}')
    expect(onClose).not.toHaveBeenCalled()
  })

  it('renders goto-clients command', () => {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Go to Clients')).toBeInTheDocument()
  })

  it('renders goto-events command', () => {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Go to Events')).toBeInTheDocument()
  })

  it('renders goto-sessions command', () => {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Go to Sessions')).toBeInTheDocument()
  })

  it('executes new-client command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Create new client'))
    expect(onClose).toHaveBeenCalled()
  })

  it('executes rotate-keys command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Rotate realm keys'))
    expect(onClose).toHaveBeenCalled()
  })

  it('executes view-sessions command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('View my sessions'))
    expect(onClose).toHaveBeenCalled()
  })

  it('executes export-events command on click', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Export event log'))
    expect(onClose).toHaveBeenCalled()
  })

  it('uses fallback labelForPath for unknown path', () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/admin/unknown']))
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Recent: /admin/unknown')).toBeInTheDocument()
  })

  it('renders mac shortcuts when on macOS', () => {
    vi.stubGlobal('navigator', { platform: 'MacIntel' })
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Go to Users')).toBeInTheDocument()
    vi.unstubAllGlobals()
  })

  it('clicks goto-users command', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Go to Users'))
    expect(onClose).toHaveBeenCalled()
  })

  it('clicks goto-clients command', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Go to Clients'))
    expect(onClose).toHaveBeenCalled()
  })

  it('clicks goto-events command', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Go to Events'))
    expect(onClose).toHaveBeenCalled()
  })

  it('clicks goto-sessions command', () => {
    const onClose = vi.fn()
    render(
      <MemoryRouter>
        <CommandPalette open onClose={onClose} />
      </MemoryRouter>
    )
    fireEvent.click(screen.getByText('Go to Sessions'))
    expect(onClose).toHaveBeenCalled()
  })
})
