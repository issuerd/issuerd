// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import EventsConfigSection from './EventsConfigSection'
import { renderWithProviders } from '../../test/utils'

const mockConfig = {
  eventsEnabled: true,
  eventsExpiration: 7200,
  adminEventsEnabled: false,
  adminEventsDetailsEnabled: false,
  eventsListeners: ['logging'],
}

const mockUpdateAsync = vi.fn()
const mockClearEventsAsync = vi.fn()
const mockClearAdminEventsAsync = vi.fn()

let mockConfigState: { data: unknown; isLoading: boolean; error: Error | null }

vi.mock('../../api/hooks/useEventsConfig', () => ({
  useEventsConfig: () => mockConfigState,
  useUpdateEventsConfig: () => ({ mutateAsync: mockUpdateAsync, isPending: false }),
  useClearEvents: () => ({ mutateAsync: mockClearEventsAsync, isPending: false }),
  useClearAdminEvents: () => ({ mutateAsync: mockClearAdminEventsAsync, isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      event_listeners: [
        { id: 'logging', name: 'Logging', description: 'Writes events to the server log' },
        { id: 'metrics', name: 'Metrics', description: 'Publishes events as metrics' },
      ],
    },
    isLoading: false,
  }),
}))

describe('EventsConfigSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockConfigState = { data: mockConfig, isLoading: false, error: null }
  })

  it('renders the current configuration', () => {
    renderWithProviders(<EventsConfigSection realm="master" />)
    expect(screen.getByText('Event Recording')).toBeInTheDocument()
    expect(screen.getByLabelText('Events enabled')).toBeChecked()
    expect(screen.getByLabelText('Admin events enabled')).not.toBeChecked()
    expect(screen.getByLabelText('Events expiration (seconds)')).toHaveValue(7200)
    expect(screen.getByRole('checkbox', { name: /Logging/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Metrics/ })).not.toBeChecked()
  })

  it('surfaces listener descriptions as subtitle and tooltip', () => {
    renderWithProviders(<EventsConfigSection realm="master" />)
    const checkbox = screen.getByRole('checkbox', { name: /Metrics/ })
    const label = checkbox.closest('label')!
    expect(label).toHaveAttribute('title', 'Publishes events as metrics')
    expect(within(label).getByText('Publishes events as metrics')).toBeInTheDocument()
  })

  it('disables the details switch until admin events are enabled', () => {
    renderWithProviders(<EventsConfigSection realm="master" />)
    expect(screen.getByLabelText('Include representations')).toBeDisabled()
    fireEvent.click(screen.getByLabelText('Admin events enabled'))
    expect(screen.getByLabelText('Include representations')).not.toBeDisabled()
  })

  it('keeps Save disabled until something changes', () => {
    renderWithProviders(<EventsConfigSection realm="master" />)
    expect(screen.getByRole('button', { name: /^Save$/ })).toBeDisabled()
    fireEvent.click(screen.getByLabelText('Events enabled'))
    expect(screen.getByRole('button', { name: /^Save$/ })).not.toBeDisabled()
  })

  it('saves the full config shape', async () => {
    mockUpdateAsync.mockResolvedValue(undefined)
    renderWithProviders(<EventsConfigSection realm="master" />)
    fireEvent.click(screen.getByLabelText('Admin events enabled'))
    fireEvent.click(screen.getByLabelText('Include representations'))
    fireEvent.change(screen.getByLabelText('Events expiration (seconds)'), {
      target: { value: '3600' },
    })
    fireEvent.click(screen.getByRole('checkbox', { name: /Metrics/ }))
    fireEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled())
    expect(mockUpdateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: {
        eventsEnabled: true,
        eventsExpiration: 3600,
        adminEventsEnabled: true,
        adminEventsDetailsEnabled: true,
        eventsListeners: ['logging', 'metrics'],
      },
    })
  })

  it('shows the server error inline when saving fails', async () => {
    mockUpdateAsync.mockRejectedValue(new Error('config rejected'))
    renderWithProviders(<EventsConfigSection realm="master" />)
    fireEvent.click(screen.getByLabelText('Events enabled'))
    fireEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    expect(await screen.findByText('config rejected')).toBeInTheDocument()
  })

  it('clears events only after confirmation', async () => {
    mockClearEventsAsync.mockResolvedValue(undefined)
    renderWithProviders(<EventsConfigSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /Clear events/i }))
    expect(mockClearEventsAsync).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/Delete all stored events/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Clear' }))
    await waitFor(() => expect(mockClearEventsAsync).toHaveBeenCalledWith('master'))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('clears admin events only after confirmation', async () => {
    mockClearAdminEventsAsync.mockResolvedValue(undefined)
    renderWithProviders(<EventsConfigSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /Clear admin events/i }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/Delete all stored admin events/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Clear' }))
    await waitFor(() => expect(mockClearAdminEventsAsync).toHaveBeenCalledWith('master'))
  })

  it('does not clear when the confirm dialog is cancelled', async () => {
    renderWithProviders(<EventsConfigSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /Clear events/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockClearEventsAsync).not.toHaveBeenCalled()
  })

  it('shows a spinner while loading', () => {
    mockConfigState = { data: null, isLoading: true, error: null }
    renderWithProviders(<EventsConfigSection realm="master" />)
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows an error message when loading fails', () => {
    mockConfigState = { data: null, isLoading: false, error: new Error('load failed') }
    renderWithProviders(<EventsConfigSection realm="master" />)
    expect(screen.getByText(/load failed/i)).toBeInTheDocument()
  })
})
