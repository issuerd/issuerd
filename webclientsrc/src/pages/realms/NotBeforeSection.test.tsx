// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import NotBeforeSection from './NotBeforeSection'
import { renderWithProviders } from '../../test/utils'
import type { RealmRepresentation } from '@generated'

const mockUpdateAsync = vi.fn()

vi.mock('../../api/hooks/useRealms', () => ({
  useUpdateRealm: () => ({ mutateAsync: mockUpdateAsync, isPending: false }),
}))

const baseRealm: RealmRepresentation = { realm: 'master', enabled: true }

describe('NotBeforeSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows "Not set" when no cutoff is configured', () => {
    renderWithProviders(<NotBeforeSection realmName="master" realm={baseRealm} />)
    expect(screen.getByTestId('not-before-value')).toHaveTextContent('Not set')
  })

  it('renders the configured cutoff as a timestamp', () => {
    const realm = { ...baseRealm, notBefore: 1700000000 }
    renderWithProviders(<NotBeforeSection realmName="master" realm={realm} />)
    const expected = new Date(1700000000 * 1000).toLocaleString()
    expect(screen.getByTestId('not-before-value')).toHaveTextContent(expected)
  })

  it('sets the cutoff to the current time after confirmation', async () => {
    mockUpdateAsync.mockResolvedValue(undefined)
    renderWithProviders(<NotBeforeSection realmName="master" realm={baseRealm} />)
    fireEvent.click(screen.getByRole('button', { name: /^Set to now$/i }))
    expect(mockUpdateAsync).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Set to now' }))
    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled())
    const call = mockUpdateAsync.mock.calls[0][0]
    expect(call.realm).toBe('master')
    expect(call.body.realm).toBe('master')
    const now = Math.floor(Date.now() / 1000)
    expect(call.body.notBefore).toBeGreaterThanOrEqual(now - 5)
    expect(call.body.notBefore).toBeLessThanOrEqual(now + 5)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('does not update when the confirm dialog is cancelled', async () => {
    renderWithProviders(<NotBeforeSection realmName="master" realm={baseRealm} />)
    fireEvent.click(screen.getByRole('button', { name: /^Set to now$/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockUpdateAsync).not.toHaveBeenCalled()
  })

  it('keeps the modal open when the update fails', async () => {
    mockUpdateAsync.mockRejectedValue(new Error('update failed'))
    renderWithProviders(<NotBeforeSection realmName="master" realm={baseRealm} />)
    fireEvent.click(screen.getByRole('button', { name: /^Set to now$/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Set to now' }))
    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled())
    // The rejection is caught; the dialog stays open so the admin can retry.
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})
