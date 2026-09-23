// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import RealmActionsSection from './RealmActionsSection'
import { renderWithProviders } from '../../test/utils'

const mockExportAsync = vi.fn()
const mockPushAsync = vi.fn()

vi.mock('../../api/hooks/useRealmAdminActions', () => ({
  useExportRealm: () => ({ mutateAsync: mockExportAsync, isPending: false }),
  usePushRevocation: () => ({ mutateAsync: mockPushAsync, isPending: false }),
}))

describe('RealmActionsSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders export and push sections', () => {
    renderWithProviders(<RealmActionsSection realm="master" />)
    expect(screen.getByRole('button', { name: /^Export realm$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Push revocation$/i })).toBeInTheDocument()
  })

  it('opens a modal with the pretty-printed export document', async () => {
    mockExportAsync.mockResolvedValue({ realm: 'master', users: [{ username: 'alice' }] })
    renderWithProviders(<RealmActionsSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /^Export realm$/i }))
    await waitFor(() => expect(mockExportAsync).toHaveBeenCalledWith('master'))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/Realm export/)).toBeInTheDocument()
    // Pretty-printed JSON: two-space indentation of the nested username field.
    const pre = dialog.querySelector('pre')!
    expect(pre.textContent).toContain('"realm": "master"')
    expect(pre.textContent).toContain('  "username": "alice"')
    // Copy and download affordances.
    expect(within(dialog).getByRole('button', { name: /Copy to clipboard/i })).toBeInTheDocument()
    const download = within(dialog).getByRole('link')
    expect(download).toHaveAttribute('download', 'master-export.json')
    expect(download.getAttribute('href')).toContain('data:application/json,')
  })

  it('shows the error inline when export fails', async () => {
    mockExportAsync.mockRejectedValue(new Error('export denied'))
    renderWithProviders(<RealmActionsSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /^Export realm$/i }))
    expect(await screen.findByText('export denied')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('pushes revocation only after confirmation', async () => {
    mockPushAsync.mockResolvedValue(undefined)
    renderWithProviders(<RealmActionsSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /^Push revocation$/i }))
    expect(mockPushAsync).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Push' }))
    await waitFor(() => expect(mockPushAsync).toHaveBeenCalledWith('master'))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('does not push when the confirm dialog is cancelled', async () => {
    renderWithProviders(<RealmActionsSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: /^Push revocation$/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockPushAsync).not.toHaveBeenCalled()
  })
})
