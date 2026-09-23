// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import PartialImportSection from './PartialImportSection'
import { renderWithProviders } from '../../test/utils'

const mockImportAsync = vi.fn()

vi.mock('../../api/hooks/useRealmAdminActions', () => ({
  usePartialImport: () => ({ mutateAsync: mockImportAsync, isPending: false }),
}))

describe('PartialImportSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the form controls', () => {
    renderWithProviders(<PartialImportSection realm="master" />)
    expect(screen.getByText('Partial Import')).toBeInTheDocument()
    expect(screen.getByLabelText('Realm partial JSON')).toBeInTheDocument()
    expect(screen.getByLabelText('Load from file')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'If a resource exists' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Import$/ })).toBeDisabled()
  })

  it('offers the three conflict strategies with descriptions', async () => {
    renderWithProviders(<PartialImportSection realm="master" />)
    fireEvent.click(screen.getByRole('button', { name: 'If a resource exists' }))
    for (const name of [/Fail/, /Skip/, /Overwrite/]) {
      expect(await screen.findByRole('option', { name })).toBeInTheDocument()
    }
    expect(
      screen.getByRole('option', { name: /Overwrite/ })
    ).toHaveAttribute('title', 'Replace existing resources with the imported ones')
  })

  it('submits the parsed document with the selected strategy', async () => {
    mockImportAsync.mockResolvedValue({ added: 1, skipped: 0, updated: 0, results: [] })
    renderWithProviders(<PartialImportSection realm="master" />)
    fireEvent.change(screen.getByLabelText('Realm partial JSON'), {
      target: { value: '{"users":[{"username":"alice"}]}' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'If a resource exists' }))
    fireEvent.click(await screen.findByRole('option', { name: /Skip/ }))
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    await waitFor(() => expect(mockImportAsync).toHaveBeenCalled())
    expect(mockImportAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: { users: [{ username: 'alice' }] },
      ifResourceExists: 'SKIP',
    })
  })

  it('renders the result summary and per-resource outcomes', async () => {
    mockImportAsync.mockResolvedValue({
      added: 1,
      skipped: 1,
      updated: 1,
      results: [
        { resourceType: 'USER', resourceName: 'alice', action: 'added' },
        { resourceType: 'CLIENT', resourceName: 'app', action: 'skipped' },
        { resourceType: 'GROUP', resourceName: 'devs', action: 'updated' },
      ],
    })
    renderWithProviders(<PartialImportSection realm="master" />)
    fireEvent.change(screen.getByLabelText('Realm partial JSON'), {
      target: { value: '{"groups":[{"name":"devs"}]}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    const result = await screen.findByTestId('partial-import-result')
    expect(result).toHaveTextContent('1 added')
    expect(result).toHaveTextContent('1 skipped')
    expect(result).toHaveTextContent('1 updated')
    expect(result).toHaveTextContent('USER')
    expect(result).toHaveTextContent('alice')
    expect(result).toHaveTextContent('skipped')
    expect(result).toHaveTextContent('updated')
  })

  it('shows an error for invalid JSON without calling the API', async () => {
    renderWithProviders(<PartialImportSection realm="master" />)
    fireEvent.change(screen.getByLabelText('Realm partial JSON'), {
      target: { value: '{not json' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    expect(await screen.findByText(/Invalid JSON/)).toBeInTheDocument()
    expect(mockImportAsync).not.toHaveBeenCalled()
  })

  it('shows the server error inline when the import fails', async () => {
    mockImportAsync.mockRejectedValue(new Error('user alice already exists'))
    renderWithProviders(<PartialImportSection realm="master" />)
    fireEvent.change(screen.getByLabelText('Realm partial JSON'), {
      target: { value: '{"users":[{"username":"alice"}]}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    expect(await screen.findByText('user alice already exists')).toBeInTheDocument()
  })
})
