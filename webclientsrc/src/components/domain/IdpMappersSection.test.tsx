// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import IdpMappersSection from './IdpMappersSection'
import type { IdpMapper } from '@generated'

const mockCreate = vi.fn()
const mockUpdate = vi.fn()
const mockDelete = vi.fn()

let mockMappersState: { data: IdpMapper[] | undefined; isLoading: boolean; error: Error | null }

vi.mock('../../api/hooks/useIdentityProviders', () => ({
  useIdpMappers: () => mockMappersState,
  useCreateIdpMapper: () => ({ mutateAsync: mockCreate, isPending: false }),
  useUpdateIdpMapper: () => ({ mutateAsync: mockUpdate, isPending: false }),
  useDeleteIdpMapper: () => ({ mutateAsync: mockDelete, isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      idp_mapper_types: [
        { id: 'attribute', name: 'Attribute', description: 'Copy a claim into a user attribute' },
        { id: 'role', name: 'Role', description: 'Grant a realm role when a claim matches' },
        { id: 'username_template', name: 'Username Template', description: 'Derive the username from a template' },
      ],
    },
    isLoading: false,
  }),
}))

const attributeMapper: IdpMapper = {
  name: 'email-attr',
  mapper_type: 'attribute',
  config: { claim: 'email', attribute: 'external_email' },
}

describe('IdpMappersSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockMappersState = { data: [], isLoading: false, error: null }
    mockCreate.mockResolvedValue({})
    mockUpdate.mockResolvedValue(undefined)
    mockDelete.mockResolvedValue(undefined)
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })

  it('shows an empty state when no mappers are configured', () => {
    render(<IdpMappersSection realm="master" alias="google" />)
    expect(screen.getByText('No mappers configured for this provider.')).toBeInTheDocument()
  })

  it('renders a row per mapper with its type badge', () => {
    mockMappersState = { data: [attributeMapper], isLoading: false, error: null }
    render(<IdpMappersSection realm="master" alias="google" />)
    expect(screen.getByText('email-attr')).toBeInTheDocument()
    expect(screen.getByText('Attribute')).toBeInTheDocument()
  })

  it('creates a mapper via the dialog with type-specific config fields', async () => {
    render(<IdpMappersSection realm="master" alias="google" />)

    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'email-attr' } })

    // Mapper type options come from serverinfo, descriptions included
    fireEvent.click(screen.getByLabelText('Mapper Type'))
    expect(screen.getByText('Copy a claim into a user attribute')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('option', { name: /Attribute/ }))

    fireEvent.change(screen.getByLabelText('Claim'), { target: { value: 'email' } })
    fireEvent.change(screen.getByLabelText('User Attribute'), { target: { value: 'external_email' } })

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith({
        realm: 'master',
        alias: 'google',
        body: {
          name: 'email-attr',
          mapper_type: 'attribute',
          config: { claim: 'email', attribute: 'external_email' },
        },
      })
    )
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    )
  })

  it('edits an existing mapper with prefilled fields and a locked name', async () => {
    mockMappersState = { data: [attributeMapper], isLoading: false, error: null }
    render(<IdpMappersSection realm="master" alias="google" />)

    fireEvent.click(screen.getByLabelText('Edit mapper email-attr'))

    expect(screen.getByLabelText('Name')).toHaveValue('email-attr')
    expect(screen.getByLabelText('Name')).toBeDisabled()
    expect(screen.getByLabelText('Claim')).toHaveValue('email')

    fireEvent.change(screen.getByLabelText('Claim'), { target: { value: 'mail' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockUpdate).toHaveBeenCalledWith({
        realm: 'master',
        alias: 'google',
        name: 'email-attr',
        body: {
          name: 'email-attr',
          mapper_type: 'attribute',
          config: { claim: 'mail', attribute: 'external_email' },
        },
      })
    )
  })

  it('shows the template field for username_template mappers', () => {
    render(<IdpMappersSection realm="master" alias="google" />)

    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.click(screen.getByLabelText('Mapper Type'))
    fireEvent.click(screen.getByRole('option', { name: /Username Template/ }))

    expect(screen.getByLabelText('Template')).toBeInTheDocument()
    expect(screen.getByText(/\$\{ALIAS\} expands to the provider alias/)).toBeInTheDocument()
  })

  it('deletes a mapper after confirmation', async () => {
    mockMappersState = { data: [attributeMapper], isLoading: false, error: null }
    render(<IdpMappersSection realm="master" alias="google" />)

    fireEvent.click(screen.getByLabelText('Delete mapper email-attr'))

    await waitFor(() =>
      expect(mockDelete).toHaveBeenCalledWith({ realm: 'master', alias: 'google', name: 'email-attr' })
    )
  })

  it('does not delete when confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    mockMappersState = { data: [attributeMapper], isLoading: false, error: null }
    render(<IdpMappersSection realm="master" alias="google" />)

    fireEvent.click(screen.getByLabelText('Delete mapper email-attr'))

    expect(mockDelete).not.toHaveBeenCalled()
  })
})
