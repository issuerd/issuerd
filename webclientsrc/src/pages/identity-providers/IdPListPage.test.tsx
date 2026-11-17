// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import IdPListPage from './IdPListPage'
import { renderWithProviders } from '../../test/utils'
import type { IdentityProviderRepresentation } from '@generated'

const mockCreate = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

const idps: IdentityProviderRepresentation[] = [
  {
    alias: 'google',
    display_name: 'Google',
    provider_id: 'google',
    enabled: true,
    config: {},
  },
  {
    alias: 'corporate-ldap',
    display_name: 'Corporate LDAP',
    provider_id: 'ldap',
    enabled: false,
    config: {},
  },
]

let mockIdpsState: {
  data: IdentityProviderRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: idps, isLoading: false, error: null }

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: (state: { currentRealm: string }) => unknown) =>
    selector({ currentRealm: 'master' }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../api/hooks/useIdentityProviders', () => ({
  useIdps: () => mockIdpsState,
  useCreateIdp: () => ({ mutateAsync: mockCreate, isPending: false }),
  useDeleteIdp: () => ({
    mutateAsync: mockDelete,
    mutate: mockDelete,
    isPending: false,
  }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      provider_ids: [
        { id: 'ldap', name: 'LDAP', description: 'User federation via LDAP' },
        { id: 'google', name: 'Google', description: 'Google social login' },
      ],
      identity_provider_presets: [
        {
          provider_id: 'google',
          display_name: 'Google',
          config: { issuer: 'https://accounts.google.com' },
        },
      ],
    },
    isLoading: false,
    error: null,
  }),
}))

describe('IdPListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockIdpsState = { data: idps, isLoading: false, error: null }
    mockCreate.mockResolvedValue(undefined)
  })

  it('shows a loader while identity providers are loading', () => {
    mockIdpsState = { data: [], isLoading: true, error: null }
    renderWithProviders(<IdPListPage />)

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when there are no identity providers', () => {
    mockIdpsState = { data: [], isLoading: false, error: null }
    renderWithProviders(<IdPListPage />)

    expect(screen.getByText('No identity providers')).toBeInTheDocument()
    expect(screen.getByText('Add an identity provider to get started.')).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockIdpsState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load identity providers'),
    }
    renderWithProviders(<IdPListPage />)

    expect(screen.getByText('Could not load identity providers')).toBeInTheDocument()
  })

  it('renders provider details and status badges', () => {
    renderWithProviders(<IdPListPage />)

    expect(screen.getByText('google')).toBeInTheDocument()
    expect(screen.getByText('Corporate LDAP')).toBeInTheDocument()
    expect(screen.getAllByText('Google')).toHaveLength(2)
    expect(screen.getByText('LDAP')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('inactive')).toBeInTheDocument()
  })

  it('navigates to the provider editor on row click', () => {
    renderWithProviders(<IdPListPage />)

    fireEvent.click(screen.getByText('corporate-ldap'))

    expect(mockNavigate).toHaveBeenCalledWith('/identity-providers/corporate-ldap')
  })

  it('creates an identity provider through the modal form', async () => {
    renderWithProviders(<IdPListPage />)

    fireEvent.click(screen.getByRole('button', { name: /Add Provider/ }))
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'new-ldap' } })
    fireEvent.change(screen.getByLabelText('Display Name'), {
      target: { value: 'New LDAP' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith({
        realm: 'master',
        body: {
          alias: 'new-ldap',
          display_name: 'New LDAP',
          provider_id: 'ldap',
          enabled: true,
          config: {},
        },
      }),
    )
  })
})
