// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import IdPEditPage from './IdPEditPage'

const mockUpdate = vi.fn()
const mockDelete = vi.fn()
const mockSync = vi.fn()
const mockTestConnection = vi.fn()
const mockNavigate = vi.fn()

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../api/hooks/useIdentityProviders', () => ({
  useIdp: () => ({
    data: {
      alias: 'google',
      display_name: 'Google',
      provider_id: 'google',
      enabled: true,
      config: { clientId: 'cid', issuer: 'https://accounts.google.com' },
    },
    isLoading: false,
    error: null,
  }),
  useUpdateIdp: () => ({ mutateAsync: mockUpdate, isPending: false }),
  useDeleteIdp: () => ({ mutateAsync: mockDelete, isPending: false }),
  useSyncUsers: () => ({ mutateAsync: mockSync, isPending: false }),
  useTestIdpConnection: () => ({ mutateAsync: mockTestConnection, isPending: false }),
  useIdpMappers: () => ({
    data: [{ name: 'email-attr', mapper_type: 'attribute', config: { claim: 'email', attribute: 'external_email' } }],
    isLoading: false,
    error: null,
  }),
  useCreateIdpMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUpdateIdpMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteIdpMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
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
      broker_sync_modes: [
        { id: 'import', name: 'Import', description: 'Map data only on first login' },
      ],
      broker_client_auth_methods: [
        { id: 'client_secret_basic', name: 'Client Secret Basic', description: 'HTTP Basic Authorization header' },
      ],
      idp_mapper_types: [
        { id: 'attribute', name: 'Attribute', description: 'Copy a claim into a user attribute' },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/identity-providers/google']}>
        <Routes>
          <Route path="/admin/identity-providers/:alias" element={<IdPEditPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('IdPEditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('renders the mappers section with existing mappers', () => {
    renderPage()
    expect(screen.getByText('Mappers')).toBeInTheDocument()
    expect(screen.getByText('email-attr')).toBeInTheDocument()
  })

  it('shows a success banner when the connection test passes', async () => {
    mockTestConnection.mockResolvedValue({ status: 'ok', problems: [] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    expect(
      await screen.findByText('Connection test passed — the provider configuration is usable.')
    ).toBeInTheDocument()
    expect(mockTestConnection).toHaveBeenCalledWith({ realm: 'master', alias: 'google' })
  })

  it('shows the problem list when the connection test fails', async () => {
    mockTestConnection.mockResolvedValue({
      status: 'error',
      problems: ['clientSecret is required', 'issuer is required when useDiscovery is enabled'],
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    expect(await screen.findByText('clientSecret is required')).toBeInTheDocument()
    expect(
      screen.getByText('issuer is required when useDiscovery is enabled')
    ).toBeInTheDocument()
  })

  it('shows an error banner when the connection test request itself fails', async () => {
    mockTestConnection.mockRejectedValue(new Error('Forbidden'))
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    expect(await screen.findByText('Forbidden')).toBeInTheDocument()
  })
})
