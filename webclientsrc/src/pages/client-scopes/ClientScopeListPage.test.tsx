// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ClientScopeListPage from './ClientScopeListPage'

const mockCreate = vi.fn()
const mockDelete = vi.fn()
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

vi.mock('../../api/hooks/useClientScopes', () => ({
  useClientScopes: () => ({
    data: [
      { id: 's1', name: 'profile', description: 'Profile claims', protocol: 'openid-connect' },
      { id: 's2', name: 'custom', description: null, protocol: 'openid-connect' },
    ],
    isLoading: false,
    error: null,
  }),
  useCreateClientScope: () => ({ mutateAsync: mockCreate, isPending: false }),
  useDeleteClientScope: () => ({ mutateAsync: mockDelete, mutate: mockDelete, isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      protocols: [
        { id: 'openid-connect', name: 'OpenID Connect', description: 'OIDC protocol' },
        { id: 'saml', name: 'SAML', description: 'SAML 2.0 protocol' },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ClientScopeListPage />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ClientScopeListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists client scopes with dynamic protocol badges', () => {
    renderPage()
    expect(screen.getByText('profile')).toBeInTheDocument()
    expect(screen.getByText('custom')).toBeInTheDocument()
    expect(screen.getByText('Profile claims')).toBeInTheDocument()
    expect(screen.getAllByText('OpenID Connect').length).toBeGreaterThan(0)
  })

  it('navigates to the detail page on row click', async () => {
    renderPage()
    fireEvent.click(screen.getByText('profile'))
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/client-scopes/s1'))
  })

  it('creates a client scope via the modal form', async () => {
    mockCreate.mockResolvedValue({ id: 's3' })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Client Scope/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new-scope' } })
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'My scope' } })

    // protocol dropdown is dynamic from serverInfo, descriptions surfaced
    fireEvent.click(screen.getByLabelText('Protocol'))
    expect(screen.getByText('SAML 2.0 protocol')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('option', { name: /SAML/ }))

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCreate).toHaveBeenCalled())
    expect(mockCreate.mock.calls[0][0]).toEqual({
      realm: 'master',
      body: { name: 'new-scope', description: 'My scope', protocol: 'saml' },
    })
  })
})
