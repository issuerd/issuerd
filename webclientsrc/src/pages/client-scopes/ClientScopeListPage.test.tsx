// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ClientScopeListPage from './ClientScopeListPage'
import type { ClientScopeRepresentation } from '@generated'

const mockCreate = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

const scopes: ClientScopeRepresentation[] = [
  { id: 's1', name: 'profile', description: 'Profile claims', protocol: 'openid-connect' },
  { id: 's2', name: 'custom', description: null, protocol: 'openid-connect' },
]

let mockScopesState: {
  data: ClientScopeRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: scopes, isLoading: false, error: null }

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

vi.mock('../../api/hooks/useClientScopes', () => ({
  useClientScopes: () => mockScopesState,
  useCreateClientScope: () => ({ mutateAsync: mockCreate, isPending: false }),
  useDeleteClientScope: () => ({
    mutateAsync: mockDelete,
    mutate: mockDelete,
    isPending: false,
  }),
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
    </QueryClientProvider>,
  )
}

describe('ClientScopeListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockScopesState = { data: scopes, isLoading: false, error: null }
    mockCreate.mockResolvedValue({ id: 's3' })
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
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Client Scope/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new-scope' } })
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'My scope' } })

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

  it('shows a loader while client scopes are loading', () => {
    mockScopesState = { data: [], isLoading: true, error: null }
    renderPage()

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when there are no client scopes', () => {
    mockScopesState = { data: [], isLoading: false, error: null }
    renderPage()

    expect(screen.getByText('No client scopes')).toBeInTheDocument()
    expect(
      screen.getByText('Create a client scope to bundle protocol mappers.'),
    ).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockScopesState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load client scopes'),
    }
    renderPage()

    expect(screen.getByText('Could not load client scopes')).toBeInTheDocument()
  })

  it('bulk deletes selected scopes after confirmation', () => {
    window.confirm = vi.fn(() => true)
    renderPage()

    fireEvent.click(screen.getByLabelText('Select row s1'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    expect(mockDelete).toHaveBeenCalledWith({ realm: 'master', id: 's1' })
  })

  it('closes the create modal through both close actions', async () => {
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Client Scope/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Create Client Scope/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})
