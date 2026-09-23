// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ClientScopeDetailPage from './ClientScopeDetailPage'

const mockUpdate = vi.fn()
const mockDelete = vi.fn()
const mockCreateMapper = vi.fn()
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
  useClientScope: () => ({
    data: { id: 's1', name: 'profile', description: 'Profile claims', protocol: 'openid-connect' },
    isLoading: false,
    error: null,
  }),
  useUpdateClientScope: () => ({ mutateAsync: mockUpdate, isPending: false }),
  useDeleteClientScope: () => ({ mutateAsync: mockDelete, isPending: false }),
  useScopeMappers: () => ({
    data: [
      {
        id: 'm1',
        name: 'department',
        protocol_mapper: 'oidc-usermodel-attribute-mapper',
        config: { 'claim.name': 'department_claim' },
      },
    ],
    isLoading: false,
    error: null,
  }),
  useCreateScopeMapper: () => ({ mutateAsync: mockCreateMapper, isPending: false }),
  useUpdateScopeMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteScopeMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      protocols: [{ id: 'openid-connect', name: 'OpenID Connect', description: 'OIDC protocol' }],
      mapper_types: [
        { id: 'oidc-usermodel-attribute-mapper', name: 'User Attribute', description: 'Map a user attribute' },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/client-scopes/s1']}>
        <Routes>
          <Route path="/admin/client-scopes/:id" element={<ClientScopeDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ClientScopeDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the settings tab with the scope form', () => {
    renderPage()
    const nameInput = screen.getByLabelText('Name') as HTMLInputElement
    expect(nameInput.value).toBe('profile')
    expect(nameInput).toBeDisabled()
    expect((screen.getByLabelText('Description') as HTMLInputElement).value).toBe('Profile claims')
  })

  it('updates the scope settings', async () => {
    mockUpdate.mockResolvedValue(undefined)
    renderPage()
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Updated' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][0].body.description).toBe('Updated')
  })

  it('lists mappers on the mappers tab via the shared editor', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Mappers' }))
    expect(screen.getByText('department')).toBeInTheDocument()
    // EnumBadge resolves the mapper type label from serverInfo
    expect(screen.getByText('User Attribute')).toBeInTheDocument()
  })

  it('creates a mapper on the mappers tab', async () => {
    const user = userEvent.setup()
    mockCreateMapper.mockResolvedValue({ id: 'm2' })
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Mappers' }))
    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new-mapper' } })
    fireEvent.click(screen.getByText('Select mapper type'))
    fireEvent.click(screen.getByRole('option', { name: /User Attribute/ }))
    fireEvent.change(screen.getByLabelText('User Attribute'), { target: { value: 'department' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockCreateMapper).toHaveBeenCalled())
    const vars = mockCreateMapper.mock.calls[0][0]
    expect(vars.scopeId).toBe('s1')
    expect(vars.body.name).toBe('new-mapper')
    expect(vars.body.config['user.attribute']).toBe('department')
  })

  it('deletes the scope and navigates back', async () => {
    mockDelete.mockResolvedValue(undefined)
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith({ realm: 'master', id: 's1' }))
    expect(mockNavigate).toHaveBeenCalledWith('/client-scopes')
  })
})
