// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import GroupEditPage from './GroupEditPage'

const mockRemoveRealmRoles = vi.fn()
const mockCreateChildGroup = vi.fn()
const mockMoveGroup = vi.fn()

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('../../api/hooks/useGroups', () => ({
  useGroup: () => ({
    data: { id: 'g1', name: 'developers', path: '/developers', parent_id: 'g3' },
    isLoading: false,
    error: null,
  }),
  useGroups: () => ({
    data: [
      { id: 'g1', name: 'developers', path: '/developers', parent_id: 'g3' },
      { id: 'g2', name: 'backend', path: '/developers/backend', parent_id: 'g1' },
      { id: 'g3', name: 'admins', path: '/admins', parent_id: null },
      { id: 'g4', name: 'ops', path: '/ops', parent_id: null },
    ],
    isLoading: false,
  }),
  useUpdateGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useGroupRealmRoles: () => ({ data: [{ id: 'r1', name: 'team-lead' }], isLoading: false }),
  useAvailableGroupRealmRoles: () => ({ data: [{ id: 'r2', name: 'user' }], isLoading: false }),
  useGroupClientRoles: () => ({ data: [], isLoading: false }),
  useAvailableGroupClientRoles: () => ({ data: [], isLoading: false }),
  useAddGroupRealmRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveGroupRealmRoles: () => ({ mutateAsync: mockRemoveRealmRoles, isPending: false }),
  useAddGroupClientRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveGroupClientRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useGroupTree', () => ({
  useGroupMembers: () => ({
    data: [
      { id: 'u1', username: 'alice', email: 'alice@example.com', enabled: true },
      { id: 'u2', username: 'bob', email: null, enabled: false },
    ],
    isLoading: false,
  }),
  useCreateChildGroup: () => ({ mutateAsync: mockCreateChildGroup, isPending: false }),
  useMoveGroup: () => ({ mutateAsync: mockMoveGroup, isPending: false }),
}))

vi.mock('../../api/hooks/useClients', () => ({
  useClients: () => ({
    data: [{ id: 'c1', client_id: 'backend-api' }],
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/groups/g1']}>
        <Routes>
          <Route path="/admin/groups/:id" element={<GroupEditPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('GroupEditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the settings tab by default', () => {
    renderPage()
    expect(screen.getByRole('tab', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Role Mappings' })).toBeInTheDocument()
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('developers')
  })

  it('shows group role mappings and removes an assigned realm role', async () => {
    const user = userEvent.setup()
    mockRemoveRealmRoles.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Role Mappings' }))

    expect(screen.getByText('team-lead')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()

    fireEvent.click(screen.getByText('team-lead'))
    await waitFor(() =>
      expect(mockRemoveRealmRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'g1',
        roles: [{ id: 'r1', name: 'team-lead' }],
      })
    )
  })
})

describe('GroupEditPage children', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists direct sub-groups on the Children tab', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Children' }))
    expect(screen.getByText('backend')).toBeInTheDocument()
    expect(screen.getByText('/developers/backend')).toBeInTheDocument()
    // Non-child groups are not listed.
    expect(screen.queryByText('admins')).not.toBeInTheDocument()
  })

  it('creates a sub-group from the name input', async () => {
    const user = userEvent.setup()
    mockCreateChildGroup.mockResolvedValue({ id: 'g5', name: 'frontend' })
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Children' }))
    await user.type(screen.getByLabelText('New Sub-group'), 'frontend')
    await user.click(screen.getByRole('button', { name: /Create/ }))
    await waitFor(() =>
      expect(mockCreateChildGroup).toHaveBeenCalledWith({
        realm: 'master',
        id: 'g1',
        body: { name: 'frontend' },
      })
    )
  })
})

describe('GroupEditPage members', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the members table', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Members' }))
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText('Showing 1–2')).toBeInTheDocument()
  })
})

describe('GroupEditPage move', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('offers the realm groups as parents, excluding self and descendants', () => {
    renderPage()
    const select = screen.getByLabelText('Parent Group')
    expect(within(select).getByRole('option', { name: 'None (root)' })).toBeInTheDocument()
    expect(within(select).getByRole('option', { name: '/admins' })).toBeInTheDocument()
    expect(within(select).getByRole('option', { name: '/ops' })).toBeInTheDocument()
    expect(within(select).queryByRole('option', { name: '/developers' })).not.toBeInTheDocument()
    expect(
      within(select).queryByRole('option', { name: '/developers/backend' })
    ).not.toBeInTheDocument()
    // The current parent is preselected.
    expect((select as HTMLSelectElement).value).toBe('g3')
  })

  it('moves the group under another parent', async () => {
    mockMoveGroup.mockResolvedValue(undefined)
    renderPage()
    fireEvent.change(screen.getByLabelText('Parent Group'), { target: { value: 'g4' } })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    await waitFor(() =>
      expect(mockMoveGroup).toHaveBeenCalledWith({
        realm: 'master',
        id: 'g1',
        body: { name: 'developers', parent_id: 'g4' },
      })
    )
  })

  it('moves the group to the root with an explicit null parent', async () => {
    mockMoveGroup.mockResolvedValue(undefined)
    renderPage()
    fireEvent.change(screen.getByLabelText('Parent Group'), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    await waitFor(() =>
      expect(mockMoveGroup).toHaveBeenCalledWith({
        realm: 'master',
        id: 'g1',
        body: { name: 'developers', parent_id: null },
      })
    )
  })

  it('keeps the Move button disabled while the selection is unchanged', () => {
    renderPage()
    expect(screen.getByRole('button', { name: 'Move' })).toBeDisabled()
  })
})
