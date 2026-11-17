// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import RoleListPage from './RoleListPage'
import { renderWithProviders } from '../../test/utils'
import type { RoleRepresentation } from '@generated'

const mockCreate = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

const roles: RoleRepresentation[] = [
  { id: 'r1', name: 'realm admin', description: 'Realm administrators' },
  { id: 'r2', name: 'auditor', description: null },
]

let mockRolesState: {
  data: RoleRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: roles, isLoading: false, error: null }

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

vi.mock('../../api/hooks/useRoles', () => ({
  useRealmRoles: () => mockRolesState,
  useRealmRoleCount: () => ({ data: mockRolesState.data.length }),
  useCreateRealmRole: () => ({ mutateAsync: mockCreate, isPending: false }),
  useDeleteRealmRole: () => ({
    mutateAsync: mockDelete,
    mutate: mockDelete,
    isPending: false,
  }),
}))

describe('RoleListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockRolesState = { data: roles, isLoading: false, error: null }
    mockCreate.mockResolvedValue(undefined)
  })

  it('shows a loader while roles are loading', () => {
    mockRolesState = { data: [], isLoading: true, error: null }
    renderWithProviders(<RoleListPage />)

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when there are no roles', () => {
    mockRolesState = { data: [], isLoading: false, error: null }
    renderWithProviders(<RoleListPage />)

    expect(screen.getByText('No roles')).toBeInTheDocument()
    expect(screen.getByText('Create a role to get started.')).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockRolesState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load roles'),
    }
    renderWithProviders(<RoleListPage />)

    expect(screen.getByText('Could not load roles')).toBeInTheDocument()
  })

  it('renders role names and descriptions', () => {
    renderWithProviders(<RoleListPage />)

    expect(screen.getByText('realm admin')).toBeInTheDocument()
    expect(screen.getByText('Realm administrators')).toBeInTheDocument()
    expect(screen.getByText('auditor')).toBeInTheDocument()
  })

  it('navigates to the role editor on row click', () => {
    renderWithProviders(<RoleListPage />)

    fireEvent.click(screen.getByText('realm admin'))

    expect(mockNavigate).toHaveBeenCalledWith('/roles/realm%20admin')
  })

  it('creates a role through the modal form', async () => {
    renderWithProviders(<RoleListPage />)

    fireEvent.click(screen.getByRole('button', { name: /Create Role/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'support' } })
    fireEvent.change(screen.getByLabelText('Description'), {
      target: { value: 'Support operators' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith({
        realm: 'master',
        body: { name: 'support', description: 'Support operators' },
      }),
    )
  })

  it('closes the create modal through both close actions', async () => {
    renderWithProviders(<RoleListPage />)

    fireEvent.click(screen.getByRole('button', { name: /Create Role/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Create Role/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})
