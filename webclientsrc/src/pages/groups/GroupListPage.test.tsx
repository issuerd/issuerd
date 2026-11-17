// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import GroupListPage from './GroupListPage'
import { renderWithProviders } from '../../test/utils'
import type { GroupRepresentation } from '@generated'

const mockCreate = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

const groups: GroupRepresentation[] = [
  { id: 'g1', name: 'developers', path: '/developers' },
  { id: 'g2', name: 'operations', path: '/operations' },
]

let mockGroupsState: {
  data: GroupRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: groups, isLoading: false, error: null }

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

vi.mock('../../api/hooks/useGroups', () => ({
  useGroups: () => mockGroupsState,
  useGroupCount: () => ({ data: mockGroupsState.data.length }),
  useCreateGroup: () => ({ mutateAsync: mockCreate, isPending: false }),
  useDeleteGroup: () => ({
    mutateAsync: mockDelete,
    mutate: mockDelete,
    isPending: false,
  }),
}))

describe('GroupListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockGroupsState = { data: groups, isLoading: false, error: null }
    mockCreate.mockResolvedValue(undefined)
  })

  it('shows a loader while groups are loading', () => {
    mockGroupsState = { data: [], isLoading: true, error: null }
    renderWithProviders(<GroupListPage />)

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when there are no groups', () => {
    mockGroupsState = { data: [], isLoading: false, error: null }
    renderWithProviders(<GroupListPage />)

    expect(screen.getByText('No groups')).toBeInTheDocument()
    expect(screen.getByText('Create a group to get started.')).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockGroupsState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load groups'),
    }
    renderWithProviders(<GroupListPage />)

    expect(screen.getByText('Could not load groups')).toBeInTheDocument()
  })

  it('renders group names and paths', () => {
    renderWithProviders(<GroupListPage />)

    expect(screen.getByText('developers')).toBeInTheDocument()
    expect(screen.getByText('/developers')).toBeInTheDocument()
    expect(screen.getByText('operations')).toBeInTheDocument()
    expect(screen.getByText('/operations')).toBeInTheDocument()
  })

  it('navigates to the group editor on row click', () => {
    renderWithProviders(<GroupListPage />)

    fireEvent.click(screen.getByText('developers'))

    expect(mockNavigate).toHaveBeenCalledWith('/groups/g1')
  })

  it('creates a group through the modal form', async () => {
    renderWithProviders(<GroupListPage />)

    fireEvent.click(screen.getByRole('button', { name: /Create Group/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'quality' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith({
        realm: 'master',
        body: { name: 'quality' },
      }),
    )
  })
})
