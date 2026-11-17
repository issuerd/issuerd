// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import SessionListPage from './SessionListPage'
import { renderWithProviders } from '../../test/utils'
import type { UserSessionRepresentation } from '@generated'

const mockDelete = vi.fn()
const mockList = vi.fn()

const sessions: UserSessionRepresentation[] = [
  {
    id: 's1',
    username: 'alice',
    user_id: 'u1',
    ip_address: '127.0.0.1',
    started: 1700000000,
    last_access: 1700000100,
    offline: false,
    clients: {},
  },
  {
    id: 's2',
    username: 'bob',
    user_id: 'u2',
    ip_address: '127.0.0.2',
    started: 1700000000,
    last_access: 1700000100,
    offline: true,
    clients: {},
  },
]

let mockSessionsState: {
  data: UserSessionRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: sessions, isLoading: false, error: null }
let mockTotalCount = sessions.length

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: (state: { currentRealm: string }) => unknown) =>
    selector({ currentRealm: 'master' }),
}))

vi.mock('../../api/hooks/useSessions', () => ({
  useSessions: (realm: string, options: { first: number; max: number }) => {
    mockList(realm, options)
    return mockSessionsState
  },
  useSessionCount: () => ({ data: mockTotalCount }),
  useDeleteSession: () => ({ mutate: mockDelete }),
}))

describe('SessionListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    window.confirm = vi.fn(() => true)
    mockSessionsState = { data: sessions, isLoading: false, error: null }
    mockTotalCount = sessions.length
  })

  it('marks offline sessions with a badge and online ones without', async () => {
    renderWithProviders(<SessionListPage />)

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText('Offline')).toBeInTheDocument()
    expect(screen.getByText('Online')).toBeInTheDocument()
  })

  it('shows the offline explanation in the detail drawer', async () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.click(await screen.findByText('bob'))
    await waitFor(() => {
      expect(
        screen.getByText(/Backs an offline_access refresh token/i),
      ).toBeInTheDocument()
    })
    expect(screen.getByText('u2')).toBeInTheDocument()
  })

  it('shows a loader while sessions are loading', () => {
    mockSessionsState = { data: [], isLoading: true, error: null }
    renderWithProviders(<SessionListPage />)

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when there are no sessions', () => {
    mockSessionsState = { data: [], isLoading: false, error: null }
    mockTotalCount = 0
    renderWithProviders(<SessionListPage />)

    expect(screen.getByText('No sessions')).toBeInTheDocument()
    expect(screen.getByText('There are no active sessions.')).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockSessionsState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load sessions'),
    }
    renderWithProviders(<SessionListPage />)

    expect(screen.getByText('Could not load sessions')).toBeInTheDocument()
  })

  it('revokes selected sessions after confirmation', () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.click(screen.getByLabelText('Select row s1'))
    fireEvent.click(screen.getByRole('button', { name: /Revoke Selected/ }))

    expect(mockDelete).toHaveBeenCalledWith({ realm: 'master', session: 's1' })
  })

  it('revokes the open session from its detail drawer', () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.click(screen.getByText('alice'))
    fireEvent.click(screen.getByRole('button', { name: 'Revoke Session' }))

    expect(mockDelete).toHaveBeenCalledWith({ realm: 'master', session: 's1' })
  })

  it('does not revoke the open session when confirmation is cancelled', () => {
    window.confirm = vi.fn(() => false)
    renderWithProviders(<SessionListPage />)

    fireEvent.click(screen.getByText('alice'))
    fireEvent.click(screen.getByRole('button', { name: 'Revoke Session' }))

    expect(mockDelete).not.toHaveBeenCalled()
  })

  it('requests the selected page and page size', () => {
    mockTotalCount = 100
    renderWithProviders(<SessionListPage />)

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(mockList).toHaveBeenLastCalledWith('master', { first: 25, max: 25 })

    fireEvent.change(screen.getByLabelText('Rows'), { target: { value: '10' } })
    expect(mockList).toHaveBeenLastCalledWith('master', { first: 0, max: 10 })
  })

  it('closes the detail drawer without revoking the session', async () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.click(screen.getByText('alice'))
    fireEvent.click(screen.getByRole('button', { name: 'Close drawer' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockDelete).not.toHaveBeenCalled()
  })

  it('filters rows using every session column accessor', () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.change(screen.getByPlaceholderText('Search...'), {
      target: { value: '127.0.0.2' },
    })

    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.queryByText('alice')).not.toBeInTheDocument()
  })
})
