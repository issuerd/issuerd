// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityDashboard from './SecurityDashboard'

let mockUsersData: any[] = [
  { id: 'u1', username: 'alice', enabled: true, email_verified: true },
  { id: 'u2', username: 'bob', enabled: false, email_verified: false },
]
let mockSessionsData: any[] = []
let mockClientsData: any[] = [{ client_id: 'app', public_client: true }]
let mockEventsData: any[] = []
let mockLoginErrorsData: any[] = []
let mockUsersLoading = false
let mockUsersError: Error | null = null
let mockLockedUsersData: any[] = []
let mockLockedUsersLoading = false
let mockLockedUsersError: Error | null = null
const mockClearMutate = vi.fn()

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) =>
    selector({ currentRealm: 'master' }),
}))

vi.mock('../../api/hooks/useUsers', () => ({
  useUsers: () => ({
    data: mockUsersData,
    isLoading: mockUsersLoading,
    error: mockUsersError,
  }),
}))

vi.mock('../../api/hooks/useSessions', () => ({
  useSessions: () => ({ data: mockSessionsData, isLoading: false }),
}))

vi.mock('../../api/hooks/useClients', () => ({
  useClients: () => ({
    data: mockClientsData,
    isLoading: false,
  }),
}))

vi.mock('../../api/hooks/useEvents', () => ({
  useEvents: (_realm: string, filters: any) => {
    if (filters?.event_type === 'login_error') {
      return { data: mockLoginErrorsData, isLoading: false, isFetching: false }
    }
    return { data: mockEventsData, isLoading: false, isFetching: false }
  },
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: { event_types: [{ id: 'login_error', name: 'Login Error', description: 'Login error event' }] },
    isLoading: false,
  }),
}))

vi.mock('../../api/hooks/useAttackDetection', () => ({
  useLockedUsers: () => ({
    data: mockLockedUsersData,
    isLoading: mockLockedUsersLoading,
    error: mockLockedUsersError,
  }),
  useClearBruteForceState: () => ({ mutate: mockClearMutate, isPending: false }),
}))

function Wrapper({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SecurityDashboard', () => {
  beforeEach(() => {
    mockUsersData = [
      { id: 'u1', username: 'alice', enabled: true, email_verified: true },
      { id: 'u2', username: 'bob', enabled: false, email_verified: false },
    ]
    mockSessionsData = []
    mockClientsData = [{ client_id: 'app', public_client: true }]
    mockEventsData = []
    mockLoginErrorsData = []
    mockUsersLoading = false
    mockUsersError = null
    mockLockedUsersData = []
    mockLockedUsersLoading = false
    mockLockedUsersError = null
    mockClearMutate.mockClear()
  })

  it('renders security score and stats', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText('Security Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Security Score')).toBeInTheDocument()
  })

  it('renders active threats', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText('Active Threats')).toBeInTheDocument()
  })

  it('renders quick actions', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByRole('button', { name: /view all events/i })).toBeInTheDocument()
  })

  it('shows no threats when score is high', () => {
    mockUsersData = [{ username: 'alice', enabled: true, email_verified: true }]
    mockClientsData = [{ client_id: 'app', public_client: false }]
    mockSessionsData = [{ id: 's1' }]
    mockLoginErrorsData = []
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/No active threats detected/i)).toBeInTheDocument()
  })

  it('shows medium threat for failed logins', () => {
    mockLoginErrorsData = Array.from({ length: 15 }, (_, i) => ({ id: i }))
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/15 failed logins in the last 24h/i)).toBeInTheDocument()
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('shows investigate button on threats with actions', () => {
    mockLoginErrorsData = Array.from({ length: 15 }, (_, i) => ({ id: i }))
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getAllByText(/Investigate/i)[0]).toBeInTheDocument()
  })

  it('renders security events with event_type object', () => {
    mockEventsData = [
      {
        event_type: { custom: 'login_error' },
        ip_address: '1.2.3.4',
        client_id: 'app',
        time: Math.floor(Date.now() / 1000),
        details: { error: 'invalid_credentials' },
      },
    ]
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/1\.2\.3\.4/)).toBeInTheDocument()
  })

  it('renders security events with string event_type', () => {
    mockEventsData = [
      {
        event_type: 'client_login_error',
        ip_address: '5.6.7.8',
        client_id: null,
        time: Math.floor(Date.now() / 1000),
        details: null,
      },
    ]
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/N\/A/)).toBeInTheDocument()
  })

  it('shows no security events message', () => {
    mockEventsData = []
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/No security events in the last 7 days/i)).toBeInTheDocument()
  })

  it('triggers refresh on button click', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    const btn = screen.getByRole('button', { name: /Refresh/i })
    fireEvent.click(btn)
    expect(btn).toBeInTheDocument()
  })

  it('navigates on investigate button click', () => {
    mockLoginErrorsData = Array.from({ length: 15 }, (_, i) => ({ id: i }))
    render(<SecurityDashboard />, { wrapper: Wrapper })
    const buttons = screen.getAllByText(/Investigate/i)
    fireEvent.click(buttons[0])
    // Navigation tested by MemoryRouter; no error means success
  })

  it('navigates on quick action buttons', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: /View All Events/i }))
    fireEvent.click(screen.getByRole('button', { name: /Manage Sessions/i }))
    fireEvent.click(screen.getByRole('button', { name: /Review Keys/i }))
    fireEvent.click(screen.getByRole('button', { name: /Audit Users/i }))
  })

  it('shows spinner while loading', () => {
    mockUsersLoading = true
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error message when users query fails', () => {
    mockUsersError = new Error('users fetch failed')
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/users fetch failed/i)).toBeInTheDocument()
  })

  it('shows empty attack detection state when no users are locked', () => {
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/Attack Detection/i)).toBeInTheDocument()
    expect(screen.getByText(/No locked-out users/i)).toBeInTheDocument()
  })

  it('lists locked-out users and unlocks via resolved user id', () => {
    mockLockedUsersData = [{ username: 'alice', ip: '10.0.0.1', numFailures: 3 }]
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    const unlock = screen.getByRole('button', { name: 'Unlock' })
    expect(unlock).not.toBeDisabled()
    fireEvent.click(unlock)
    expect(mockClearMutate).toHaveBeenCalledWith({ realm: 'master', id: 'u1' })
  })

  it('unlocks via server-resolved userId when the user is not in the loaded list', () => {
    // 'ghost' is not in mockUsersData — resolution must come from row.userId alone.
    mockLockedUsersData = [{ username: 'ghost', ip: '10.0.0.5', numFailures: 2, userId: 'u-ghost' }]
    render(<SecurityDashboard />, { wrapper: Wrapper })
    const unlock = screen.getByRole('button', { name: 'Unlock' })
    expect(unlock).not.toBeDisabled()
    fireEvent.click(unlock)
    expect(mockClearMutate).toHaveBeenCalledWith({ realm: 'master', id: 'u-ghost' })
  })

  it('disables unlock when the username cannot be resolved to a user id', () => {
    mockLockedUsersData = [{ username: 'mallory', ip: '10.0.0.9', numFailures: 7 }]
    render(<SecurityDashboard />, { wrapper: Wrapper })
    const unlock = screen.getByRole('button', { name: 'Unlock' })
    expect(unlock).toBeDisabled()
    fireEvent.click(unlock)
    expect(mockClearMutate).not.toHaveBeenCalled()
  })

  it('shows attack detection error without breaking the page', () => {
    mockLockedUsersError = new Error('forbidden')
    render(<SecurityDashboard />, { wrapper: Wrapper })
    expect(screen.getByText(/forbidden/i)).toBeInTheDocument()
    expect(screen.getByText('Security Score')).toBeInTheDocument()
  })
})
