// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import EventListPage from './EventListPage'

const mockUseEvents = vi.fn()
const mockUseEventCount = vi.fn()
const mockUseAdminEvents = vi.fn()
const mockUseAdminEventCount = vi.fn()

const loginEvents = [
  {
    id: 'e1',
    time: 1700000000,
    event_type: 'login',
    realm_id: 'c1b5b0e0-1111-2222-3333-444444444444',
    client_id: 'account-console',
    user_id: 'a9f8-user-guid-0001',
    username: 'alice',
    session_id: 'sess-1',
    ip_address: '10.0.0.1',
    details: { username: 'alice', method: 'password' },
    error: null,
  },
  {
    id: 'e2',
    time: 1700000100,
    event_type: 'login_error',
    realm_id: 'c1b5b0e0-1111-2222-3333-444444444444',
    client_id: null,
    user_id: 'a9f8-user-guid-0002',
    username: null,
    session_id: null,
    ip_address: '10.0.0.2',
    details: { username: 'ghosty' },
    error: 'invalid_user_credentials',
  },
]

const adminEvents = [
  {
    id: 'a1',
    time: 1700000200,
    realm_id: 'c1b5b0e0-1111-2222-3333-444444444444',
    auth_realm_id: 'master-realm-id',
    auth_client_id: 'admin-cli',
    auth_user_id: 'b8c7-admin-guid-0001',
    auth_username: 'root',
    operation_type: 'CREATE',
    resource_type: 'USER',
    resource_path: 'users/a9f8-user-guid-0001',
    representation: null,
    error: null,
  },
]

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'demo' }),
}))

vi.mock('../../api/hooks/useEvents', () => ({
  useEvents: (realm: string, filters: any) => mockUseEvents(realm, filters),
  useEventCount: (realm: string, filters: any) => mockUseEventCount(realm, filters),
  useAdminEvents: (realm: string, filters: any) => mockUseAdminEvents(realm, filters),
  useAdminEventCount: (realm: string, filters: any) => mockUseAdminEventCount(realm, filters),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      event_types: [
        { id: 'login', name: 'Login', description: 'Successful login' },
        { id: 'login_error', name: 'Login Error', description: 'Failed login' },
      ],
      operation_types: [{ id: 'CREATE', name: 'Create', description: 'Create operation' }],
      resource_types: [{ id: 'USER', name: 'User', description: 'User resource' }],
    },
    isLoading: false,
  }),
}))

function Wrapper({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('EventListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseEvents.mockReturnValue({ data: loginEvents, isLoading: false, isFetching: false, error: null })
    mockUseEventCount.mockReturnValue({ data: 100 })
    mockUseAdminEvents.mockReturnValue({ data: adminEvents, isLoading: false, isFetching: false, error: null })
    mockUseAdminEventCount.mockReturnValue({ data: 3 })
  })

  it('requests the first page with the default page size', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    expect(mockUseEvents).toHaveBeenCalledWith('demo', { first: 0, max: 25 })
  })

  it('passes only filters (no paging) to the count hook', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    expect(mockUseEventCount).toHaveBeenCalledWith('demo', {})
  })

  it('navigates to the next page via server-side offsets', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    expect(screen.getByText(/Showing/)).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Next page'))

    const lastCall = mockUseEvents.mock.calls.at(-1)
    expect(lastCall?.[1]).toEqual({ first: 25, max: 25 })
  })

  it('shows usernames and the realm name instead of raw ids', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    // Resolved username from the backend, details fallback, and realm name.
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('ghosty')).toBeInTheDocument()
    expect(screen.getAllByText('demo').length).toBeGreaterThan(0)
    // Raw GUIDs are not rendered in the table.
    expect(screen.queryByText('a9f8-user-guid-0001')).not.toBeInTheDocument()
    expect(screen.queryByText('c1b5b0e0-1111-2222-3333-444444444444')).not.toBeInTheDocument()
  })

  it('opens the detail drawer with a single Client ID field and the session id', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByText('alice'))

    expect(screen.getByText('Event Detail')).toBeInTheDocument()
    expect(screen.getAllByText('Client ID')).toHaveLength(1)
    expect(screen.getByText('Session ID')).toBeInTheDocument()
    expect(screen.getByText('sess-1')).toBeInTheDocument()
  })

  it('shows the resolved admin username on the admin tab', () => {
    render(<EventListPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByText('Admin Events'))

    expect(screen.getByText('root')).toBeInTheDocument()
    expect(screen.queryByText('b8c7-admin-guid-0001')).not.toBeInTheDocument()
  })

  it('paginates the admin tab independently', () => {
    mockUseAdminEventCount.mockReturnValue({ data: 60 })
    render(<EventListPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByText('Admin Events'))
    fireEvent.click(screen.getByLabelText('Next page'))

    const lastCall = mockUseAdminEvents.mock.calls.at(-1)
    expect(lastCall?.[1]).toEqual({ first: 25, max: 25 })
    // The login tab query is untouched by admin-tab paging.
    expect(mockUseEvents.mock.calls.at(-1)?.[1]).toEqual({ first: 0, max: 25 })
  })
})
