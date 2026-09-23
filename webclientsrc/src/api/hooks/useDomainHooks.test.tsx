// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useClients, useClient, useCreateClient } from './useClients'
import { useRealmRoles, useCreateRealmRole } from './useRoles'
import { useGroups, useCreateGroup } from './useGroups'
import { useSessions, useDeleteSession } from './useSessions'
import { useEvents } from './useEvents'
import { useIdps, useCreateIdp } from './useIdentityProviders'
import { useKeys } from './useKeys'
import { useFlows } from './useAuthFlows'

const mockListClients = vi.fn()
const mockCountClients = vi.fn()
const mockGetClient = vi.fn()
const mockCreateClient = vi.fn()
const mockListRealmRoles = vi.fn()
const mockCountRealmRoles = vi.fn()
const mockCreateRealmRole = vi.fn()
const mockListGroups = vi.fn()
const mockCountGroups = vi.fn()
const mockCreateGroup = vi.fn()
const mockListSessions = vi.fn()
const mockCountSessions = vi.fn()
const mockDeleteSession = vi.fn()
const mockQueryEvents = vi.fn()
const mockListIdps = vi.fn()
const mockCreateIdp = vi.fn()
const mockGetKeys = vi.fn()
const mockListFlows = vi.fn()

vi.mock('@generated', () => ({
  listClients: (...args: unknown[]) => mockListClients(...args),
  countClients: (...args: unknown[]) => mockCountClients(...args),
  getClient: (...args: unknown[]) => mockGetClient(...args),
  createClient: (...args: unknown[]) => mockCreateClient(...args),
  listRealmRoles: (...args: unknown[]) => mockListRealmRoles(...args),
  countRealmRoles: (...args: unknown[]) => mockCountRealmRoles(...args),
  createRealmRole: (...args: unknown[]) => mockCreateRealmRole(...args),
  listGroups: (...args: unknown[]) => mockListGroups(...args),
  countGroups: (...args: unknown[]) => mockCountGroups(...args),
  createGroup: (...args: unknown[]) => mockCreateGroup(...args),
  listSessions: (...args: unknown[]) => mockListSessions(...args),
  countSessions: (...args: unknown[]) => mockCountSessions(...args),
  deleteSession: (...args: unknown[]) => mockDeleteSession(...args),
  queryEvents: (...args: unknown[]) => mockQueryEvents(...args),
  listIdps: (...args: unknown[]) => mockListIdps(...args),
  createIdp: (...args: unknown[]) => mockCreateIdp(...args),
  getKeys: (...args: unknown[]) => mockGetKeys(...args),
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('domain hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useClients fetches clients', async () => {
    mockListClients.mockResolvedValue({
      data: [{ client_id: 'app', enabled: true }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useClients('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('useClient fetches a single client', async () => {
    mockGetClient.mockResolvedValue({
      data: { client_id: 'app', enabled: true },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useClient('master', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.client_id).toBe('app')
  })

  it('useCreateClient creates and invalidates', async () => {
    mockCreateClient.mockResolvedValue({
      data: { client_id: 'new', enabled: true },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { client_id: 'new', enabled: true } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useRealmRoles fetches roles', async () => {
    mockListRealmRoles.mockResolvedValue({
      data: [{ name: 'admin' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useRealmRoles('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].name).toBe('admin')
  })

  it('useCreateRealmRole creates a role', async () => {
    mockCreateRealmRole.mockResolvedValue({
      data: { name: 'user' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'user' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useGroups fetches groups', async () => {
    mockListGroups.mockResolvedValue({
      data: [{ name: 'admins', id: 'g1' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useGroups('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].name).toBe('admins')
  })

  it('useCreateGroup creates a group', async () => {
    mockCreateGroup.mockResolvedValue({
      data: { name: 'users', id: 'g2' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'users' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useSessions fetches sessions', async () => {
    mockListSessions.mockResolvedValue({
      data: [{ id: 's1', username: 'alice', ip_address: '127.0.0.1', started: 1, last_access: 2, user_id: 'u1', clients: {} }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useSessions('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('useDeleteSession deletes a session', async () => {
    mockDeleteSession.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteSession(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', session: 's1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useEvents fetches events', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [{ event_type: 'login', time: 1, realm_id: 'master' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useEvents('master', { first: 0, max: 10 }), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('useIdps fetches identity providers', async () => {
    mockListIdps.mockResolvedValue({
      data: [{ alias: 'google', provider_id: 'google', enabled: true }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useIdps('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].alias).toBe('google')
  })

  it('useCreateIdp creates an IdP', async () => {
    mockCreateIdp.mockResolvedValue({
      data: { alias: 'github', provider_id: 'github' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { alias: 'github', provider_id: 'github' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useKeys fetches keys', async () => {
    mockGetKeys.mockResolvedValue({
      data: { active: { RS256: 'kid1' }, passive: [] },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useKeys('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.active.RS256).toBe('kid1')
  })

  it('useFlows fetches auth flows', async () => {
    mockListFlows.mockResolvedValue({
      data: [{ alias: 'browser', top_level: true, built_in: true }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useFlows('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].alias).toBe('browser')
  })
})
