// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useDashboard } from './useDashboard'

const mockListUsers = vi.fn()
const mockCountUsers = vi.fn()
const mockListSessions = vi.fn()
const mockCountSessions = vi.fn()
const mockQueryEvents = vi.fn()
const mockGetServerinfo = vi.fn()

vi.mock('@generated', () => ({
  listUsers: (...args: unknown[]) => mockListUsers(...args),
  countUsers: (...args: unknown[]) => mockCountUsers(...args),
  listSessions: (...args: unknown[]) => mockListSessions(...args),
  countSessions: (...args: unknown[]) => mockCountSessions(...args),
  queryEvents: (...args: unknown[]) => mockQueryEvents(...args),
  getServerinfo: (...args: unknown[]) => mockGetServerinfo(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListUsers.mockResolvedValue({ data: [{ id: 'u1', enabled: true }], error: undefined, response: { status: 200 } })
    mockCountUsers.mockResolvedValue({ data: { count: 1 }, error: undefined, response: { status: 200 } })
    mockListSessions.mockResolvedValue({ data: [{ id: 's1' }], error: undefined, response: { status: 200 } })
    mockCountSessions.mockResolvedValue({ data: { count: 1 }, error: undefined, response: { status: 200 } })
    mockQueryEvents.mockResolvedValue({ data: [], error: undefined, response: { status: 200 } })
    mockGetServerinfo.mockResolvedValue({
      data: { protocols: [{ id: 'oidc' }], response_types: [], provider_ids: [] },
      error: undefined,
      response: { status: 200 },
    })
  })

  it('returns dashboard data', async () => {
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data).toBeDefined()
    expect(result.current.data?.totalUsers).toBe(1)
    expect(result.current.data?.totalSessions).toBe(1)
  })

  it('computes active users correctly', async () => {
    mockListUsers.mockResolvedValue({
      data: [
        { id: 'u1', enabled: true },
        { id: 'u2', enabled: false },
      ],
      error: undefined,
      response: { status: 200 },
    })
    mockCountUsers.mockResolvedValue({ data: { count: 2 }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.activeUsers).toBe(1)
    expect(result.current.data?.totalUsers).toBe(2)
  })

  it('computes token events with string event_type', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: 'login', time: Date.now() / 1000, client_id: 'c1' },
        { id: 'e2', event_type: 'code_to_token', time: Date.now() / 1000, client_id: 'c1' },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.tokenEvents24h).toBe(2)
    expect(result.current.data?.topClients).toHaveLength(1)
  })

  it('computes token events with object event_type containing custom', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: { custom: 'login' }, time: Date.now() / 1000, client_id: 'c1' },
        { id: 'e2', event_type: { custom: 'code_to_token' }, time: Date.now() / 1000, client_id: 'c1' },
        { id: 'e3', event_type: { custom: 'refresh_token' }, time: Date.now() / 1000, client_id: 'c2' },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.tokenEvents24h).toBe(3)
    // topClients only counts login and code_to_token, not refresh_token
    expect(result.current.data?.topClients).toHaveLength(1)
    expect(result.current.data?.topClients?.[0].client_id).toBe('c1')
  })

  it('filters out non-token events', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: 'login_error', time: Date.now() / 1000 },
        { id: 'e2', event_type: 'logout', time: Date.now() / 1000 },
        { id: 'e3', event_type: 'login', time: Date.now() / 1000 },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.tokenEvents24h).toBe(1)
  })

  it('returns healthy status when serverInfo has data', async () => {
    mockGetServerinfo.mockResolvedValue({
      data: {
        protocols: [{ id: 'oidc' }],
        response_types: [{ id: 'code' }],
        provider_ids: [{ id: 'ldap' }],
      },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.health).toEqual([
      { name: 'Database', status: 'healthy' },
      { name: 'OIDC', status: 'healthy' },
      { name: 'Cache', status: 'healthy' },
      { name: 'Federation', status: 'healthy' },
    ])
  })

  it('returns warning status when serverInfo arrays are empty', async () => {
    mockGetServerinfo.mockResolvedValue({
      data: {
        protocols: [],
        response_types: [],
        provider_ids: [],
      },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.health).toEqual([
      { name: 'Database', status: 'warning' },
      { name: 'OIDC', status: 'warning' },
      { name: 'Cache', status: 'healthy' },
      { name: 'Federation', status: 'warning' },
    ])
  })

  it('computes failed logins from login_error events', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: 'login_error', time: Date.now() / 1000 },
        { id: 'e2', event_type: 'login_error', time: Date.now() / 1000 },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.failedLogins24h).toBe(2)
  })

  it('computes hourly tokens for last 24h', async () => {
    const now = Date.now() / 1000
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: 'login', time: now - 3600, client_id: 'c1' },
        { id: 'e2', event_type: 'login', time: now - 7200, client_id: 'c1' },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.hourlyTokens).toHaveLength(24)
    const total = result.current.data!.hourlyTokens.reduce((sum, h) => sum + h.count, 0)
    expect(total).toBe(2)
  })

  it('sorts topClients by count descending', async () => {
    const now = Date.now() / 1000
    mockQueryEvents.mockResolvedValue({
      data: [
        { id: 'e1', event_type: 'login', time: now, client_id: 'client-a' },
        { id: 'e2', event_type: 'login', time: now, client_id: 'client-a' },
        { id: 'e3', event_type: 'login', time: now, client_id: 'client-b' },
        { id: 'e4', event_type: 'code_to_token', time: now, client_id: 'client-c' },
        { id: 'e5', event_type: 'code_to_token', time: now, client_id: 'client-c' },
        { id: 'e6', event_type: 'code_to_token', time: now, client_id: 'client-c' },
      ],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useDashboard('master'), { wrapper })
    await waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.data?.topClients).toEqual([
      { client_id: 'client-c', count: 3 },
      { client_id: 'client-a', count: 2 },
      { client_id: 'client-b', count: 1 },
    ])
  })
})
