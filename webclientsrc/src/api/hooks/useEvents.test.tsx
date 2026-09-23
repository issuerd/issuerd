// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEvents, useEventCount, useAdminEvents, useAdminEventCount } from './useEvents'

const mockQueryEvents = vi.fn()
const mockQueryAdminEvents = vi.fn()
const mockCountEvents = vi.fn()
const mockCountAdminEvents = vi.fn()

vi.mock('@generated', () => ({
  queryEvents: (...args: unknown[]) => mockQueryEvents(...args),
  queryAdminEvents: (...args: unknown[]) => mockQueryAdminEvents(...args),
  countEvents: (...args: unknown[]) => mockCountEvents(...args),
  countAdminEvents: (...args: unknown[]) => mockCountAdminEvents(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useEvents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns events on success', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [{ id: 'e1', event_type: 'login' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useEvents('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('passes all filters to query', async () => {
    mockQueryEvents.mockResolvedValue({
      data: [],
      error: undefined,
      response: { status: 200 },
    })
    const filters = {
      event_type: 'login',
      date_from: '2024-01-01T00:00:00Z',
      date_to: '2024-01-02T00:00:00Z',
      first: 0,
      max: 10,
    }
    renderHook(() => useEvents('master', filters), { wrapper })
    await waitFor(() => expect(mockQueryEvents).toHaveBeenCalled())
    const callArg = mockQueryEvents.mock.calls[0][0]
    expect(callArg.query.event_type).toBe('login')
    expect(callArg.query.date_from).toBe('2024-01-01T00:00:00Z')
    expect(callArg.query.date_to).toBe('2024-01-02T00:00:00Z')
    expect(callArg.query.first).toBe(0)
    expect(callArg.query.max).toBe(10)
  })

  it('throws on error', async () => {
    mockQueryEvents.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'fail' },
      response: { status: 500 },
    })
    const { result } = renderHook(() => useEvents('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('fail')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useEvents(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useAdminEvents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns admin events', async () => {
    mockQueryAdminEvents.mockResolvedValue({
      data: [{ id: 'a1', operation_type: 'CREATE' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useAdminEvents('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('passes all admin filters', async () => {
    mockQueryAdminEvents.mockResolvedValue({
      data: [],
      error: undefined,
      response: { status: 200 },
    })
    const filters = {
      operation_type: 'CREATE',
      resource_type: 'realm',
      date_from: '2024-01-01T00:00:00Z',
      date_to: '2024-01-02T00:00:00Z',
      first: 0,
      max: 5,
    }
    renderHook(() => useAdminEvents('master', filters), { wrapper })
    await waitFor(() => expect(mockQueryAdminEvents).toHaveBeenCalled())
    const callArg = mockQueryAdminEvents.mock.calls[0][0]
    expect(callArg.query.operation_type).toBe('CREATE')
    expect(callArg.query.resource_type).toBe('realm')
    expect(callArg.query.date_from).toBe('2024-01-01T00:00:00Z')
    expect(callArg.query.date_to).toBe('2024-01-02T00:00:00Z')
    expect(callArg.query.first).toBe(0)
    expect(callArg.query.max).toBe(5)
  })

  it('throws on admin events error', async () => {
    mockQueryAdminEvents.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'admin fail' },
      response: { status: 500 },
    })
    const { result } = renderHook(() => useAdminEvents('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('admin fail')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useAdminEvents(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useEventCount', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns the count on success', async () => {
    mockCountEvents.mockResolvedValue({
      data: { count: 42 },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useEventCount('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBe(42)
  })

  it('passes filters but never pagination params', async () => {
    mockCountEvents.mockResolvedValue({
      data: { count: 0 },
      error: undefined,
      response: { status: 200 },
    })
    const filters = {
      event_type: 'login',
      date_from: '2024-01-01T00:00:00Z',
      date_to: '2024-01-02T00:00:00Z',
      first: 20,
      max: 10,
    }
    renderHook(() => useEventCount('master', filters), { wrapper })
    await waitFor(() => expect(mockCountEvents).toHaveBeenCalled())
    const callArg = mockCountEvents.mock.calls[0][0]
    expect(callArg.query.event_type).toBe('login')
    expect(callArg.query.date_from).toBe('2024-01-01T00:00:00Z')
    expect(callArg.query.date_to).toBe('2024-01-02T00:00:00Z')
    expect(callArg.query.first).toBeUndefined()
    expect(callArg.query.max).toBeUndefined()
  })

  it('throws on error', async () => {
    mockCountEvents.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'count fail' },
      response: { status: 500 },
    })
    const { result } = renderHook(() => useEventCount('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('count fail')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useEventCount(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useAdminEventCount', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns the count on success', async () => {
    mockCountAdminEvents.mockResolvedValue({
      data: { count: 7 },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useAdminEventCount('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBe(7)
  })

  it('passes filters but never pagination params', async () => {
    mockCountAdminEvents.mockResolvedValue({
      data: { count: 0 },
      error: undefined,
      response: { status: 200 },
    })
    const filters = {
      operation_type: 'CREATE',
      resource_type: 'USER',
      first: 50,
      max: 25,
    }
    renderHook(() => useAdminEventCount('master', filters), { wrapper })
    await waitFor(() => expect(mockCountAdminEvents).toHaveBeenCalled())
    const callArg = mockCountAdminEvents.mock.calls[0][0]
    expect(callArg.query.operation_type).toBe('CREATE')
    expect(callArg.query.resource_type).toBe('USER')
    expect(callArg.query.first).toBeUndefined()
    expect(callArg.query.max).toBeUndefined()
  })

  it('throws on error', async () => {
    mockCountAdminEvents.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'admin count fail' },
      response: { status: 500 },
    })
    const { result } = renderHook(() => useAdminEventCount('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('admin count fail')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useAdminEventCount(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })
})
