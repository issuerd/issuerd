// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useSessions, useDeleteSession } from './useSessions'

const mockListSessions = vi.fn()
const mockCountSessions = vi.fn()
const mockDeleteSession = vi.fn()

vi.mock('@generated', () => ({
  listSessions: (...args: unknown[]) => mockListSessions(...args),
  countSessions: (...args: unknown[]) => mockCountSessions(...args),
  deleteSession: (...args: unknown[]) => mockDeleteSession(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useSessions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns sessions on success', async () => {
    mockListSessions.mockResolvedValue({
      data: [{ id: 's1', user_id: 'u1' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useSessions('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('throws on error response', async () => {
    mockListSessions.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useSessions('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('passes options through', async () => {
    mockListSessions.mockResolvedValue({
      data: [],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useSessions('master', undefined, { refetchInterval: 5000 }), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useSessions(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useDeleteSession', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('deletes a session', async () => {
    mockDeleteSession.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteSession(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', session: 's1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('rolls back on error', async () => {
    mockDeleteSession.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['sessions', 'master'], [{ id: 's1', user_id: 'u1' }])
    const { result } = renderHook(() => useDeleteSession(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', session: 's1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['sessions', 'master'])).toEqual([{ id: 's1', user_id: 'u1' }])
  })

  it('throws on deleteSession error response', async () => {
    mockDeleteSession.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useDeleteSession(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', session: 's1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('optimistic delete when list cache is undefined', async () => {
    mockDeleteSession.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useDeleteSession(), { wrapper: customWrapper })
    await result.current.mutateAsync({ realm: 'master', session: 's1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })
})
