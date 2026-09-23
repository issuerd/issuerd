// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useLockedUsers, useClearBruteForceState } from './useAttackDetection'

const mockListLockedUsers = vi.fn()
const mockClearUserBruteForceState = vi.fn()

vi.mock('@generated', () => ({
  listLockedUsers: (...args: unknown[]) => mockListLockedUsers(...args),
  clearUserBruteForceState: (...args: unknown[]) => mockClearUserBruteForceState(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useAttackDetection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useLockedUsers fetches locked-out users', async () => {
    mockListLockedUsers.mockResolvedValue({
      data: [{ username: 'alice', ip: '10.0.0.1', numFailures: 3 }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useLockedUsers('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(mockListLockedUsers).toHaveBeenCalledWith({ path: { realm: 'master' } })
  })

  it('useLockedUsers surfaces API errors', async () => {
    mockListLockedUsers.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useLockedUsers('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('forbidden')
  })

  it('useClearBruteForceState deletes state for the user', async () => {
    mockClearUserBruteForceState.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useClearBruteForceState(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockClearUserBruteForceState).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1' },
    })
  })

  it('useClearBruteForceState surfaces API errors', async () => {
    mockClearUserBruteForceState.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'user not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useClearBruteForceState(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'missing' })
    ).rejects.toThrow('user not found')
  })
})
