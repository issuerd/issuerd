// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useLiveSessionCount } from './useLiveSessionCount'

const mockListSessions = vi.fn()
const mockCountSessions = vi.fn()

vi.mock('@generated', () => ({
  listSessions: (...args: unknown[]) => mockListSessions(...args),
  countSessions: (...args: unknown[]) => mockCountSessions(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useLiveSessionCount', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns sessions with refetch interval', async () => {
    mockListSessions.mockResolvedValue({
      data: [{ id: 's1' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useLiveSessionCount('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })
})
