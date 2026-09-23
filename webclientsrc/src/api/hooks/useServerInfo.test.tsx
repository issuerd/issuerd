// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useServerInfo } from './useServerInfo'

const mockGetServerinfo = vi.fn()

vi.mock('@generated', () => ({
  getServerinfo: (...args: unknown[]) => mockGetServerinfo(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useServerInfo', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns server info', async () => {
    mockGetServerinfo.mockResolvedValue({
      data: { protocols: [{ id: 'openid-connect', name: 'OIDC' }] },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useServerInfo(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.protocols).toHaveLength(1)
  })

  it('throws on error', async () => {
    mockGetServerinfo.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'down' },
      response: { status: 503 },
    })
    const { result } = renderHook(() => useServerInfo(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('down')
  })
})
