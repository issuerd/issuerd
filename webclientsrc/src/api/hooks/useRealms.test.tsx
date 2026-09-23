// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useRealms, useRealm, useCreateRealm, useUpdateRealm, useDeleteRealm } from './useRealms'

const mockListRealms = vi.fn()
const mockCountRealms = vi.fn()
const mockGetRealm = vi.fn()
const mockCreateRealm = vi.fn()
const mockUpdateRealm = vi.fn()
const mockDeleteRealm = vi.fn()

vi.mock('@generated', () => ({
  listRealms: (...args: unknown[]) => mockListRealms(...args),
  countRealms: (...args: unknown[]) => mockCountRealms(...args),
  getRealm: (...args: unknown[]) => mockGetRealm(...args),
  createRealm: (...args: unknown[]) => mockCreateRealm(...args),
  updateRealm: (...args: unknown[]) => mockUpdateRealm(...args),
  deleteRealm: (...args: unknown[]) => mockDeleteRealm(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useRealms', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns realms', async () => {
    mockListRealms.mockResolvedValue({ data: [{ realm: 'master' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useRealms(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('throws on useRealms error', async () => {
    mockListRealms.mockResolvedValue({ data: undefined, error: { errorMessage: 'db down' }, response: { status: 503 } })
    const { result } = renderHook(() => useRealms(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('db down')
  })

  it('returns realm by name', async () => {
    mockGetRealm.mockResolvedValue({ data: { realm: 'master' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useRealm('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.realm).toBe('master')
  })

  it('throws on useRealm error', async () => {
    mockGetRealm.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useRealm('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('create realm', async () => {
    mockCreateRealm.mockResolvedValue({ data: { realm: 'new' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateRealm(), { wrapper })
    await result.current.mutateAsync({ realm: 'new', enabled: true })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('throws on createRealm error', async () => {
    mockCreateRealm.mockResolvedValue({ data: undefined, error: { errorMessage: 'conflict' }, response: { status: 409 } })
    const { result } = renderHook(() => useCreateRealm(), { wrapper })
    await result.current.mutateAsync({ realm: 'new', enabled: true }).catch(() => {})
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('conflict')
  })

  it('update realm', async () => {
    mockUpdateRealm.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateRealm(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { display_name: 'M' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('update realm rolls back on error', async () => {
    mockUpdateRealm.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useUpdateRealm(), { wrapper })
    result.current.mutate({ realm: 'master', body: { display_name: 'M' } })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('delete realm', async () => {
    mockDeleteRealm.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteRealm(), { wrapper })
    await result.current.mutateAsync('master')
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('delete realm rolls back on error', async () => {
    mockDeleteRealm.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useDeleteRealm(), { wrapper })
    result.current.mutate('master')
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('throws on updateRealm error', async () => {
    mockUpdateRealm.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUpdateRealm(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { display_name: 'M' } })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on deleteRealm error', async () => {
    mockDeleteRealm.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useDeleteRealm(), { wrapper })
    await expect(result.current.mutateAsync('master')).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('update realm optimistic update when list cache is undefined', async () => {
    mockUpdateRealm.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['realms', 'master'], { realm: 'master', display_name: 'Original' })
    const { result } = renderHook(() => useUpdateRealm(), { wrapper: customWrapper })
    await result.current.mutateAsync({ realm: 'master', body: { display_name: 'Updated' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })
})
