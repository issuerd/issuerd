// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useRealmRoles, useRealmRole, useCreateRealmRole, useUpdateRealmRole, useDeleteRealmRole } from './useRoles'

const mockListRealmRoles = vi.fn()
const mockCountRealmRoles = vi.fn()
const mockGetRealmRole = vi.fn()
const mockCreateRealmRole = vi.fn()
const mockUpdateRealmRole = vi.fn()
const mockDeleteRealmRole = vi.fn()

vi.mock('@generated', () => ({
  listRealmRoles: (...args: unknown[]) => mockListRealmRoles(...args),
  countRealmRoles: (...args: unknown[]) => mockCountRealmRoles(...args),
  getRealmRole: (...args: unknown[]) => mockGetRealmRole(...args),
  createRealmRole: (...args: unknown[]) => mockCreateRealmRole(...args),
  updateRealmRole: (...args: unknown[]) => mockUpdateRealmRole(...args),
  deleteRealmRole: (...args: unknown[]) => mockDeleteRealmRole(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useRoles', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns realm roles on success', async () => {
    mockListRealmRoles.mockResolvedValue({
      data: [{ id: 'r1', name: 'admin' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useRealmRoles('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].name).toBe('admin')
  })

  it('throws on error response', async () => {
    mockListRealmRoles.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useRealmRoles('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useRealmRoles(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('returns realm role by name on success', async () => {
    mockGetRealmRole.mockResolvedValue({
      data: { id: 'r1', name: 'admin' },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useRealmRole('master', 'admin'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.name).toBe('admin')
  })

  it('throws on getRealmRole error', async () => {
    mockGetRealmRole.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useRealmRole('master', 'admin'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Not found')
  })

  it('is disabled when name is empty', () => {
    const { result } = renderHook(() => useRealmRole('master', ''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('calls getRealmRole with role_name path param', async () => {
    mockGetRealmRole.mockResolvedValue({
      data: { id: 'r1', name: 'admin' },
      error: undefined,
      response: { status: 200 },
    })
    renderHook(() => useRealmRole('master', 'admin'), { wrapper })
    await waitFor(() => expect(mockGetRealmRole).toHaveBeenCalled())
    expect(mockGetRealmRole).toHaveBeenCalledWith({ path: { realm: 'master', role_name: 'admin' } })
  })

  it('creates a realm role', async () => {
    mockCreateRealmRole.mockResolvedValue({
      data: { id: 'r2', name: 'user' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'user' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateRealmRole).toHaveBeenCalledWith({ path: { realm: 'master' }, body: { name: 'user' } })
  })

  it('updates a realm role', async () => {
    mockUpdateRealmRole.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useUpdateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin', body: { name: 'admin', description: 'updated' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateRealmRole).toHaveBeenCalledWith({ path: { realm: 'master', role_name: 'admin' }, body: { name: 'admin', description: 'updated' } })
  })

  it('deletes a realm role', async () => {
    mockDeleteRealmRole.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeleteRealmRole).toHaveBeenCalledWith({ path: { realm: 'master', role_name: 'admin' } })
  })

  it('throws on createRealmRole error', async () => {
    mockCreateRealmRole.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad request' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateRealmRole(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { name: 'admin' } })).rejects.toThrow('bad request')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('bad request')
  })

  it('throws on updateRealmRole error', async () => {
    mockUpdateRealmRole.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUpdateRealmRole(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', name: 'admin', body: { name: 'admin' } })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on deleteRealmRole error', async () => {
    mockDeleteRealmRole.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useDeleteRealmRole(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', name: 'admin' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })
})
