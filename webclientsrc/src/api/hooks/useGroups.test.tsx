// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useGroups, useGroup, useCreateGroup, useUpdateGroup, useDeleteGroup } from './useGroups'

const mockListGroups = vi.fn()
const mockCountGroups = vi.fn()
const mockGetGroup = vi.fn()
const mockCreateGroup = vi.fn()
const mockUpdateGroup = vi.fn()
const mockDeleteGroup = vi.fn()

vi.mock('@generated', () => ({
  listGroups: (...args: unknown[]) => mockListGroups(...args),
  countGroups: (...args: unknown[]) => mockCountGroups(...args),
  getGroup: (...args: unknown[]) => mockGetGroup(...args),
  createGroup: (...args: unknown[]) => mockCreateGroup(...args),
  updateGroup: (...args: unknown[]) => mockUpdateGroup(...args),
  deleteGroup: (...args: unknown[]) => mockDeleteGroup(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useGroups', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns groups on success', async () => {
    mockListGroups.mockResolvedValue({
      data: [{ id: 'g1', name: 'admins' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useGroups('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].name).toBe('admins')
  })

  it('throws on error response', async () => {
    mockListGroups.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useGroups('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useGroups(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('returns group by id on success', async () => {
    mockGetGroup.mockResolvedValue({
      data: { id: 'g1', name: 'admins' },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useGroup('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.name).toBe('admins')
  })

  it('throws on getGroup error', async () => {
    mockGetGroup.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useGroup('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Not found')
  })

  it('is disabled when id is empty', () => {
    const { result } = renderHook(() => useGroup('master', ''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('creates a group', async () => {
    mockCreateGroup.mockResolvedValue({
      data: { id: 'g2', name: 'users' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'users' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateGroup).toHaveBeenCalledWith({ path: { realm: 'master' }, body: { name: 'users' } })
  })

  it('updates a group', async () => {
    mockUpdateGroup.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useUpdateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'superusers' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateGroup).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1' }, body: { name: 'superusers' } })
  })

  it('deletes a group', async () => {
    mockDeleteGroup.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeleteGroup).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1' } })
  })

  it('throws on createGroup error', async () => {
    mockCreateGroup.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad request' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateGroup(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { name: 'users' } })).rejects.toThrow('bad request')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('bad request')
  })

  it('throws on updateGroup error', async () => {
    mockUpdateGroup.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUpdateGroup(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'superusers' } })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on deleteGroup error', async () => {
    mockDeleteGroup.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useDeleteGroup(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'g1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })
})
