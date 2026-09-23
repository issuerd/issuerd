// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useGroupMembers, useCreateChildGroup, useMoveGroup } from './useGroupTree'
import { useToastStore } from '../../stores/toastStore'

const mockGetGroupMembers = vi.fn()
const mockCreateChildGroup = vi.fn()
const mockUpdateGroup = vi.fn()

vi.mock('@generated', () => ({
  getGroupMembers: (...args: unknown[]) => mockGetGroupMembers(...args),
  createChildGroup: (...args: unknown[]) => mockCreateChildGroup(...args),
  updateGroup: (...args: unknown[]) => mockUpdateGroup(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useGroupMembers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('fetches members with pagination parameters', async () => {
    mockGetGroupMembers.mockResolvedValue({
      data: [{ id: 'u1', username: 'alice' }],
      error: undefined,
    })
    const { result } = renderHook(() => useGroupMembers('master', 'g1', { first: 20, max: 20 }), {
      wrapper,
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ id: 'u1', username: 'alice' }])
    expect(mockGetGroupMembers).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'g1' },
      query: { first: 20, max: 20 },
    })
  })

  it('surfaces API errors', async () => {
    mockGetGroupMembers.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'group not found' },
    })
    const { result } = renderHook(() => useGroupMembers('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('group not found')
  })
})

describe('useCreateChildGroup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('posts the child name under the parent group', async () => {
    mockCreateChildGroup.mockResolvedValue({
      data: { id: 'g2', name: 'backend', parent_id: 'g1', path: '/developers/backend' },
      error: undefined,
    })
    const { result } = renderHook(() => useCreateChildGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'backend' } })
    expect(mockCreateChildGroup).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'g1' },
      body: { name: 'backend' },
    })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Sub-group created',
        type: 'success',
      })
    )
  })

  it('toasts and throws on conflict', async () => {
    mockCreateChildGroup.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'group name already exists' },
    })
    const { result } = renderHook(() => useCreateChildGroup(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'backend' } })
    ).rejects.toThrow('group name already exists')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to create sub-group',
      type: 'error',
    })
  })
})

describe('useMoveGroup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('moves under a parent by id', async () => {
    mockUpdateGroup.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useMoveGroup(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'g2',
      body: { name: 'backend', parent_id: 'g1' },
    })
    expect(mockUpdateGroup).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'g2' },
      body: { name: 'backend', parent_id: 'g1' },
    })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Group moved',
        type: 'success',
      })
    )
  })

  it('sends explicit null to move to the root', async () => {
    mockUpdateGroup.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useMoveGroup(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'g2',
      body: { name: 'backend', parent_id: null },
    })
    expect(mockUpdateGroup).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'g2' },
      body: { name: 'backend', parent_id: null },
    })
  })

  it('surfaces a cycle rejection (400) as an error toast', async () => {
    mockUpdateGroup.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'move would create a cycle' },
    })
    const { result } = renderHook(() => useMoveGroup(), { wrapper })
    await expect(
      result.current.mutateAsync({
        realm: 'master',
        id: 'g1',
        body: { name: 'developers', parent_id: 'g2' },
      })
    ).rejects.toThrow('move would create a cycle')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to move group',
      message: 'move would create a cycle',
      type: 'error',
    })
  })
})
