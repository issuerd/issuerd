// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useAvailableUserRealmRoles,
  useUserClientRoles,
  useAvailableUserClientRoles,
  useAddUserClientRoles,
  useRemoveUserClientRoles,
} from './useUsers'
import {
  useGroupRealmRoles,
  useAvailableGroupRealmRoles,
  useGroupClientRoles,
  useAvailableGroupClientRoles,
  useAddGroupRealmRoles,
  useRemoveGroupRealmRoles,
  useAddGroupClientRoles,
  useRemoveGroupClientRoles,
} from './useGroups'

const mockGetAvailableUserRealmRoles = vi.fn()
const mockGetUserClientRoles = vi.fn()
const mockGetAvailableUserClientRoles = vi.fn()
const mockAddUserClientRoles = vi.fn()
const mockRemoveUserClientRoles = vi.fn()
const mockGetGroupRealmRoles = vi.fn()
const mockGetAvailableGroupRealmRoles = vi.fn()
const mockGetGroupClientRoles = vi.fn()
const mockGetAvailableGroupClientRoles = vi.fn()
const mockAddGroupRealmRoles = vi.fn()
const mockRemoveGroupRealmRoles = vi.fn()
const mockAddGroupClientRoles = vi.fn()
const mockRemoveGroupClientRoles = vi.fn()

vi.mock('@generated', () => ({
  getAvailableUserRealmRoles: (...args: unknown[]) => mockGetAvailableUserRealmRoles(...args),
  getUserClientRoles: (...args: unknown[]) => mockGetUserClientRoles(...args),
  getAvailableUserClientRoles: (...args: unknown[]) => mockGetAvailableUserClientRoles(...args),
  addUserClientRoles: (...args: unknown[]) => mockAddUserClientRoles(...args),
  removeUserClientRoles: (...args: unknown[]) => mockRemoveUserClientRoles(...args),
  getGroupRealmRoles: (...args: unknown[]) => mockGetGroupRealmRoles(...args),
  getAvailableGroupRealmRoles: (...args: unknown[]) => mockGetAvailableGroupRealmRoles(...args),
  getGroupClientRoles: (...args: unknown[]) => mockGetGroupClientRoles(...args),
  getAvailableGroupClientRoles: (...args: unknown[]) => mockGetAvailableGroupClientRoles(...args),
  addGroupRealmRoles: (...args: unknown[]) => mockAddGroupRealmRoles(...args),
  removeGroupRealmRoles: (...args: unknown[]) => mockRemoveGroupRealmRoles(...args),
  addGroupClientRoles: (...args: unknown[]) => mockAddGroupClientRoles(...args),
  removeGroupClientRoles: (...args: unknown[]) => mockRemoveGroupClientRoles(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('user role-mapping hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetches available user realm roles', async () => {
    mockGetAvailableUserRealmRoles.mockResolvedValue({ data: [{ id: 'r1', name: 'admin' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useAvailableUserRealmRoles('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(mockGetAvailableUserRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' } })
  })

  it('fetches assigned user client roles', async () => {
    mockGetUserClientRoles.mockResolvedValue({ data: [{ id: 'r2', name: 'reader', client_role: true }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useUserClientRoles('master', 'u1', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockGetUserClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1', client_id: 'c1' } })
    expect(result.current.data?.[0].name).toBe('reader')
  })

  it('fetches available user client roles', async () => {
    mockGetAvailableUserClientRoles.mockResolvedValue({ data: [{ id: 'r3', name: 'writer' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useAvailableUserClientRoles('master', 'u1', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].name).toBe('writer')
  })

  it('user client-role queries are disabled when client id is empty', () => {
    const { result: assigned } = renderHook(() => useUserClientRoles('master', 'u1', ''), { wrapper })
    expect(assigned.current.fetchStatus).toBe('idle')
    const { result: available } = renderHook(() => useAvailableUserClientRoles('master', 'u1', ''), { wrapper })
    expect(available.current.fetchStatus).toBe('idle')
  })

  it('adds user client roles with RoleRepresentation bodies', async () => {
    mockAddUserClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r2', name: 'reader' }]
    const { result } = renderHook(() => useAddUserClientRoles(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', clientId: 'c1', roles })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockAddUserClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1', client_id: 'c1' }, body: roles })
  })

  it('removes user client roles', async () => {
    mockRemoveUserClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r2', name: 'reader' }]
    const { result } = renderHook(() => useRemoveUserClientRoles(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', clientId: 'c1', roles })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockRemoveUserClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1', client_id: 'c1' }, body: roles })
  })

  it('throws on addUserClientRoles error', async () => {
    mockAddUserClientRoles.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useAddUserClientRoles(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'u1', clientId: 'c1', roles: [{ id: 'rX', name: 'x' }] })
    ).rejects.toThrow('not found')
  })
})

describe('group role-mapping hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetches assigned group realm roles', async () => {
    mockGetGroupRealmRoles.mockResolvedValue({ data: [{ id: 'r1', name: 'admin' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useGroupRealmRoles('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockGetGroupRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1' } })
  })

  it('fetches available group realm roles', async () => {
    mockGetAvailableGroupRealmRoles.mockResolvedValue({ data: [{ id: 'r2', name: 'user' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useAvailableGroupRealmRoles('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[0].name).toBe('user')
  })

  it('fetches assigned and available group client roles', async () => {
    mockGetGroupClientRoles.mockResolvedValue({ data: [{ id: 'r3', name: 'reader' }], error: undefined, response: { status: 200 } })
    mockGetAvailableGroupClientRoles.mockResolvedValue({ data: [{ id: 'r4', name: 'writer' }], error: undefined, response: { status: 200 } })
    const { result: assigned } = renderHook(() => useGroupClientRoles('master', 'g1', 'c1'), { wrapper })
    const { result: available } = renderHook(() => useAvailableGroupClientRoles('master', 'g1', 'c1'), { wrapper })
    await waitFor(() => expect(assigned.current.isSuccess).toBe(true))
    await waitFor(() => expect(available.current.isSuccess).toBe(true))
    expect(mockGetGroupClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1', client_id: 'c1' } })
    expect(assigned.current.data?.[0].name).toBe('reader')
    expect(available.current.data?.[0].name).toBe('writer')
  })

  it('adds and removes group realm roles', async () => {
    mockAddGroupRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockRemoveGroupRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r1', name: 'admin' }]
    const { result: add } = renderHook(() => useAddGroupRealmRoles(), { wrapper })
    await add.current.mutateAsync({ realm: 'master', id: 'g1', roles })
    expect(mockAddGroupRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1' }, body: roles })
    const { result: remove } = renderHook(() => useRemoveGroupRealmRoles(), { wrapper })
    await remove.current.mutateAsync({ realm: 'master', id: 'g1', roles })
    expect(mockRemoveGroupRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1' }, body: roles })
  })

  it('adds and removes group client roles', async () => {
    mockAddGroupClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockRemoveGroupClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r3', name: 'reader' }]
    const { result: add } = renderHook(() => useAddGroupClientRoles(), { wrapper })
    await add.current.mutateAsync({ realm: 'master', id: 'g1', clientId: 'c1', roles })
    expect(mockAddGroupClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1', client_id: 'c1' }, body: roles })
    const { result: remove } = renderHook(() => useRemoveGroupClientRoles(), { wrapper })
    await remove.current.mutateAsync({ realm: 'master', id: 'g1', clientId: 'c1', roles })
    expect(mockRemoveGroupClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'g1', client_id: 'c1' }, body: roles })
  })

  it('throws on group role-mapping error', async () => {
    mockGetGroupRealmRoles.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useGroupRealmRoles('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })
})
