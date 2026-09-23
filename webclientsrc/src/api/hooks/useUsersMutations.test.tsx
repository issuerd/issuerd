// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useUpdateUser,
  useDeleteUser,
  useResetPassword,
  useAddUserGroup,
  useRemoveUserGroup,
  useAddUserRealmRoles,
  useRemoveUserRealmRoles,
} from './useUsers'

const mockUpdateUser = vi.fn()
const mockDeleteUser = vi.fn()
const mockResetPassword = vi.fn()
const mockAddUserGroup = vi.fn()
const mockRemoveUserGroup = vi.fn()
const mockAddUserRealmRoles = vi.fn()
const mockRemoveUserRealmRoles = vi.fn()

vi.mock('@generated', () => ({
  updateUser: (...args: unknown[]) => mockUpdateUser(...args),
  deleteUser: (...args: unknown[]) => mockDeleteUser(...args),
  resetPassword: (...args: unknown[]) => mockResetPassword(...args),
  addUserGroup: (...args: unknown[]) => mockAddUserGroup(...args),
  removeUserGroup: (...args: unknown[]) => mockRemoveUserGroup(...args),
  addUserRealmRoles: (...args: unknown[]) => mockAddUserRealmRoles(...args),
  removeUserRealmRoles: (...args: unknown[]) => mockRemoveUserRealmRoles(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useUsers mutations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useUpdateUser updates a user', async () => {
    mockUpdateUser.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateUser(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', body: { username: 'alice' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateUser rolls back on error', async () => {
    mockUpdateUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['users', 'master', 'u1'], { id: 'u1', username: 'old' })
    qc.setQueryData(['users', 'master'], [{ id: 'u1', username: 'old' }])
    const { result } = renderHook(() => useUpdateUser(), { wrapper: customWrapper })
    try {
      await result.current.mutateAsync({ realm: 'master', id: 'u1', body: { username: 'alice' } })
    } catch { /* expected */ }
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master', 'u1'])).toEqual({ id: 'u1', username: 'old' })
    expect(qc.getQueryData(['users', 'master'])).toEqual([{ id: 'u1', username: 'old' }])
  })

  it('useDeleteUser deletes a user', async () => {
    mockDeleteUser.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteUser(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteUser rolls back on error', async () => {
    mockDeleteUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['users', 'master'], [{ id: 'u1', username: 'alice' }])
    const { result } = renderHook(() => useDeleteUser(), { wrapper: customWrapper })
    try {
      await result.current.mutateAsync({ realm: 'master', id: 'u1' })
    } catch { /* expected */ }
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master'])).toEqual([{ id: 'u1', username: 'alice' }])
  })

  it('useResetPassword resets password', async () => {
    mockResetPassword.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useResetPassword(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', body: { type: 'password', value: 'secret', temporary: false } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useAddUserGroup adds a group', async () => {
    mockAddUserGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useAddUserGroup(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useAddUserGroup shows error toast on failure', async () => {
    mockAddUserGroup.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useAddUserGroup(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('useRemoveUserGroup removes a group', async () => {
    mockRemoveUserGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useRemoveUserGroup(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useRemoveUserGroup shows error toast on failure', async () => {
    mockRemoveUserGroup.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useRemoveUserGroup(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('useAddUserRealmRoles adds roles', async () => {
    mockAddUserRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useAddUserRealmRoles(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', roles: [{ id: 'r1', name: 'r1' }] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useAddUserRealmRoles shows error toast on failure', async () => {
    mockAddUserRealmRoles.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useAddUserRealmRoles(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', roles: [{ id: 'r1', name: 'r1' }] })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('useRemoveUserRealmRoles removes roles', async () => {
    mockRemoveUserRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useRemoveUserRealmRoles(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', roles: [{ id: 'r1', name: 'r1' }] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useRemoveUserRealmRoles shows error toast on failure', async () => {
    mockRemoveUserRealmRoles.mockRejectedValue(new Error('fail'))
    const { result } = renderHook(() => useRemoveUserRealmRoles(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'u1', roles: [{ id: 'r1', name: 'r1' }] })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })
})
