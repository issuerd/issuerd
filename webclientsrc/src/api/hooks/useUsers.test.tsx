// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useUsers,
  useUser,
  useCreateUser,
  useUpdateUser,
  useDeleteUser,
  useResetPassword,
  useUserSessions,
  useUserGroups,
  useUserRealmRoles,
  useAddUserGroup,
  useRemoveUserGroup,
  useAddUserRealmRoles,
  useRemoveUserRealmRoles,
} from './useUsers'

const mockListUsers = vi.fn()
const mockCountUsers = vi.fn()
const mockGetUser = vi.fn()
const mockCreateUser = vi.fn()
const mockUpdateUser = vi.fn()
const mockDeleteUser = vi.fn()
const mockResetPassword = vi.fn()
const mockGetUserSessions = vi.fn()
const mockGetUserGroups = vi.fn()
const mockGetUserRealmRoles = vi.fn()
const mockAddUserGroup = vi.fn()
const mockRemoveUserGroup = vi.fn()
const mockAddUserRealmRoles = vi.fn()
const mockRemoveUserRealmRoles = vi.fn()

vi.mock('@generated', () => ({
  listUsers: (...args: unknown[]) => mockListUsers(...args),
  countUsers: (...args: unknown[]) => mockCountUsers(...args),
  getUser: (...args: unknown[]) => mockGetUser(...args),
  createUser: (...args: unknown[]) => mockCreateUser(...args),
  updateUser: (...args: unknown[]) => mockUpdateUser(...args),
  deleteUser: (...args: unknown[]) => mockDeleteUser(...args),
  resetPassword: (...args: unknown[]) => mockResetPassword(...args),
  getUserSessions: (...args: unknown[]) => mockGetUserSessions(...args),
  getUserGroups: (...args: unknown[]) => mockGetUserGroups(...args),
  getUserRealmRoles: (...args: unknown[]) => mockGetUserRealmRoles(...args),
  addUserGroup: (...args: unknown[]) => mockAddUserGroup(...args),
  removeUserGroup: (...args: unknown[]) => mockRemoveUserGroup(...args),
  addUserRealmRoles: (...args: unknown[]) => mockAddUserRealmRoles(...args),
  removeUserRealmRoles: (...args: unknown[]) => mockRemoveUserRealmRoles(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useUsers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns users on success', async () => {
    mockListUsers.mockResolvedValue({
      data: [{ id: 'u1', username: 'alice' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUsers('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].username).toBe('alice')
  })

  it('returns users with search param', async () => {
    mockListUsers.mockResolvedValue({
      data: [{ id: 'u1', username: 'alice' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUsers('master', { search: 'alice' }), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockListUsers).toHaveBeenCalledWith({ path: { realm: 'master' }, query: { search: 'alice' } })
  })

  it('throws on error response', async () => {
    mockListUsers.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useUsers('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('fetches user by id', async () => {
    mockGetUser.mockResolvedValue({
      data: { id: 'u1', username: 'bob' },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUser('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.username).toBe('bob')
  })

  it('creates a user', async () => {
    mockCreateUser.mockResolvedValue({
      data: { id: 'u2', username: 'charlie' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { username: 'charlie' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('sanitizeUserBody trims email, first_name, last_name in createUser', async () => {
    mockCreateUser.mockResolvedValue({
      data: { id: 'u2' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      body: { username: 'charlie', email: '  a@b.com  ', first_name: '  Charlie  ', last_name: '  Brown  ' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockCreateUser.mock.calls[0][0]
    expect(callArg.body.email).toBe('a@b.com')
    expect(callArg.body.first_name).toBe('Charlie')
    expect(callArg.body.last_name).toBe('Brown')
  })

  it('sanitizeUserBody converts empty strings to null in createUser', async () => {
    mockCreateUser.mockResolvedValue({
      data: { id: 'u2' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      body: { username: 'charlie', email: '   ', first_name: '   ', last_name: '   ' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockCreateUser.mock.calls[0][0]
    expect(callArg.body.email).toBeNull()
    expect(callArg.body.first_name).toBeNull()
    expect(callArg.body.last_name).toBeNull()
  })

  it('updates a user', async () => {
    mockUpdateUser.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useUpdateUser(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', body: { first_name: 'Bob' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('sanitizeUserBody trims fields in updateUser', async () => {
    mockUpdateUser.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useUpdateUser(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'u1',
      body: { email: '  a@b.com  ', first_name: '  Bob  ', last_name: '  Smith  ' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockUpdateUser.mock.calls[0][0]
    expect(callArg.body.email).toBe('a@b.com')
    expect(callArg.body.first_name).toBe('Bob')
    expect(callArg.body.last_name).toBe('Smith')
  })

  it('update user rollback on error', async () => {
    mockUpdateUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['users', 'master', 'u1'], { id: 'u1', username: 'alice' })
    qc.setQueryData(['users', 'master'], [{ id: 'u1', username: 'alice' }])
    const { result } = renderHook(() => useUpdateUser(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'u1', body: { first_name: 'Hacked' } })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master', 'u1'])).toEqual({ id: 'u1', username: 'alice' })
    expect(qc.getQueryData(['users', 'master'])).toEqual([{ id: 'u1', username: 'alice' }])
  })

  it('update user rollback gracefully when no previous cache', async () => {
    mockUpdateUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useUpdateUser(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'u1', body: { first_name: 'Hacked' } })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master', 'u1'])).toBeUndefined()
    expect(qc.getQueryData(['users', 'master'])).toBeUndefined()
  })

  it('deletes a user', async () => {
    mockDeleteUser.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteUser(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('delete user rollback on error', async () => {
    mockDeleteUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['users', 'master'], [{ id: 'u1', username: 'alice' }])
    const { result } = renderHook(() => useDeleteUser(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'u1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master'])).toEqual([{ id: 'u1', username: 'alice' }])
  })

  it('delete user rollback gracefully when no previous cache', async () => {
    mockDeleteUser.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useDeleteUser(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'u1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['users', 'master'])).toBeUndefined()
  })

  it('resets password', async () => {
    mockResetPassword.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useResetPassword(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', body: { type: 'password', value: 'secret' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockResetPassword).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' }, body: { type: 'password', value: 'secret' } })
  })

  it('fetches user sessions', async () => {
    mockGetUserSessions.mockResolvedValue({
      data: [{ id: 's1', user_id: 'u1' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUserSessions('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('fetches user groups', async () => {
    mockGetUserGroups.mockResolvedValue({
      data: [{ id: 'g1', name: 'admins' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUserGroups('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('fetches user realm roles', async () => {
    mockGetUserRealmRoles.mockResolvedValue({
      data: [{ id: 'r1', name: 'admin' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useUserRealmRoles('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('adds user group', async () => {
    mockAddUserGroup.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useAddUserGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockAddUserGroup).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1', group_id: 'g1' } })
  })

  it('removes user group', async () => {
    mockRemoveUserGroup.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useRemoveUserGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', groupId: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockRemoveUserGroup).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1', group_id: 'g1' } })
  })

  it('adds user realm roles', async () => {
    mockAddUserRealmRoles.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useAddUserRealmRoles(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', roles: ['admin', 'user'] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockAddUserRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' }, body: ['admin', 'user'] })
  })

  it('removes user realm roles', async () => {
    mockRemoveUserRealmRoles.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useRemoveUserRealmRoles(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', roles: ['admin'] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockRemoveUserRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' }, body: ['admin'] })
  })

  it('throws on getUser error', async () => {
    mockGetUser.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUser('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on createUser error', async () => {
    mockCreateUser.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad request' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { username: 'alice' } })).rejects.toThrow('bad request')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('bad request')
  })

  it('throws on resetPassword error', async () => {
    mockResetPassword.mockResolvedValue({ data: undefined, error: { errorMessage: 'weak password' }, response: { status: 400 } })
    const { result } = renderHook(() => useResetPassword(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1', body: { type: 'password', value: '123' } })).rejects.toThrow('weak password')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('weak password')
  })

  it('lists policy violations in the resetPassword error message', async () => {
    mockResetPassword.mockResolvedValue({
      data: undefined,
      error: {
        errorMessage:
          'password policy violation: [min_length] password must be at least 8 characters long',
        policyViolations: [
          { code: 'min_length', message: 'password must be at least 8 characters long' },
          { code: 'not_username', message: 'password must not contain the username' },
        ],
      },
      response: { status: 400 },
    })
    const { result } = renderHook(() => useResetPassword(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'u1', body: { type: 'password', value: '123' } })
    ).rejects.toThrow('password must be at least 8 characters long')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe(
      '• password must be at least 8 characters long\n• password must not contain the username'
    )
  })

  it('throws on addUserGroup error', async () => {
    mockAddUserGroup.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useAddUserGroup(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1', groupId: 'g1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on removeUserGroup error', async () => {
    mockRemoveUserGroup.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useRemoveUserGroup(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1', groupId: 'g1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on addUserRealmRoles error', async () => {
    mockAddUserRealmRoles.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useAddUserRealmRoles(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1', roles: ['admin'] })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on getUserSessions error', async () => {
    mockGetUserSessions.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUserSessions('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on getUserGroups error', async () => {
    mockGetUserGroups.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUserGroups('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on getUserRealmRoles error', async () => {
    mockGetUserRealmRoles.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUserRealmRoles('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on removeUserRealmRoles error', async () => {
    mockRemoveUserRealmRoles.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useRemoveUserRealmRoles(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1', roles: ['admin'] })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })
})
