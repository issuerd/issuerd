// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useGroup, useCreateGroup, useUpdateGroup, useDeleteGroup } from './useGroups'
import { useRealmRole, useCreateRealmRole, useUpdateRealmRole, useDeleteRealmRole } from './useRoles'
import { useIdp, useCreateIdp, useUpdateIdp, useDeleteIdp } from './useIdentityProviders'

const mockGetGroup = vi.fn()
const mockCreateGroup = vi.fn()
const mockUpdateGroup = vi.fn()
const mockDeleteGroup = vi.fn()
const mockGetRealmRole = vi.fn()
const mockCreateRealmRole = vi.fn()
const mockUpdateRealmRole = vi.fn()
const mockDeleteRealmRole = vi.fn()
const mockGetIdp = vi.fn()
const mockCreateIdp = vi.fn()
const mockUpdateIdp = vi.fn()
const mockDeleteIdp = vi.fn()

vi.mock('@generated', () => ({
  getGroup: (...args: unknown[]) => mockGetGroup(...args),
  createGroup: (...args: unknown[]) => mockCreateGroup(...args),
  updateGroup: (...args: unknown[]) => mockUpdateGroup(...args),
  deleteGroup: (...args: unknown[]) => mockDeleteGroup(...args),
  getRealmRole: (...args: unknown[]) => mockGetRealmRole(...args),
  createRealmRole: (...args: unknown[]) => mockCreateRealmRole(...args),
  updateRealmRole: (...args: unknown[]) => mockUpdateRealmRole(...args),
  deleteRealmRole: (...args: unknown[]) => mockDeleteRealmRole(...args),
  getIdp: (...args: unknown[]) => mockGetIdp(...args),
  createIdp: (...args: unknown[]) => mockCreateIdp(...args),
  updateIdp: (...args: unknown[]) => mockUpdateIdp(...args),
  deleteIdp: (...args: unknown[]) => mockDeleteIdp(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('detail hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useGroup fetches a group', async () => {
    mockGetGroup.mockResolvedValue({ data: { id: 'g1', name: 'admins' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useGroup('master', 'g1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.name).toBe('admins')
  })

  it('useRealmRole fetches a role', async () => {
    mockGetRealmRole.mockResolvedValue({ data: { name: 'admin' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useRealmRole('master', 'admin'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.name).toBe('admin')
  })

  it('useIdp fetches an IdP', async () => {
    mockGetIdp.mockResolvedValue({ data: { alias: 'google', provider_id: 'google' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useIdp('master', 'google'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.alias).toBe('google')
  })
})

describe('create/update/delete hooks invalidate queries', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useCreateGroup invalidates on success', async () => {
    mockCreateGroup.mockResolvedValue({ data: { id: 'g2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'users' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateGroup invalidates on success', async () => {
    mockUpdateGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'admins' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteGroup invalidates on success', async () => {
    mockDeleteGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useCreateRealmRole invalidates on success', async () => {
    mockCreateRealmRole.mockResolvedValue({ data: { name: 'user' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'user' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateRealmRole invalidates on success', async () => {
    mockUpdateRealmRole.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin', body: { name: 'admin' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteRealmRole invalidates on success', async () => {
    mockDeleteRealmRole.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useCreateIdp invalidates on success', async () => {
    mockCreateIdp.mockResolvedValue({ data: { alias: 'github' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { alias: 'github', provider_id: 'github' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateIdp invalidates on success', async () => {
    mockUpdateIdp.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google', body: { alias: 'google', provider_id: 'google' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteIdp invalidates on success', async () => {
    mockDeleteIdp.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })
})
