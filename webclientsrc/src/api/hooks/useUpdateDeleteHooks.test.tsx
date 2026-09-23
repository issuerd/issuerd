// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useUpdateClient, useDeleteClient, useRotateClientSecret, useGetClientSecret, useCreateClient,
} from './useClients'
import { useUpdateRealm, useDeleteRealm, useCreateRealm } from './useRealms'
import { useUpdateGroup, useDeleteGroup, useCreateGroup } from './useGroups'
import { useUpdateRealmRole, useDeleteRealmRole, useCreateRealmRole } from './useRoles'
import { useUpdateIdp, useDeleteIdp, useCreateIdp } from './useIdentityProviders'

const mockUpdateClient = vi.fn()
const mockDeleteClient = vi.fn()
const mockRotateClientSecret = vi.fn()
const mockGetClientSecret = vi.fn()
const mockCreateClient = vi.fn()
const mockUpdateRealm = vi.fn()
const mockDeleteRealm = vi.fn()
const mockCreateRealm = vi.fn()
const mockUpdateGroup = vi.fn()
const mockDeleteGroup = vi.fn()
const mockCreateGroup = vi.fn()
const mockUpdateRealmRole = vi.fn()
const mockDeleteRealmRole = vi.fn()
const mockCreateRealmRole = vi.fn()
const mockUpdateIdp = vi.fn()
const mockDeleteIdp = vi.fn()
const mockCreateIdp = vi.fn()

vi.mock('@generated', () => ({
  updateClient: (...args: unknown[]) => mockUpdateClient(...args),
  deleteClient: (...args: unknown[]) => mockDeleteClient(...args),
  rotateClientSecret: (...args: unknown[]) => mockRotateClientSecret(...args),
  getClientSecret: (...args: unknown[]) => mockGetClientSecret(...args),
  createClient: (...args: unknown[]) => mockCreateClient(...args),
  updateRealm: (...args: unknown[]) => mockUpdateRealm(...args),
  deleteRealm: (...args: unknown[]) => mockDeleteRealm(...args),
  createRealm: (...args: unknown[]) => mockCreateRealm(...args),
  updateGroup: (...args: unknown[]) => mockUpdateGroup(...args),
  deleteGroup: (...args: unknown[]) => mockDeleteGroup(...args),
  createGroup: (...args: unknown[]) => mockCreateGroup(...args),
  updateRealmRole: (...args: unknown[]) => mockUpdateRealmRole(...args),
  deleteRealmRole: (...args: unknown[]) => mockDeleteRealmRole(...args),
  createRealmRole: (...args: unknown[]) => mockCreateRealmRole(...args),
  updateIdp: (...args: unknown[]) => mockUpdateIdp(...args),
  deleteIdp: (...args: unknown[]) => mockDeleteIdp(...args),
  createIdp: (...args: unknown[]) => mockCreateIdp(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('update/delete hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('useUpdateClient updates a client', async () => {
    mockUpdateClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateClient(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'c1', body: { client_id: 'app' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateClient rolls back on error', async () => {
    mockUpdateClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['clients', 'master', 'c1'], { id: 'c1', client_id: 'old' })
    qc.setQueryData(['clients', 'master'], [{ id: 'c1', client_id: 'old' }])
    const { result } = renderHook(() => useUpdateClient(), { wrapper: customWrapper })
    try {
      await result.current.mutateAsync({ realm: 'master', id: 'c1', body: { client_id: 'app' } })
    } catch { /* expected */ }
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master', 'c1'])).toEqual({ id: 'c1', client_id: 'old' })
    expect(qc.getQueryData(['clients', 'master'])).toEqual([{ id: 'c1', client_id: 'old' }])
  })

  it('useDeleteClient deletes a client', async () => {
    mockDeleteClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteClient(), { wrapper })
    result.current.mutate({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteClient rolls back on error', async () => {
    mockDeleteClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['clients', 'master'], [{ id: 'c1', client_id: 'app' }])
    const { result } = renderHook(() => useDeleteClient(), { wrapper: customWrapper })
    try {
      await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    } catch { /* expected */ }
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master'])).toEqual([{ id: 'c1', client_id: 'app' }])
  })

  it('useRotateClientSecret rotates secret', async () => {
    mockRotateClientSecret.mockResolvedValue({ data: { value: 'new-secret' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useRotateClientSecret(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.value).toBe('new-secret')
  })

  it('useGetClientSecret gets secret', async () => {
    mockGetClientSecret.mockResolvedValue({ data: { value: 'secret' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useGetClientSecret(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.value).toBe('secret')
  })

  it('useCreateClient creates a client', async () => {
    mockCreateClient.mockResolvedValue({ data: { id: 'c2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { client_id: 'app2' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateRealm updates a realm', async () => {
    mockUpdateRealm.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateRealm(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { realm: 'master', enabled: true } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateRealm rolls back on error', async () => {
    mockUpdateRealm.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['realms', 'master'], { realm: 'master', enabled: true })
    qc.setQueryData(['realms'], [{ realm: 'master', enabled: true }])
    const { result } = renderHook(() => useUpdateRealm(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', body: { realm: 'master', enabled: false } })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['realms', 'master'])).toEqual({ realm: 'master', enabled: true })
    expect(qc.getQueryData(['realms'])).toEqual([{ realm: 'master', enabled: true }])
  })

  it('useDeleteRealm deletes a realm', async () => {
    mockDeleteRealm.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteRealm(), { wrapper })
    result.current.mutate('master')
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteRealm rolls back on error', async () => {
    mockDeleteRealm.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['realms'], [{ realm: 'master', enabled: true }])
    const { result } = renderHook(() => useDeleteRealm(), { wrapper: customWrapper })
    try {
      await result.current.mutateAsync('master')
    } catch { /* expected */ }
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['realms'])).toEqual([{ realm: 'master', enabled: true }])
  })

  it('useCreateRealm creates a realm', async () => {
    mockCreateRealm.mockResolvedValue({ data: { realm: 'new' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateRealm(), { wrapper })
    await result.current.mutateAsync({ realm: 'new', enabled: true })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateGroup updates a group', async () => {
    mockUpdateGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1', body: { name: 'admins' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteGroup deletes a group', async () => {
    mockDeleteGroup.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'g1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useCreateGroup creates a group', async () => {
    mockCreateGroup.mockResolvedValue({ data: { id: 'g2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateGroup(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'users' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateRealmRole updates a role', async () => {
    mockUpdateRealmRole.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin', body: { name: 'admin' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteRealmRole deletes a role', async () => {
    mockDeleteRealmRole.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', name: 'admin' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useCreateRealmRole creates a role', async () => {
    mockCreateRealmRole.mockResolvedValue({ data: { name: 'user' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateRealmRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'user' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useUpdateIdp updates an IdP', async () => {
    mockUpdateIdp.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google', body: { alias: 'google', provider_id: 'google' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useDeleteIdp deletes an IdP', async () => {
    mockDeleteIdp.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('useCreateIdp creates an IdP', async () => {
    mockCreateIdp.mockResolvedValue({ data: { alias: 'github' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { alias: 'github', provider_id: 'github' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })
})
