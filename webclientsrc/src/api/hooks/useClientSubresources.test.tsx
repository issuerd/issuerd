// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useClientRoles,
  useCreateClientRole,
  useDeleteClientRole,
  useClientMappers,
  useCreateClientMapper,
  useUpdateClientMapper,
  useDeleteClientMapper,
  useDefaultClientScopes,
  useOptionalClientScopes,
  useAssignDefaultClientScope,
  useUnassignDefaultClientScope,
  useAssignOptionalClientScope,
  useUnassignOptionalClientScope,
  useScopeMappingRealmRoles,
  useAvailableScopeMappingRealmRoles,
  useAddScopeMappingRealmRoles,
  useRemoveScopeMappingRealmRoles,
  useScopeMappingClientRoles,
  useAvailableScopeMappingClientRoles,
  useAddScopeMappingClientRoles,
  useRemoveScopeMappingClientRoles,
} from './useClients'

const mockListClientRoles = vi.fn()
const mockCreateClientRole = vi.fn()
const mockDeleteClientRole = vi.fn()
const mockListClientMappers = vi.fn()
const mockCreateClientMapper = vi.fn()
const mockUpdateClientMapper = vi.fn()
const mockDeleteClientMapper = vi.fn()
const mockGetDefaultClientScopes = vi.fn()
const mockAssignDefaultClientScope = vi.fn()
const mockUnassignDefaultClientScope = vi.fn()
const mockGetOptionalClientScopes = vi.fn()
const mockAssignOptionalClientScope = vi.fn()
const mockUnassignOptionalClientScope = vi.fn()
const mockGetScopeMappingRealmRoles = vi.fn()
const mockGetAvailableScopeMappingRealmRoles = vi.fn()
const mockAddScopeMappingRealmRoles = vi.fn()
const mockRemoveScopeMappingRealmRoles = vi.fn()
const mockGetScopeMappingClientRoles = vi.fn()
const mockGetAvailableScopeMappingClientRoles = vi.fn()
const mockAddScopeMappingClientRoles = vi.fn()
const mockRemoveScopeMappingClientRoles = vi.fn()

vi.mock('@generated', () => ({
  listClientRoles: (...args: unknown[]) => mockListClientRoles(...args),
  createClientRole: (...args: unknown[]) => mockCreateClientRole(...args),
  deleteClientRole: (...args: unknown[]) => mockDeleteClientRole(...args),
  listClientMappers: (...args: unknown[]) => mockListClientMappers(...args),
  createClientMapper: (...args: unknown[]) => mockCreateClientMapper(...args),
  updateClientMapper: (...args: unknown[]) => mockUpdateClientMapper(...args),
  deleteClientMapper: (...args: unknown[]) => mockDeleteClientMapper(...args),
  getDefaultClientScopes: (...args: unknown[]) => mockGetDefaultClientScopes(...args),
  assignDefaultClientScope: (...args: unknown[]) => mockAssignDefaultClientScope(...args),
  unassignDefaultClientScope: (...args: unknown[]) => mockUnassignDefaultClientScope(...args),
  getOptionalClientScopes: (...args: unknown[]) => mockGetOptionalClientScopes(...args),
  assignOptionalClientScope: (...args: unknown[]) => mockAssignOptionalClientScope(...args),
  unassignOptionalClientScope: (...args: unknown[]) => mockUnassignOptionalClientScope(...args),
  getScopeMappingRealmRoles: (...args: unknown[]) => mockGetScopeMappingRealmRoles(...args),
  getAvailableScopeMappingRealmRoles: (...args: unknown[]) => mockGetAvailableScopeMappingRealmRoles(...args),
  addScopeMappingRealmRoles: (...args: unknown[]) => mockAddScopeMappingRealmRoles(...args),
  removeScopeMappingRealmRoles: (...args: unknown[]) => mockRemoveScopeMappingRealmRoles(...args),
  getScopeMappingClientRoles: (...args: unknown[]) => mockGetScopeMappingClientRoles(...args),
  getAvailableScopeMappingClientRoles: (...args: unknown[]) => mockGetAvailableScopeMappingClientRoles(...args),
  addScopeMappingClientRoles: (...args: unknown[]) => mockAddScopeMappingClientRoles(...args),
  removeScopeMappingClientRoles: (...args: unknown[]) => mockRemoveScopeMappingClientRoles(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('client sub-resource hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists client roles', async () => {
    mockListClientRoles.mockResolvedValue({ data: [{ id: 'r1', name: 'reader', client_role: true }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClientRoles('master', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(mockListClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1' } })
  })

  it('creates a client role', async () => {
    mockCreateClientRole.mockResolvedValue({ data: { id: 'r2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClientRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', clientId: 'c1', body: { name: 'writer' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateClientRole).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1' }, body: { name: 'writer' } })
  })

  it('deletes a client role by name', async () => {
    mockDeleteClientRole.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteClientRole(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', clientId: 'c1', roleName: 'writer' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeleteClientRole).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', role_name: 'writer' } })
  })

  it('throws on createClientRole error', async () => {
    mockCreateClientRole.mockResolvedValue({ data: undefined, error: { errorMessage: 'conflict' }, response: { status: 409 } })
    const { result } = renderHook(() => useCreateClientRole(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', clientId: 'c1', body: { name: 'x' } })).rejects.toThrow('conflict')
  })

  it('lists client mappers', async () => {
    mockListClientMappers.mockResolvedValue({ data: [{ id: 'm1', name: 'dep' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClientMappers('master', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('creates a client mapper', async () => {
    mockCreateClientMapper.mockResolvedValue({ data: { id: 'm1' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClientMapper(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      clientId: 'c1',
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateClientMapper).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'c1' },
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
  })

  it('updates a client mapper', async () => {
    mockUpdateClientMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateClientMapper(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      clientId: 'c1',
      mapperId: 'm1',
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateClientMapper).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'c1', mapper_id: 'm1' },
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
  })

  it('deletes a client mapper', async () => {
    mockDeleteClientMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteClientMapper(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', clientId: 'c1', mapperId: 'm1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('fetches default and optional client scopes', async () => {
    mockGetDefaultClientScopes.mockResolvedValue({ data: [{ id: 's1', name: 'profile' }], error: undefined, response: { status: 200 } })
    mockGetOptionalClientScopes.mockResolvedValue({ data: [{ id: 's2', name: 'email' }], error: undefined, response: { status: 200 } })
    const { result: def } = renderHook(() => useDefaultClientScopes('master', 'c1'), { wrapper })
    const { result: opt } = renderHook(() => useOptionalClientScopes('master', 'c1'), { wrapper })
    await waitFor(() => expect(def.current.isSuccess).toBe(true))
    await waitFor(() => expect(opt.current.isSuccess).toBe(true))
    expect(def.current.data?.[0].name).toBe('profile')
    expect(opt.current.data?.[0].name).toBe('email')
  })

  it('assigns and unassigns default client scopes', async () => {
    mockAssignDefaultClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockUnassignDefaultClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result: assign } = renderHook(() => useAssignDefaultClientScope(), { wrapper })
    await assign.current.mutateAsync({ realm: 'master', clientId: 'c1', scopeId: 's1' })
    expect(mockAssignDefaultClientScope).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', scope_id: 's1' } })
    const { result: unassign } = renderHook(() => useUnassignDefaultClientScope(), { wrapper })
    await unassign.current.mutateAsync({ realm: 'master', clientId: 'c1', scopeId: 's1' })
    expect(mockUnassignDefaultClientScope).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', scope_id: 's1' } })
  })

  it('assigns and unassigns optional client scopes', async () => {
    mockAssignOptionalClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockUnassignOptionalClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result: assign } = renderHook(() => useAssignOptionalClientScope(), { wrapper })
    await assign.current.mutateAsync({ realm: 'master', clientId: 'c1', scopeId: 's2' })
    expect(mockAssignOptionalClientScope).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', scope_id: 's2' } })
    const { result: unassign } = renderHook(() => useUnassignOptionalClientScope(), { wrapper })
    await unassign.current.mutateAsync({ realm: 'master', clientId: 'c1', scopeId: 's2' })
    expect(mockUnassignOptionalClientScope).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', scope_id: 's2' } })
  })

  it('throws on assign error', async () => {
    mockAssignDefaultClientScope.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useAssignDefaultClientScope(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', clientId: 'c1', scopeId: 'sX' })).rejects.toThrow('not found')
  })

  it('fetches scope-mapping realm roles (assigned + available)', async () => {
    mockGetScopeMappingRealmRoles.mockResolvedValue({ data: [{ id: 'r1', name: 'admin' }], error: undefined, response: { status: 200 } })
    mockGetAvailableScopeMappingRealmRoles.mockResolvedValue({ data: [{ id: 'r2', name: 'user' }], error: undefined, response: { status: 200 } })
    const { result: assigned } = renderHook(() => useScopeMappingRealmRoles('master', 'c1'), { wrapper })
    const { result: available } = renderHook(() => useAvailableScopeMappingRealmRoles('master', 'c1'), { wrapper })
    await waitFor(() => expect(assigned.current.isSuccess).toBe(true))
    await waitFor(() => expect(available.current.isSuccess).toBe(true))
    expect(assigned.current.data?.[0].name).toBe('admin')
    expect(available.current.data?.[0].name).toBe('user')
  })

  it('adds and removes scope-mapping realm roles', async () => {
    mockAddScopeMappingRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockRemoveScopeMappingRealmRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r1', name: 'admin' }]
    const { result: add } = renderHook(() => useAddScopeMappingRealmRoles(), { wrapper })
    await add.current.mutateAsync({ realm: 'master', id: 'c1', roles })
    expect(mockAddScopeMappingRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1' }, body: roles })
    const { result: remove } = renderHook(() => useRemoveScopeMappingRealmRoles(), { wrapper })
    await remove.current.mutateAsync({ realm: 'master', id: 'c1', roles })
    expect(mockRemoveScopeMappingRealmRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1' }, body: roles })
  })

  it('fetches scope-mapping client roles (assigned + available)', async () => {
    mockGetScopeMappingClientRoles.mockResolvedValue({ data: [{ id: 'r3', name: 'reader' }], error: undefined, response: { status: 200 } })
    mockGetAvailableScopeMappingClientRoles.mockResolvedValue({ data: [{ id: 'r4', name: 'writer' }], error: undefined, response: { status: 200 } })
    const { result: assigned } = renderHook(() => useScopeMappingClientRoles('master', 'c1', 'c2'), { wrapper })
    const { result: available } = renderHook(() => useAvailableScopeMappingClientRoles('master', 'c1', 'c2'), { wrapper })
    await waitFor(() => expect(assigned.current.isSuccess).toBe(true))
    await waitFor(() => expect(available.current.isSuccess).toBe(true))
    expect(mockGetScopeMappingClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', client_id: 'c2' } })
    expect(assigned.current.data?.[0].name).toBe('reader')
    expect(available.current.data?.[0].name).toBe('writer')
  })

  it('adds and removes scope-mapping client roles', async () => {
    mockAddScopeMappingClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockRemoveScopeMappingClientRoles.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const roles = [{ id: 'r3', name: 'reader' }]
    const { result: add } = renderHook(() => useAddScopeMappingClientRoles(), { wrapper })
    await add.current.mutateAsync({ realm: 'master', id: 'c1', clientId: 'c2', roles })
    expect(mockAddScopeMappingClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', client_id: 'c2' }, body: roles })
    const { result: remove } = renderHook(() => useRemoveScopeMappingClientRoles(), { wrapper })
    await remove.current.mutateAsync({ realm: 'master', id: 'c1', clientId: 'c2', roles })
    expect(mockRemoveScopeMappingClientRoles).toHaveBeenCalledWith({ path: { realm: 'master', id: 'c1', client_id: 'c2' }, body: roles })
  })

  it('scope-mapping queries are disabled when ids are empty', () => {
    const { result: realmRoles } = renderHook(() => useScopeMappingRealmRoles('master', ''), { wrapper })
    expect(realmRoles.current.fetchStatus).toBe('idle')
    const { result: clientRoles } = renderHook(() => useScopeMappingClientRoles('master', 'c1', ''), { wrapper })
    expect(clientRoles.current.fetchStatus).toBe('idle')
  })
})
