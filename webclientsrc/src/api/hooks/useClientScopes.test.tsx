// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useClientScopes,
  useClientScope,
  useCreateClientScope,
  useUpdateClientScope,
  useDeleteClientScope,
  useScopeMappers,
  useCreateScopeMapper,
  useUpdateScopeMapper,
  useDeleteScopeMapper,
} from './useClientScopes'

const mockListClientScopes = vi.fn()
const mockGetClientScope = vi.fn()
const mockCreateClientScope = vi.fn()
const mockUpdateClientScope = vi.fn()
const mockDeleteClientScope = vi.fn()
const mockListScopeMappers = vi.fn()
const mockCreateScopeMapper = vi.fn()
const mockUpdateScopeMapper = vi.fn()
const mockDeleteScopeMapper = vi.fn()

vi.mock('@generated', () => ({
  listClientScopes: (...args: unknown[]) => mockListClientScopes(...args),
  getClientScope: (...args: unknown[]) => mockGetClientScope(...args),
  createClientScope: (...args: unknown[]) => mockCreateClientScope(...args),
  updateClientScope: (...args: unknown[]) => mockUpdateClientScope(...args),
  deleteClientScope: (...args: unknown[]) => mockDeleteClientScope(...args),
  listScopeMappers: (...args: unknown[]) => mockListScopeMappers(...args),
  createScopeMapper: (...args: unknown[]) => mockCreateScopeMapper(...args),
  updateScopeMapper: (...args: unknown[]) => mockUpdateScopeMapper(...args),
  deleteScopeMapper: (...args: unknown[]) => mockDeleteScopeMapper(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useClientScopes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists client scopes', async () => {
    mockListClientScopes.mockResolvedValue({ data: [{ id: 's1', name: 'profile' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClientScopes('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(mockListClientScopes).toHaveBeenCalledWith({ path: { realm: 'master' } })
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useClientScopes(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('fetches a single client scope', async () => {
    mockGetClientScope.mockResolvedValue({ data: { id: 's1', name: 'profile', protocol_mappers: [] }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClientScope('master', 's1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.name).toBe('profile')
  })

  it('creates a client scope', async () => {
    mockCreateClientScope.mockResolvedValue({ data: { id: 's2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClientScope(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { name: 'custom' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateClientScope).toHaveBeenCalledWith({ path: { realm: 'master' }, body: { name: 'custom' } })
  })

  it('updates a client scope', async () => {
    mockUpdateClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateClientScope(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 's1', body: { name: 'profile', description: 'd' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('deletes a client scope', async () => {
    mockDeleteClientScope.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteClientScope(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 's1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('throws on listClientScopes error', async () => {
    mockListClientScopes.mockResolvedValue({ data: undefined, error: { errorMessage: 'fail' }, response: { status: 500 } })
    const { result } = renderHook(() => useClientScopes('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('fail')
  })

  it('throws on createClientScope error', async () => {
    mockCreateClientScope.mockResolvedValue({ data: undefined, error: { errorMessage: 'conflict' }, response: { status: 409 } })
    const { result } = renderHook(() => useCreateClientScope(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { name: 'x' } })).rejects.toThrow('conflict')
  })

  it('lists scope mappers', async () => {
    mockListScopeMappers.mockResolvedValue({ data: [{ id: 'm1', name: 'dep' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useScopeMappers('master', 's1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(mockListScopeMappers).toHaveBeenCalledWith({ path: { realm: 'master', id: 's1' } })
  })

  it('is disabled when scope id is empty', () => {
    const { result } = renderHook(() => useScopeMappers('master', ''), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('creates a scope mapper', async () => {
    mockCreateScopeMapper.mockResolvedValue({ data: { id: 'm1' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateScopeMapper(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      scopeId: 's1',
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateScopeMapper).toHaveBeenCalledWith({
      path: { realm: 'master', id: 's1' },
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
  })

  it('updates a scope mapper', async () => {
    mockUpdateScopeMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateScopeMapper(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      scopeId: 's1',
      mapperId: 'm1',
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateScopeMapper).toHaveBeenCalledWith({
      path: { realm: 'master', id: 's1', mapper_id: 'm1' },
      body: { name: 'dep', protocol_mapper: 'oidc-usermodel-attribute-mapper' },
    })
  })

  it('deletes a scope mapper', async () => {
    mockDeleteScopeMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteScopeMapper(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', scopeId: 's1', mapperId: 'm1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('throws on createScopeMapper error', async () => {
    mockCreateScopeMapper.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad mapper' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateScopeMapper(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', scopeId: 's1', body: { name: 'x', protocol_mapper: 'oidc-full-name-mapper' } })
    ).rejects.toThrow('bad mapper')
  })
})
