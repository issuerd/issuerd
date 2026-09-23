// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useIdps,
  useIdp,
  useCreateIdp,
  useUpdateIdp,
  useDeleteIdp,
  useIdpMappers,
  useCreateIdpMapper,
  useUpdateIdpMapper,
  useDeleteIdpMapper,
  useTestIdpConnection,
} from './useIdentityProviders'

const mockListIdps = vi.fn()
const mockGetIdp = vi.fn()
const mockCreateIdp = vi.fn()
const mockUpdateIdp = vi.fn()
const mockDeleteIdp = vi.fn()
const mockListIdpMappers = vi.fn()
const mockCreateIdpMapper = vi.fn()
const mockUpdateIdpMapper = vi.fn()
const mockDeleteIdpMapper = vi.fn()
const mockTestIdpConnection = vi.fn()

vi.mock('@generated', () => ({
  listIdps: (...args: unknown[]) => mockListIdps(...args),
  getIdp: (...args: unknown[]) => mockGetIdp(...args),
  createIdp: (...args: unknown[]) => mockCreateIdp(...args),
  updateIdp: (...args: unknown[]) => mockUpdateIdp(...args),
  deleteIdp: (...args: unknown[]) => mockDeleteIdp(...args),
  listIdpMappers: (...args: unknown[]) => mockListIdpMappers(...args),
  createIdpMapper: (...args: unknown[]) => mockCreateIdpMapper(...args),
  updateIdpMapper: (...args: unknown[]) => mockUpdateIdpMapper(...args),
  deleteIdpMapper: (...args: unknown[]) => mockDeleteIdpMapper(...args),
  testIdpConnection: (...args: unknown[]) => mockTestIdpConnection(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useIdentityProviders', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns idps on success', async () => {
    mockListIdps.mockResolvedValue({
      data: [{ alias: 'ldap', providerId: 'ldap' }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useIdps('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].alias).toBe('ldap')
  })

  it('throws on error response', async () => {
    mockListIdps.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Forbidden' },
      response: { status: 403 },
    })
    const { result } = renderHook(() => useIdps('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useIdps(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('returns idp by alias on success', async () => {
    mockGetIdp.mockResolvedValue({
      data: { alias: 'ldap', providerId: 'ldap' },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useIdp('master', 'ldap'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.alias).toBe('ldap')
  })

  it('throws on getIdp error', async () => {
    mockGetIdp.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'Not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useIdp('master', 'ldap'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Not found')
  })

  it('is disabled when alias is empty', () => {
    const { result } = renderHook(() => useIdp('master', ''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('creates an idp', async () => {
    mockCreateIdp.mockResolvedValue({
      data: { alias: 'saml' },
      error: undefined,
      response: { status: 201 },
    })
    const { result } = renderHook(() => useCreateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { alias: 'saml', providerId: 'saml' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateIdp).toHaveBeenCalledWith({ path: { realm: 'master' }, body: { alias: 'saml', providerId: 'saml' } })
  })

  it('updates an idp', async () => {
    mockUpdateIdp.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useUpdateIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'ldap', body: { alias: 'ldap', enabled: false } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateIdp).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'ldap' }, body: { alias: 'ldap', enabled: false } })
  })

  it('deletes an idp', async () => {
    mockDeleteIdp.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { status: 204 },
    })
    const { result } = renderHook(() => useDeleteIdp(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'ldap' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeleteIdp).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'ldap' } })
  })

  it('throws on createIdp error', async () => {
    mockCreateIdp.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad request' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateIdp(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { alias: 'ldap' } })).rejects.toThrow('bad request')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('bad request')
  })

  it('throws on updateIdp error', async () => {
    mockUpdateIdp.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUpdateIdp(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', alias: 'ldap', body: { alias: 'ldap' } })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on deleteIdp error', async () => {
    mockDeleteIdp.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useDeleteIdp(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', alias: 'ldap' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })
})

describe('useIdentityProviders mappers + test-connection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists mappers for an idp', async () => {
    mockListIdpMappers.mockResolvedValue({
      data: [{ name: 'email', mapper_type: 'attribute', config: { claim: 'email', attribute: 'external_email' } }],
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useIdpMappers('master', 'google'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockListIdpMappers).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'google' } })
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].name).toBe('email')
  })

  it('creates a mapper', async () => {
    const body = { name: 'email', mapper_type: 'attribute' as const, config: { claim: 'email', attribute: 'external_email' } }
    mockCreateIdpMapper.mockResolvedValue({ data: body, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateIdpMapper(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google', body })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockCreateIdpMapper).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'google' }, body })
  })

  it('updates a mapper', async () => {
    const body = { name: 'email', mapper_type: 'attribute' as const, config: { claim: 'mail' } }
    mockUpdateIdpMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateIdpMapper(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google', name: 'email', body })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockUpdateIdpMapper).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'google', name: 'email' }, body })
  })

  it('deletes a mapper', async () => {
    mockDeleteIdpMapper.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteIdpMapper(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'google', name: 'email' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeleteIdpMapper).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'google', name: 'email' } })
  })

  it('throws on mapper list error', async () => {
    mockListIdpMappers.mockResolvedValue({ data: undefined, error: { errorMessage: 'Forbidden' }, response: { status: 403 } })
    const { result } = renderHook(() => useIdpMappers('master', 'google'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Forbidden')
  })

  it('returns the ok result of a successful test-connection', async () => {
    mockTestIdpConnection.mockResolvedValue({
      data: { status: 'ok', problems: [] },
      error: undefined,
      response: { status: 200 },
    })
    const { result } = renderHook(() => useTestIdpConnection(), { wrapper })
    const data = await result.current.mutateAsync({ realm: 'master', alias: 'google' })
    expect(mockTestIdpConnection).toHaveBeenCalledWith({ path: { realm: 'master', alias: 'google' } })
    expect(data).toEqual({ status: 'ok', problems: [] })
  })

  it('returns the problem list of a failed (400) test-connection instead of throwing', async () => {
    mockTestIdpConnection.mockResolvedValue({
      data: undefined,
      error: { status: 'error', problems: ['clientId is required'] },
      response: { status: 400 },
    })
    const { result } = renderHook(() => useTestIdpConnection(), { wrapper })
    const data = await result.current.mutateAsync({ realm: 'master', alias: 'google' })
    expect(data).toEqual({ status: 'error', problems: ['clientId is required'] })
  })

  it('throws on other test-connection errors', async () => {
    mockTestIdpConnection.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useTestIdpConnection(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', alias: 'nope' })).rejects.toThrow('not found')
  })
})
