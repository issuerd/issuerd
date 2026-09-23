// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useClients,
  useClient,
  useCreateClient,
  useUpdateClient,
  useDeleteClient,
  useRotateClientSecret,
  useGetClientSecret,
} from './useClients'

const mockListClients = vi.fn()
const mockCountClients = vi.fn()
const mockGetClient = vi.fn()
const mockCreateClient = vi.fn()
const mockUpdateClient = vi.fn()
const mockDeleteClient = vi.fn()
const mockRotateClientSecret = vi.fn()
const mockGetClientSecret = vi.fn()

vi.mock('@generated', () => ({
  listClients: (...args: unknown[]) => mockListClients(...args),
  countClients: (...args: unknown[]) => mockCountClients(...args),
  getClient: (...args: unknown[]) => mockGetClient(...args),
  createClient: (...args: unknown[]) => mockCreateClient(...args),
  updateClient: (...args: unknown[]) => mockUpdateClient(...args),
  deleteClient: (...args: unknown[]) => mockDeleteClient(...args),
  rotateClientSecret: (...args: unknown[]) => mockRotateClientSecret(...args),
  getClientSecret: (...args: unknown[]) => mockGetClientSecret(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useClients', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns clients', async () => {
    mockListClients.mockResolvedValue({ data: [{ id: 'c1' }], error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClients('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toHaveLength(1)
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useClients(''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('returns client by id', async () => {
    mockGetClient.mockResolvedValue({ data: { id: 'c1' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useClient('master', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.id).toBe('c1')
  })

  it('is disabled when client id is empty', () => {
    const { result } = renderHook(() => useClient('master', ''), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('create client', async () => {
    mockCreateClient.mockResolvedValue({ data: { id: 'c2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { client_id: 'app' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('sanitizeClientBody trims name in createClient', async () => {
    mockCreateClient.mockResolvedValue({ data: { id: 'c2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { client_id: 'app', name: '  App  ' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockCreateClient.mock.calls[0][0]
    expect(callArg.body.name).toBe('App')
  })

  it('sanitizeClientBody converts empty name to null in createClient', async () => {
    mockCreateClient.mockResolvedValue({ data: { id: 'c2' }, error: undefined, response: { status: 201 } })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { client_id: 'app', name: '   ' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockCreateClient.mock.calls[0][0]
    expect(callArg.body.name).toBeNull()
  })

  it('update client', async () => {
    mockUpdateClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1', body: { name: 'App' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('sanitizeClientBody trims name in updateClient', async () => {
    mockUpdateClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1', body: { name: '  App  ' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const callArg = mockUpdateClient.mock.calls[0][0]
    expect(callArg.body.name).toBe('App')
  })

  it('update client rollback on error', async () => {
    mockUpdateClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['clients', 'master', 'c1'], { id: 'c1', name: 'Original' })
    qc.setQueryData(['clients', 'master'], [{ id: 'c1', name: 'Original' }])
    const { result } = renderHook(() => useUpdateClient(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'c1', body: { name: 'Updated' } })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master', 'c1'])).toEqual({ id: 'c1', name: 'Original' })
    expect(qc.getQueryData(['clients', 'master'])).toEqual([{ id: 'c1', name: 'Original' }])
  })

  it('update client rollback gracefully when no previous cache', async () => {
    mockUpdateClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useUpdateClient(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'c1', body: { name: 'Updated' } })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master', 'c1'])).toBeUndefined()
    expect(qc.getQueryData(['clients', 'master'])).toBeUndefined()
  })

  it('delete client', async () => {
    mockDeleteClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteClient(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('delete client rollback on error', async () => {
    mockDeleteClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['clients', 'master'], [{ id: 'c1', name: 'Original' }])
    const { result } = renderHook(() => useDeleteClient(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master'])).toEqual([{ id: 'c1', name: 'Original' }])
  })

  it('delete client rollback gracefully when no previous cache', async () => {
    mockDeleteClient.mockRejectedValue(new Error('fail'))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useDeleteClient(), { wrapper: customWrapper })
    result.current.mutate({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(qc.getQueryData(['clients', 'master'])).toBeUndefined()
  })

  it('rotate secret', async () => {
    mockRotateClientSecret.mockResolvedValue({ data: { value: 'secret' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useRotateClientSecret(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('get client secret', async () => {
    mockGetClientSecret.mockResolvedValue({ data: { value: 'secret' }, error: undefined, response: { status: 200 } })
    const { result } = renderHook(() => useGetClientSecret(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('throws on listClients error', async () => {
    mockListClients.mockResolvedValue({ data: undefined, error: { errorMessage: 'fail' }, response: { status: 500 } })
    const { result } = renderHook(() => useClients('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('fail')
  })

  it('throws on getClient error', async () => {
    mockGetClient.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useClient('master', 'c1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on createClient error', async () => {
    mockCreateClient.mockResolvedValue({ data: undefined, error: { errorMessage: 'bad request' }, response: { status: 400 } })
    const { result } = renderHook(() => useCreateClient(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', body: { client_id: 'app' } })).rejects.toThrow('bad request')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('bad request')
  })

  it('throws on rotateClientSecret error', async () => {
    mockRotateClientSecret.mockResolvedValue({ data: undefined, error: { errorMessage: 'denied' }, response: { status: 403 } })
    const { result } = renderHook(() => useRotateClientSecret(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'c1' })).rejects.toThrow('denied')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('denied')
  })

  it('throws on getClientSecret error', async () => {
    mockGetClientSecret.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useGetClientSecret(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'c1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on updateClient error', async () => {
    mockUpdateClient.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useUpdateClient(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'c1', body: { name: 'App' } })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('throws on deleteClient error', async () => {
    mockDeleteClient.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' }, response: { status: 404 } })
    const { result } = renderHook(() => useDeleteClient(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'c1' })).rejects.toThrow('not found')
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('not found')
  })

  it('update client optimistic update when list cache is undefined', async () => {
    mockUpdateClient.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    qc.setQueryData(['clients', 'master', 'c1'], { id: 'c1', name: 'Original' })
    // list cache is intentionally undefined
    const { result } = renderHook(() => useUpdateClient(), { wrapper: customWrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'c1', body: { name: 'Updated' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })
})
