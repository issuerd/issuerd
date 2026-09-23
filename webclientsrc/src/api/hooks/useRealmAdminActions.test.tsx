// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { usePartialImport, useExportRealm, usePushRevocation } from './useRealmAdminActions'
import { useToastStore } from '../../stores/toastStore'

const mockPartialImport = vi.fn()
const mockExportRealm = vi.fn()
const mockPushRevocation = vi.fn()

vi.mock('@generated', () => ({
  partialImport: (...args: unknown[]) => mockPartialImport(...args),
  exportRealm: (...args: unknown[]) => mockExportRealm(...args),
  pushRevocation: (...args: unknown[]) => mockPushRevocation(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('usePartialImport', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('sends body plus the conflict strategy as query parameter', async () => {
    const resultData = { added: 1, skipped: 0, updated: 0, results: [] }
    mockPartialImport.mockResolvedValue({ data: resultData, error: undefined })
    const { result } = renderHook(() => usePartialImport(), { wrapper })
    const body = { users: [{ username: 'alice' }] }
    const data = await result.current.mutateAsync({
      realm: 'master',
      body,
      ifResourceExists: 'SKIP',
    })
    expect(mockPartialImport).toHaveBeenCalledWith({
      path: { realm: 'master' },
      body,
      query: { ifResourceExists: 'SKIP' },
    })
    expect(data).toEqual(resultData)
  })

  it('toasts and throws on error', async () => {
    mockPartialImport.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'conflict: user alice exists' },
    })
    const { result } = renderHook(() => usePartialImport(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', body: {}, ifResourceExists: 'FAIL' })
    ).rejects.toThrow('conflict: user alice exists')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Import failed',
      type: 'error',
    })
  })
})

describe('useExportRealm', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('returns the export document', async () => {
    mockExportRealm.mockResolvedValue({
      data: { realm: 'master', users: [], clients: [] },
      error: undefined,
    })
    const { result } = renderHook(() => useExportRealm(), { wrapper })
    const data = await result.current.mutateAsync('master')
    expect(mockExportRealm).toHaveBeenCalledWith({ path: { realm: 'master' } })
    expect(data).toMatchObject({ realm: 'master' })
  })

  it('toasts and throws on error', async () => {
    mockExportRealm.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'forbidden' },
    })
    const { result } = renderHook(() => useExportRealm(), { wrapper })
    await expect(result.current.mutateAsync('master')).rejects.toThrow('forbidden')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Export failed',
      type: 'error',
    })
  })
})

describe('usePushRevocation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('posts and toasts on success', async () => {
    mockPushRevocation.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => usePushRevocation(), { wrapper })
    await result.current.mutateAsync('master')
    expect(mockPushRevocation).toHaveBeenCalledWith({ path: { realm: 'master' } })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Revocation pushed',
        type: 'success',
      })
    )
  })

  it('toasts and throws on error', async () => {
    mockPushRevocation.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'realm not found' },
    })
    const { result } = renderHook(() => usePushRevocation(), { wrapper })
    await expect(result.current.mutateAsync('master')).rejects.toThrow('realm not found')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to push revocation',
      type: 'error',
    })
  })
})
