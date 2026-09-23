// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useKeys, useRotateKeys, useDisableKey } from './useKeys'
import { useToastStore } from '../../stores/toastStore'

const mockGetKeys = vi.fn()
const mockRotateKeys = vi.fn()
const mockDisableKey = vi.fn()

vi.mock('@generated', () => ({
  getKeys: (...args: unknown[]) => mockGetKeys(...args),
  rotateKeys: (...args: unknown[]) => mockRotateKeys(...args),
  disableKey: (...args: unknown[]) => mockDisableKey(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useKeys', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetches keys', async () => {
    mockGetKeys.mockResolvedValue({ data: [{ kid: 'k1' }], error: undefined })
    const { result } = renderHook(() => useKeys('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ kid: 'k1' }])
  })

  it('throws on error', async () => {
    mockGetKeys.mockResolvedValue({ data: undefined, error: { errorMessage: 'fail' } })
    const { result } = renderHook(() => useKeys('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('fail')
  })
})

describe('useRotateKeys', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('posts to the rotate endpoint, invalidates the keys query, and toasts', async () => {
    mockRotateKeys.mockResolvedValue({ data: undefined, error: undefined })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const invalidateSpy = vi.spyOn(client, 'invalidateQueries')
    const localWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useRotateKeys(), { wrapper: localWrapper })
    await result.current.mutateAsync({ realm: 'master' })
    expect(mockRotateKeys).toHaveBeenCalledWith({ path: { realm: 'master' }, body: {} })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['keys', 'master'] })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Keys rotated',
        type: 'success',
      })
    )
  })

  it('passes an explicit algorithm through as the request body', async () => {
    mockRotateKeys.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useRotateKeys(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', algorithm: 'ES256' })
    expect(mockRotateKeys).toHaveBeenCalledWith({
      path: { realm: 'master' },
      body: { algorithm: 'ES256' },
    })
  })

  it('toasts and throws on error', async () => {
    mockRotateKeys.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'forbidden' },
    })
    const { result } = renderHook(() => useRotateKeys(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master' })).rejects.toThrow('forbidden')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to rotate keys',
      type: 'error',
    })
  })
})

describe('useDisableKey', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('puts to the disable endpoint and invalidates the keys query', async () => {
    mockDisableKey.mockResolvedValue({ data: undefined, error: undefined })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const invalidateSpy = vi.spyOn(client, 'invalidateQueries')
    const localWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useDisableKey(), { wrapper: localWrapper })
    await result.current.mutateAsync({ realm: 'master', kid: 'k1' })
    expect(mockDisableKey).toHaveBeenCalledWith({ path: { realm: 'master', kid: 'k1' } })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['keys', 'master'] })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Key disabled',
        type: 'success',
      })
    )
  })

  it('surfaces the last-active-key 400 as an error toast', async () => {
    mockDisableKey.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'cannot disable the only active key' },
    })
    const { result } = renderHook(() => useDisableKey(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', kid: 'k1' })).rejects.toThrow(
      'cannot disable the only active key'
    )
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to disable key',
      message: 'cannot disable the only active key',
      type: 'error',
    })
  })
})
