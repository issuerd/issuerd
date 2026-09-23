// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useEventsConfig,
  useUpdateEventsConfig,
  useClearEvents,
  useClearAdminEvents,
} from './useEventsConfig'
import { useToastStore } from '../../stores/toastStore'

const mockGetEventsConfig = vi.fn()
const mockUpdateEventsConfig = vi.fn()
const mockClearEvents = vi.fn()
const mockClearAdminEvents = vi.fn()

vi.mock('@generated', () => ({
  getEventsConfig: (...args: unknown[]) => mockGetEventsConfig(...args),
  updateEventsConfig: (...args: unknown[]) => mockUpdateEventsConfig(...args),
  clearEvents: (...args: unknown[]) => mockClearEvents(...args),
  clearAdminEvents: (...args: unknown[]) => mockClearAdminEvents(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useEventsConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('fetches the events config for the realm', async () => {
    mockGetEventsConfig.mockResolvedValue({
      data: { eventsEnabled: true, eventsListeners: ['logging'] },
      error: undefined,
    })
    const { result } = renderHook(() => useEventsConfig('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockGetEventsConfig).toHaveBeenCalledWith({ path: { realm: 'master' } })
    expect(result.current.data).toEqual({ eventsEnabled: true, eventsListeners: ['logging'] })
  })

  it('throws on error', async () => {
    mockGetEventsConfig.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'boom' },
    })
    const { result } = renderHook(() => useEventsConfig('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('boom')
  })

  it('is disabled when realm is empty', () => {
    const { result } = renderHook(() => useEventsConfig(''), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(mockGetEventsConfig).not.toHaveBeenCalled()
  })

  it('keys the query per realm', async () => {
    mockGetEventsConfig.mockResolvedValue({ data: { eventsEnabled: false }, error: undefined })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const sharedWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
    renderHook(() => useEventsConfig('master'), { wrapper: sharedWrapper })
    renderHook(() => useEventsConfig('demo'), { wrapper: sharedWrapper })
    await waitFor(() => expect(mockGetEventsConfig).toHaveBeenCalledTimes(2))
    expect(client.getQueryData(['events-config', 'master'])).toBeDefined()
    expect(client.getQueryData(['events-config', 'demo'])).toBeDefined()
  })
})

describe('useUpdateEventsConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('sends path and body and toasts on success', async () => {
    mockUpdateEventsConfig.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useUpdateEventsConfig(), { wrapper })
    const body = {
      eventsEnabled: true,
      eventsExpiration: 3600,
      adminEventsEnabled: true,
      adminEventsDetailsEnabled: false,
      eventsListeners: ['logging'],
    }
    await result.current.mutateAsync({ realm: 'master', body })
    expect(mockUpdateEventsConfig).toHaveBeenCalledWith({ path: { realm: 'master' }, body })
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Events configuration saved',
      type: 'success',
    })
  })

  it('toasts and throws on error', async () => {
    mockUpdateEventsConfig.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'nope' },
    })
    const { result } = renderHook(() => useUpdateEventsConfig(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', body: {} })
    ).rejects.toThrow('nope')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to save events configuration',
      type: 'error',
    })
  })
})

describe('useClearEvents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('calls the clear endpoint and toasts on success', async () => {
    mockClearEvents.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useClearEvents(), { wrapper })
    await result.current.mutateAsync('master')
    expect(mockClearEvents).toHaveBeenCalledWith({ path: { realm: 'master' } })
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Events cleared',
      type: 'success',
    })
  })

  it('toasts and throws on error', async () => {
    mockClearEvents.mockResolvedValue({ data: undefined, error: { errorMessage: 'denied' } })
    const { result } = renderHook(() => useClearEvents(), { wrapper })
    await expect(result.current.mutateAsync('master')).rejects.toThrow('denied')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to clear events',
      type: 'error',
    })
  })
})

describe('useClearAdminEvents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('calls the clear endpoint and toasts on success', async () => {
    mockClearAdminEvents.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useClearAdminEvents(), { wrapper })
    await result.current.mutateAsync('master')
    expect(mockClearAdminEvents).toHaveBeenCalledWith({ path: { realm: 'master' } })
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Admin events cleared',
      type: 'success',
    })
  })

  it('toasts and throws on error', async () => {
    mockClearAdminEvents.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'denied' },
    })
    const { result } = renderHook(() => useClearAdminEvents(), { wrapper })
    await expect(result.current.mutateAsync('master')).rejects.toThrow('denied')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to clear admin events',
      type: 'error',
    })
  })
})
