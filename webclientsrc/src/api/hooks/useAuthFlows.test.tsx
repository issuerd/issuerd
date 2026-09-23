// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useFlows,
  useFlow,
  useCreateFlow,
  useCopyFlow,
  useDeleteFlow,
  useAddExecution,
  useAddFlowExecution,
  useUpdateExecution,
  useDeleteExecution,
  useExecutionConfig,
  useCreateExecutionConfig,
  useUpdateExecutionConfig,
  useDeleteExecutionConfig,
} from './useAuthFlows'
import { useToastStore } from '../../stores/toastStore'

const mockListFlows = vi.fn()
const mockGetFlow = vi.fn()
const mockCreateFlow = vi.fn()
const mockCopyFlow = vi.fn()
const mockDeleteFlow = vi.fn()
const mockAddExecution = vi.fn()
const mockAddFlowExecution = vi.fn()
const mockUpdateExecution = vi.fn()
const mockDeleteExecution = vi.fn()
const mockGetExecutionConfig = vi.fn()
const mockCreateExecutionConfig = vi.fn()
const mockUpdateExecutionConfig = vi.fn()
const mockDeleteExecutionConfig = vi.fn()

vi.mock('@generated', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
  getFlow: (...args: unknown[]) => mockGetFlow(...args),
  createFlow: (...args: unknown[]) => mockCreateFlow(...args),
  copyFlow: (...args: unknown[]) => mockCopyFlow(...args),
  deleteFlow: (...args: unknown[]) => mockDeleteFlow(...args),
  addExecution: (...args: unknown[]) => mockAddExecution(...args),
  addFlowExecution: (...args: unknown[]) => mockAddFlowExecution(...args),
  updateExecution: (...args: unknown[]) => mockUpdateExecution(...args),
  deleteExecution: (...args: unknown[]) => mockDeleteExecution(...args),
  getExecutionConfig: (...args: unknown[]) => mockGetExecutionConfig(...args),
  createExecutionConfig: (...args: unknown[]) => mockCreateExecutionConfig(...args),
  updateExecutionConfig: (...args: unknown[]) => mockUpdateExecutionConfig(...args),
  deleteExecutionConfig: (...args: unknown[]) => mockDeleteExecutionConfig(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useAuthFlows', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('fetches flows list', async () => {
    mockListFlows.mockResolvedValue({ data: [{ alias: 'browser' }], error: undefined })
    const { result } = renderHook(() => useFlows('master'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ alias: 'browser' }])
  })

  it('throws on flows error', async () => {
    mockListFlows.mockResolvedValue({ data: undefined, error: { errorMessage: 'fail' } })
    const { result } = renderHook(() => useFlows('master'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('fail')
  })

  it('fetches single flow', async () => {
    mockGetFlow.mockResolvedValue({ data: { alias: 'browser' }, error: undefined })
    const { result } = renderHook(() => useFlow('master', 'browser'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual({ alias: 'browser' })
  })

  it('throws on single flow error', async () => {
    mockGetFlow.mockResolvedValue({ data: undefined, error: { errorMessage: 'not found' } })
    const { result } = renderHook(() => useFlow('master', 'browser'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('not found')
  })

  it('useCreateFlow posts the flow body', async () => {
    mockCreateFlow.mockResolvedValue({ data: { alias: 'custom' }, error: undefined })
    const { result } = renderHook(() => useCreateFlow(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', body: { alias: 'custom' } })
    expect(mockCreateFlow).toHaveBeenCalledWith({ path: { realm: 'master' }, body: { alias: 'custom' } })
  })

  it('useCopyFlow posts newName to the copy endpoint', async () => {
    mockCopyFlow.mockResolvedValue({ data: { alias: 'browser copy' }, error: undefined })
    const { result } = renderHook(() => useCopyFlow(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'browser', body: { newName: 'browser copy' } })
    expect(mockCopyFlow).toHaveBeenCalledWith({
      path: { realm: 'master', flow_alias: 'browser' },
      body: { newName: 'browser copy' },
    })
  })

  it('useDeleteFlow deletes by alias', async () => {
    mockDeleteFlow.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteFlow(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', alias: 'custom' })
    expect(mockDeleteFlow).toHaveBeenCalledWith({ path: { realm: 'master', flow_alias: 'custom' } })
  })

  it('useDeleteFlow surfaces the server error message as a toast', async () => {
    mockDeleteFlow.mockResolvedValue({
      data: undefined,
      error: { errorMessage: "flow 'browser' cannot be deleted: it is referenced by the realm's 'browser_flow' binding" },
    })
    const { result } = renderHook(() => useDeleteFlow(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', alias: 'browser' })).rejects.toThrow(
      "flow 'browser' cannot be deleted",
    )
    const toasts = useToastStore.getState().toasts
    expect(toasts[0]?.type).toBe('error')
    expect(toasts[0]?.message).toContain('browser_flow')
  })

  it('useAddExecution posts provider + requirement', async () => {
    mockAddExecution.mockResolvedValue({ data: { id: 'e1' }, error: undefined })
    const { result } = renderHook(() => useAddExecution(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      flowAlias: 'custom',
      body: { provider: 'auth-username-password-form', requirement: 'required' },
    })
    expect(mockAddExecution).toHaveBeenCalledWith({
      path: { realm: 'master', flow_alias: 'custom' },
      body: { provider: 'auth-username-password-form', requirement: 'required' },
    })
  })

  it('useAddFlowExecution posts alias + requirement', async () => {
    mockAddFlowExecution.mockResolvedValue({ data: { id: 'e2' }, error: undefined })
    const { result } = renderHook(() => useAddFlowExecution(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      flowAlias: 'custom',
      body: { alias: 'sub', requirement: 'alternative' },
    })
    expect(mockAddFlowExecution).toHaveBeenCalledWith({
      path: { realm: 'master', flow_alias: 'custom' },
      body: { alias: 'sub', requirement: 'alternative' },
    })
  })

  it('useUpdateExecution sends an UpdateExecutionRequest-shaped body', async () => {
    mockUpdateExecution.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useUpdateExecution(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      flowAlias: 'custom',
      body: { id: 'e1', requirement: 'disabled' },
    })
    expect(mockUpdateExecution).toHaveBeenCalledWith({
      path: { realm: 'master', flow_alias: 'custom' },
      body: { id: 'e1', requirement: 'disabled' },
    })
  })

  it('useDeleteExecution deletes by execution id', async () => {
    mockDeleteExecution.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    const { result } = renderHook(() => useDeleteExecution(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', executionId: 'e1' })
    expect(mockDeleteExecution).toHaveBeenCalledWith({ path: { realm: 'master', execution_id: 'e1' } })
  })

  it('useExecutionConfig resolves 404 to null (no config attached)', async () => {
    mockGetExecutionConfig.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'not found' },
      response: { status: 404 },
    })
    const { result } = renderHook(() => useExecutionConfig('master', 'e1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeNull()
  })

  it('useExecutionConfig throws on non-404 errors', async () => {
    mockGetExecutionConfig.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'boom' },
      response: { status: 500 },
    })
    const { result } = renderHook(() => useExecutionConfig('master', 'e1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('boom')
  })

  it('execution config mutations hit the config endpoints', async () => {
    mockCreateExecutionConfig.mockResolvedValue({ data: { alias: 'c' }, error: undefined })
    mockUpdateExecutionConfig.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    mockDeleteExecutionConfig.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })

    const { result: createRes } = renderHook(() => useCreateExecutionConfig(), { wrapper })
    await createRes.current.mutateAsync({
      realm: 'master',
      executionId: 'e1',
      body: { alias: 'c', config: { k: 'v' } },
    })
    expect(mockCreateExecutionConfig).toHaveBeenCalledWith({
      path: { realm: 'master', execution_id: 'e1' },
      body: { alias: 'c', config: { k: 'v' } },
    })

    const { result: updateRes } = renderHook(() => useUpdateExecutionConfig(), { wrapper })
    await updateRes.current.mutateAsync({
      realm: 'master',
      executionId: 'e1',
      body: { alias: 'c', config: { k: 'v2' } },
    })
    expect(mockUpdateExecutionConfig).toHaveBeenCalledWith({
      path: { realm: 'master', execution_id: 'e1' },
      body: { alias: 'c', config: { k: 'v2' } },
    })

    const { result: deleteRes } = renderHook(() => useDeleteExecutionConfig(), { wrapper })
    await deleteRes.current.mutateAsync({ realm: 'master', executionId: 'e1' })
    expect(mockDeleteExecutionConfig).toHaveBeenCalledWith({ path: { realm: 'master', execution_id: 'e1' } })
  })
})
