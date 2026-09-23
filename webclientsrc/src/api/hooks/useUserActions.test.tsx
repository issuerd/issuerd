// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useImpersonateUser, useExecuteActionsEmail } from './useUserActions'
import { useToastStore } from '../../stores/toastStore'

const mockImpersonateUser = vi.fn()
const mockExecuteActionsEmail = vi.fn()

vi.mock('@generated', () => ({
  impersonateUser: (...args: unknown[]) => mockImpersonateUser(...args),
  executeActionsEmail: (...args: unknown[]) => mockExecuteActionsEmail(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useImpersonateUser', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('posts to the impersonation endpoint and toasts success without exposing tokens', async () => {
    mockImpersonateUser.mockResolvedValue({
      data: { access_token: 'secret-token', refresh_token: 'secret-refresh' },
      error: undefined,
    })
    const { result } = renderHook(() => useImpersonateUser(), { wrapper })
    const data = await result.current.mutateAsync({ realm: 'master', id: 'u1' })
    expect(mockImpersonateUser).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' } })
    // Returned tokens are deliberately dropped — nothing to hand back.
    expect(data).toBeUndefined()
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Impersonation session started',
        type: 'success',
      })
    )
  })

  it('toasts and throws on error', async () => {
    mockImpersonateUser.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'cannot impersonate yourself' },
    })
    const { result } = renderHook(() => useImpersonateUser(), { wrapper })
    await expect(result.current.mutateAsync({ realm: 'master', id: 'u1' })).rejects.toThrow(
      'cannot impersonate yourself'
    )
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Impersonation failed',
      message: 'cannot impersonate yourself',
      type: 'error',
    })
  })
})

describe('useExecuteActionsEmail', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('sends the action ids as body with optional query parameters', async () => {
    mockExecuteActionsEmail.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useExecuteActionsEmail(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'u1',
      actions: ['UPDATE_PASSWORD', 'VERIFY_EMAIL'],
      redirectUri: 'https://app.example.com/done',
      lifespan: 3600,
    })
    expect(mockExecuteActionsEmail).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1' },
      body: ['UPDATE_PASSWORD', 'VERIFY_EMAIL'],
      query: { redirect_uri: 'https://app.example.com/done', lifespan: 3600 },
    })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Action email sent',
        type: 'success',
      })
    )
  })

  it('omits optional query parameters when not provided', async () => {
    mockExecuteActionsEmail.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useExecuteActionsEmail(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', actions: ['TERMS_AND_CONDITIONS'] })
    expect(mockExecuteActionsEmail).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1' },
      body: ['TERMS_AND_CONDITIONS'],
      query: {},
    })
  })

  it('toasts and throws on error (e.g. user has no email)', async () => {
    mockExecuteActionsEmail.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'user has no email address' },
    })
    const { result } = renderHook(() => useExecuteActionsEmail(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'u1', actions: ['VERIFY_EMAIL'] })
    ).rejects.toThrow('user has no email address')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to send action email',
      message: 'user has no email address',
      type: 'error',
    })
  })
})
