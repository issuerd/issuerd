// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  useUserCredentials,
  useUpdateCredentialLabel,
  useDeleteCredential,
  useMoveCredential,
} from './useCredentials'
import { useToastStore } from '../../stores/toastStore'

const mockListUserCredentials = vi.fn()
const mockUpdateCredentialLabel = vi.fn()
const mockDeleteCredential = vi.fn()
const mockMoveCredentialAfter = vi.fn()

vi.mock('@generated', () => ({
  listUserCredentials: (...args: unknown[]) => mockListUserCredentials(...args),
  updateCredentialLabel: (...args: unknown[]) => mockUpdateCredentialLabel(...args),
  deleteCredential: (...args: unknown[]) => mockDeleteCredential(...args),
  moveCredentialAfter: (...args: unknown[]) => mockMoveCredentialAfter(...args),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useUserCredentials', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('fetches the user credentials', async () => {
    const creds = [{ id: 'cred-1', type: 'password', priority: 1 }]
    mockListUserCredentials.mockResolvedValue({ data: creds, error: undefined })
    const { result } = renderHook(() => useUserCredentials('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(creds)
    expect(mockListUserCredentials).toHaveBeenCalledWith({ path: { realm: 'master', id: 'u1' } })
  })

  it('surfaces API errors', async () => {
    mockListUserCredentials.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'forbidden' },
    })
    const { result } = renderHook(() => useUserCredentials('master', 'u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('forbidden')
  })
})

describe('useUpdateCredentialLabel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('sends the new label in the request body', async () => {
    mockUpdateCredentialLabel.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useUpdateCredentialLabel(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'u1',
      credentialId: 'cred-1',
      label: 'My laptop',
    })
    expect(mockUpdateCredentialLabel).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1', credential_id: 'cred-1' },
      body: { userLabel: 'My laptop' },
    })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Credential label updated',
        type: 'success',
      })
    )
  })

  it('sends null to clear the label', async () => {
    mockUpdateCredentialLabel.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useUpdateCredentialLabel(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'u1',
      credentialId: 'cred-1',
      label: null,
    })
    expect(mockUpdateCredentialLabel).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1', credential_id: 'cred-1' },
      body: { userLabel: null },
    })
  })
})

describe('useDeleteCredential', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('deletes the credential and toasts', async () => {
    mockDeleteCredential.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useDeleteCredential(), { wrapper })
    await result.current.mutateAsync({ realm: 'master', id: 'u1', credentialId: 'cred-1' })
    expect(mockDeleteCredential).toHaveBeenCalledWith({
      path: { realm: 'master', id: 'u1', credential_id: 'cred-1' },
    })
    await waitFor(() =>
      expect(useToastStore.getState().toasts[0]).toMatchObject({
        title: 'Credential deleted',
        type: 'success',
      })
    )
  })

  it('surfaces the last-credential 400 guard as an error toast', async () => {
    mockDeleteCredential.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'cannot delete the last remaining credential' },
    })
    const { result } = renderHook(() => useDeleteCredential(), { wrapper })
    await expect(
      result.current.mutateAsync({ realm: 'master', id: 'u1', credentialId: 'cred-1' })
    ).rejects.toThrow('cannot delete the last remaining credential')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to delete credential',
      message: 'cannot delete the last remaining credential',
      type: 'error',
    })
  })
})

describe('useMoveCredential', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useToastStore.setState({ toasts: [] })
  })

  it('maps to the moveAfter path parameters', async () => {
    mockMoveCredentialAfter.mockResolvedValue({ data: undefined, error: undefined })
    const { result } = renderHook(() => useMoveCredential(), { wrapper })
    await result.current.mutateAsync({
      realm: 'master',
      id: 'u1',
      credentialId: 'cred-2',
      newPreviousCredentialId: 'cred-1',
    })
    expect(mockMoveCredentialAfter).toHaveBeenCalledWith({
      path: {
        realm: 'master',
        id: 'u1',
        credential_id: 'cred-2',
        new_previous_credential_id: 'cred-1',
      },
    })
  })

  it('toasts on error', async () => {
    mockMoveCredentialAfter.mockResolvedValue({
      data: undefined,
      error: { errorMessage: 'credential not found' },
    })
    const { result } = renderHook(() => useMoveCredential(), { wrapper })
    await expect(
      result.current.mutateAsync({
        realm: 'master',
        id: 'u1',
        credentialId: 'cred-2',
        newPreviousCredentialId: 'missing',
      })
    ).rejects.toThrow('credential not found')
    expect(useToastStore.getState().toasts[0]).toMatchObject({
      title: 'Failed to reorder credentials',
      type: 'error',
    })
  })
})
