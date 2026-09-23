// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore } from '../state/authStore'

// NOTE: src/test/setup.ts pulls in ./client (and therefore ./tokenRefresh)
// before any test file's vi.mock registration runs, so vi.mock('@generated')
// cannot reach tokenRefresh's imports. Stub the fetch layer instead — this
// also exercises the real generated client's request/response handling.
import {
  initTokenRefresh,
  refreshNow,
  startSessionRefresh,
  stopSessionRefresh,
} from './tokenRefresh'

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function seedTokens(expiresInMs = 300_000) {
  useAuthStore.getState().setTokenSet('master', {
    accessToken: 'old-access',
    refreshToken: 'old-refresh',
    idToken: 'old-id',
    expiresAt: Date.now() + expiresInMs,
  })
}

const rotatedTokens = {
  access_token: 'new-access',
  refresh_token: 'new-refresh',
  id_token: 'new-id',
  expires_in: 300,
  token_type: 'Bearer',
}

describe('tokenRefresh', () => {
  beforeEach(() => {
    stopSessionRefresh()
    vi.clearAllMocks()
    sessionStorage.clear()
    localStorage.clear()
    useAuthStore.getState().logout()
    initTokenRefresh(vi.fn()) // attaches the activity listeners idempotently
  })

  it('stores rotated tokens on success', async () => {
    seedTokens()
    fetchMock.mockResolvedValue(jsonResponse(200, rotatedTokens))

    const outcome = await refreshNow()

    expect(outcome).toBe('ok')
    const stored = useAuthStore.getState().getTokenSet('master')!
    expect(stored.accessToken).toBe('new-access')
    expect(stored.refreshToken).toBe('new-refresh')

    const request: Request = fetchMock.mock.calls[0][0]
    expect(request.url).toBe(
      `${window.location.origin}/realms/master/protocol/openid-connect/token`,
    )
    const body = await request.text()
    expect(body).toContain('grant_type=refresh_token')
    expect(body).toContain('refresh_token=old-refresh')
    expect(body).toContain('client_id=admin-cli')
  })

  it('deduplicates concurrent refreshes', async () => {
    seedTokens()
    fetchMock.mockResolvedValue(jsonResponse(200, rotatedTokens))

    const [a, b] = await Promise.all([refreshNow(), refreshNow()])

    expect(a).toBe('ok')
    expect(b).toBe('ok')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('fires the expiry handler on invalid_grant', async () => {
    seedTokens()
    const onExpired = vi.fn()
    initTokenRefresh(onExpired)
    fetchMock.mockResolvedValue(
      jsonResponse(400, { error: 'invalid_grant', error_description: 'Session not active' }),
    )

    const outcome = await refreshNow()

    expect(outcome).toBe('expired')
    expect(onExpired).toHaveBeenCalledTimes(1)
  })

  it('returns error without expiring on transient failures', async () => {
    seedTokens()
    const onExpired = vi.fn()
    initTokenRefresh(onExpired)
    fetchMock.mockRejectedValue(new Error('network down'))

    const outcome = await refreshNow()

    expect(outcome).toBe('error')
    expect(onExpired).not.toHaveBeenCalled()
  })

  it('is expired when there is no refresh token', async () => {
    const outcome = await refreshNow()
    expect(outcome).toBe('expired')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refreshes on schedule while the user is active', async () => {
    vi.useFakeTimers()
    try {
      seedTokens(60_000) // expires in 60s -> refresh due after 30s (skew)
      fetchMock.mockResolvedValue(jsonResponse(200, rotatedTokens))
      startSessionRefresh()
      window.dispatchEvent(new Event('pointerdown')) // user is around

      await vi.advanceTimersByTimeAsync(31_000)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      stopSessionRefresh()
      vi.useRealTimers()
    }
  })

  it('skips the scheduled refresh when the user went inactive', async () => {
    vi.useFakeTimers()
    try {
      seedTokens(60_000)
      fetchMock.mockResolvedValue(jsonResponse(200, rotatedTokens))
      // First cycle: activity happens, refresh fires and re-arms the timer.
      startSessionRefresh()
      window.dispatchEvent(new Event('pointerdown'))
      await vi.advanceTimersByTimeAsync(31_000)
      expect(fetchMock).toHaveBeenCalledTimes(1)

      // Second cycle: no interaction since the timer was re-armed -> skip.
      await vi.advanceTimersByTimeAsync(300_000)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      stopSessionRefresh()
      vi.useRealTimers()
    }
  })
})
