// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore } from '../state/authStore'
import { client } from './client'

// Same module-graph caveat as tokenRefresh.test.ts: setup.ts imports ./client
// before test-file mocks register, so we stub fetch instead of mocking
// '@generated'.

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function seedTokens() {
  useAuthStore.getState().setTokenSet('master', {
    accessToken: 'old-access',
    refreshToken: 'old-refresh',
    idToken: 'old-id',
    expiresAt: Date.now() + 300_000,
  })
}

function urlOf(call: unknown[]): string {
  return (call[0] as Request).url
}

describe('api client 401 handling', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    localStorage.clear()
    useAuthStore.getState().logout()
  })

  it('refreshes once and retries the request with the new token', async () => {
    seedTokens()
    fetchMock.mockImplementation((req: Request) => {
      const url = req.url
      if (url.includes('/protocol/openid-connect/token')) {
        return Promise.resolve(
          jsonResponse(200, {
            access_token: 'new-access',
            refresh_token: 'new-refresh',
            expires_in: 300,
          }),
        )
      }
      if (url.endsWith('/admin/realms') && req.headers.get('Authorization') !== 'Bearer new-access') {
        return Promise.resolve(jsonResponse(401, { errorMessage: 'unauthorized' }))
      }
      return Promise.resolve(jsonResponse(200, [{ realm: 'master' }]))
    })

    const res = await client.get({ url: '/admin/realms' })

    expect(res.response?.status).toBe(200)
    expect(res.data).toEqual([{ realm: 'master' }])
    const urls = fetchMock.mock.calls.map(urlOf)
    expect(urls.filter((u) => u.includes('/protocol/openid-connect/token'))).toHaveLength(1)
    expect(urls.filter((u) => u.endsWith('/admin/realms'))).toHaveLength(2)
  })

  it('never refresh-retries the auth endpoints themselves', async () => {
    seedTokens()
    fetchMock.mockResolvedValue(jsonResponse(401, { error: 'invalid_grant' }))

    const res = await client.post({ url: '/api/v1/auth/login', body: 'x' })

    expect(res.response?.status).toBe(401)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  // Terminal: forceLogout latches module state (page navigates away in a real
  // browser), so the session-expiry case must run last in this file.
  it('clears the session when the refresh token is dead', async () => {
    seedTokens()
    fetchMock.mockImplementation((req: Request) => {
      if (req.url.includes('/protocol/openid-connect/token')) {
        return Promise.resolve(jsonResponse(400, { error: 'invalid_grant' }))
      }
      if (req.url.endsWith('/api/v1/auth/logout')) {
        return Promise.resolve(jsonResponse(200, {}))
      }
      return Promise.resolve(jsonResponse(401, { errorMessage: 'unauthorized' }))
    })

    const res = await client.get({ url: '/admin/realms' })

    expect(res.response?.status).toBe(401)
    await vi.waitFor(() => {
      expect(useAuthStore.getState().getTokenSet('master')).toBeNull()
    })
  })
})
