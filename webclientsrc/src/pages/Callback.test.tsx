// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Callback from './Callback'
import { useAuthStore } from '../state/authStore'

const tokenEndpointMock = vi.fn()

vi.mock('@generated', () => ({
  tokenEndpoint: (...args: unknown[]) => tokenEndpointMock(...args),
}))

vi.mock('../api/tokenRefresh', () => ({
  startSessionRefresh: vi.fn(),
}))

interface LocationStub {
  search: string
  origin: string
  pathname: string
  href: string
}

function stubLocation(search: string): LocationStub {
  const loc: LocationStub = {
    search,
    origin: 'http://localhost',
    pathname: '/admin/console/callback',
    href: '',
  }
  Object.defineProperty(window, 'location', { value: loc, writable: true, configurable: true })
  return loc
}

describe('Callback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    localStorage.clear()
    document.cookie = 'issuerd_code_verifier=; Max-Age=0; Path=/'
    useAuthStore.setState({ tokenSet: null, currentRealm: null })
  })

  it('restarts sign-in when the URL state does not match the stored attempt', () => {
    const loc = stubLocation('?code=abc&state=url-state')
    sessionStorage.setItem('issuerd_oidc_state', 'different-state')
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    expect(loc.href).toBe('/login.html')
    expect(sessionStorage.getItem('issuerd_callback_restart')).toBe('1')
    expect(tokenEndpointMock).not.toHaveBeenCalled()
  })

  it('restarts sign-in when no login attempt is stored at all', () => {
    const loc = stubLocation('?code=abc&state=url-state')

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    expect(loc.href).toBe('/login.html')
    expect(sessionStorage.getItem('issuerd_callback_restart')).toBe('1')
    expect(tokenEndpointMock).not.toHaveBeenCalled()
  })

  it('shows the error when a restart was already attempted', () => {
    const loc = stubLocation('?code=abc&state=url-state')
    sessionStorage.setItem('issuerd_oidc_state', 'different-state')
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    sessionStorage.setItem('issuerd_callback_restart', '1')

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    expect(screen.getByText(/State mismatch/)).toBeInTheDocument()
    // The one-shot flag is consumed so a later fresh attempt can restart again.
    expect(sessionStorage.getItem('issuerd_callback_restart')).toBeNull()
    expect(loc.href).toBe('')
    expect(tokenEndpointMock).not.toHaveBeenCalled()
  })

  it('exchanges the code when the state matches the stored attempt', async () => {
    stubLocation('?code=abc&state=matching-state')
    sessionStorage.setItem('issuerd_oidc_state', 'matching-state')
    sessionStorage.setItem('issuerd_code_verifier', 'verifier123')
    sessionStorage.setItem('issuerd_oidc_realm', 'master')
    tokenEndpointMock.mockResolvedValue({
      data: { access_token: 'tok', refresh_token: 'rt', id_token: '', expires_in: 300 },
    })

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    await waitFor(() => expect(tokenEndpointMock).toHaveBeenCalledTimes(1))
    const call = tokenEndpointMock.mock.calls[0][0] as {
      path: { realm: string }
      body: Record<string, string>
    }
    expect(call.path).toEqual({ realm: 'master' })
    expect(call.body).toMatchObject({
      grant_type: 'authorization_code',
      code: 'abc',
      client_id: 'admin-cli',
      code_verifier: 'verifier123',
    })
    await waitFor(() =>
      expect(useAuthStore.getState().getTokenSet('master')?.accessToken).toBe('tok')
    )
    // Attempt markers are cleaned up after a successful exchange.
    expect(sessionStorage.getItem('issuerd_oidc_state')).toBeNull()
    expect(sessionStorage.getItem('issuerd_code_verifier')).toBeNull()
  })

  function fakeJwt(roles: string[]): string {
    const payload = btoa(JSON.stringify({ realm_access: { roles } }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    return `h.${payload}.s`
  }

  it('restores an existing admin session into the store and skips the exchange', async () => {
    stubLocation('?code=abc&state=url-state')
    const ts = {
      accessToken: fakeJwt(['manage-realm']),
      refreshToken: 'rt',
      idToken: '',
      expiresAt: Date.now() + 300_000,
    }
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ master: ts }))
    sessionStorage.setItem('issuerd_oidc_realm', 'master')

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    // The restored session is synced into the in-memory store so guarded
    // pages do not bounce back to the login page.
    await waitFor(() => expect(useAuthStore.getState().tokenSet?.accessToken).toBe(ts.accessToken))
    expect(useAuthStore.getState().currentRealm).toBe('master')
    expect(tokenEndpointMock).not.toHaveBeenCalled()
  })

  it('restores a non-admin session into the store and routes to the account console', async () => {
    const loc = stubLocation('?code=abc&state=url-state')
    const ts = {
      accessToken: fakeJwt(['user']),
      refreshToken: 'rt',
      idToken: '',
      expiresAt: Date.now() + 300_000,
    }
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ master: ts }))

    render(
      <MemoryRouter>
        <Callback />
      </MemoryRouter>
    )

    await waitFor(() => expect(loc.href).toBe('/realms/master/account'))
    expect(useAuthStore.getState().tokenSet?.accessToken).toBe(ts.accessToken)
    expect(tokenEndpointMock).not.toHaveBeenCalled()
  })
})
