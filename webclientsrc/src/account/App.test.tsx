// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AccountApp from './App'
import { useAuthStore } from '../state/authStore'

const tokenEndpointMock = vi.fn()

vi.mock('@generated', () => ({
  tokenEndpoint: (...args: unknown[]) => tokenEndpointMock(...args),
}))

vi.mock('./components/AccountLayout', () => ({ default: () => null }))
vi.mock('./pages/ProfilePage', () => ({ default: () => null }))
vi.mock('./pages/SessionsPage', () => ({ default: () => null }))
vi.mock('./pages/PasswordPage', () => ({ default: () => null }))
vi.mock('./pages/ConsentsPage', () => ({ default: () => null }))
vi.mock('./pages/LinkedAccountsPage', () => ({ default: () => null }))

describe('AccountApp authentication', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    localStorage.clear()
    useAuthStore.getState().logout()
    window.history.pushState({}, '', '/realms/master/account?code=abc&state=matching-state')
    sessionStorage.setItem('issuerd_oidc_state', 'matching-state')
    sessionStorage.setItem('issuerd_code_verifier', 'verifier123')
    sessionStorage.setItem('issuerd_oidc_realm', 'master')
  })

  it('persists account authorization-code tokens as account-console', async () => {
    tokenEndpointMock.mockResolvedValue({
      data: { access_token: 'account-token', refresh_token: 'account-refresh', id_token: '', expires_in: 300 },
    })

    render(
      <MemoryRouter>
        <AccountApp />
      </MemoryRouter>,
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
      client_id: 'account-console',
      code_verifier: 'verifier123',
    })

    await waitFor(() =>
      expect(useAuthStore.getState().getTokenSet('master', 'account-console')?.accessToken).toBe(
        'account-token',
      ),
    )
    expect(useAuthStore.getState().getTokenSet('master', 'account-console')?.clientId).toBe(
      'account-console',
    )
    expect(useAuthStore.getState().getTokenSet('master')).toBeNull()
    expect(sessionStorage.getItem('issuerd_oidc_state')).toBeNull()
    expect(sessionStorage.getItem('issuerd_code_verifier')).toBeNull()
  })
})
