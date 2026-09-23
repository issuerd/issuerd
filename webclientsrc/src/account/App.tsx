// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useMemo, useRef, useState } from 'react'
import { tokenEndpoint } from '@generated'
import { getAccountRealm } from '../config'
import { useAuthStore } from '../state/authStore'
import AccountLayout from './components/AccountLayout'
import ProfilePage from './pages/ProfilePage'
import SessionsPage from './pages/SessionsPage'
import PasswordPage from './pages/PasswordPage'
import ConsentsPage from './pages/ConsentsPage'
import LinkedAccountsPage from './pages/LinkedAccountsPage'

interface TokenSet {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
}

async function exchangeAuthorizationCode(realm: string, code: string, urlState: string): Promise<TokenSet> {
  const storedRealm = sessionStorage.getItem('issuerd_oidc_realm') || realm
  const storedState = sessionStorage.getItem('issuerd_oidc_state')
  const codeVerifier = sessionStorage.getItem('issuerd_code_verifier')

  if (!codeVerifier) {
    throw new Error('Missing PKCE verifier. Please sign in again.')
  }
  if (urlState !== storedState) {
    throw new Error('State mismatch — possible session tampering.')
  }

  const redirectUri = `${window.location.origin}/realms/${encodeURIComponent(storedRealm)}/account`

  const res = await tokenEndpoint({
    path: { realm: storedRealm },
    body: {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'account-console',
      code_verifier: codeVerifier,
    },
  })

  if (res.error || !res.data) {
    const err = (res.error ?? {}) as { error?: string; error_description?: string }
    throw new Error(
      err.error_description || err.error || `Token exchange failed (${res.response?.status ?? 'unknown'})`
    )
  }

  const data = res.data
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || '',
    idToken: data.id_token || '',
    expiresAt: Date.now() + (data.expires_in || 300) * 1000,
  }
}

function AccountApp() {
  const realm = useMemo(() => getAccountRealm(), [])
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated(realm))
  const setTokenSet = useAuthStore((s) => s.setTokenSet)
  const [isExchanging, setIsExchanging] = useState(false)
  const [exchangeError, setExchangeError] = useState('')
  const exchangeStarted = useRef(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')

    // OAuth2 authorization-code callback from the OIDC endpoint. The account
    // console is its own redirect URI, so it must exchange the code itself
    // instead of relying on the admin SPA's /callback handler.
    if (code && state && !exchangeStarted.current) {
      if (isAuthenticated) {
        window.history.replaceState({}, '', `/realms/${encodeURIComponent(realm)}/account`)
        return
      }

      exchangeStarted.current = true
      setIsExchanging(true)
      exchangeAuthorizationCode(realm, code, state)
        .then((tokenSet) => {
          sessionStorage.removeItem('issuerd_oidc_state')
          sessionStorage.removeItem('issuerd_code_verifier')
          sessionStorage.removeItem('issuerd_oidc_realm')
          localStorage.setItem('issuerd_realm', realm)
          setTokenSet(realm, tokenSet)
          window.history.replaceState({}, '', `/realms/${encodeURIComponent(realm)}/account`)
        })
        .catch((err: Error) => {
          setExchangeError(err.message || 'Authentication failed')
        })
        .finally(() => {
          setIsExchanging(false)
        })
      return
    }

    if (!isAuthenticated) {
      const redirectUri = `${window.location.origin}/realms/${encodeURIComponent(realm)}/account`
      window.location.href = `/login.html?realm=${encodeURIComponent(realm)}&client_id=account-console&redirect_uri=${encodeURIComponent(redirectUri)}`
    }
  }, [isAuthenticated, realm, setTokenSet])

  if (exchangeError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="bg-card border border-destructive/30 rounded-xl p-8 max-w-sm w-full text-center">
          <h2 className="font-display text-lg text-destructive mb-4">Authentication Error</h2>
          <p className="text-sm text-muted-foreground mb-6">{exchangeError}</p>
          <button
            onClick={() => {
              const redirectUri = `${window.location.origin}/realms/${encodeURIComponent(realm)}/account`
              window.location.href = `/login.html?realm=${encodeURIComponent(realm)}&client_id=account-console&redirect_uri=${encodeURIComponent(redirectUri)}`
            }}
            className="px-5 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold uppercase tracking-wider hover:opacity-90 transition-all"
          >
            Back to Sign In
          </button>
        </div>
      </div>
    )
  }

  if (isExchanging || !isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-muted-foreground text-sm">Redirecting to sign in...</div>
      </div>
    )
  }

  return (
    <Routes>
      <Route element={<AccountLayout />}>
        <Route index element={<ProfilePage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="security" element={<PasswordPage />} />
        <Route path="consents" element={<ConsentsPage />} />
        <Route path="linked-accounts" element={<LinkedAccountsPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="*" element={<Navigate to="/profile" replace />} />
      </Route>
    </Routes>
  )
}

export default AccountApp
