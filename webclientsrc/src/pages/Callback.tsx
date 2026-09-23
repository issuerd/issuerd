// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { tokenEndpoint } from '@generated'
import { CONFIG, CONSOLE_BASENAME } from '../config'
import { useAuthStore } from '../state/authStore'
import { startSessionRefresh } from '../api/tokenRefresh'
import Spinner from '../components/ui/Spinner'

function parseJwtPayload(token: string): Record<string, any> {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return {}
  }
}

function hasAdminRoles(token: string): boolean {
  const payload = parseJwtPayload(token)
  const roles: string[] = payload.realm_access?.roles || []
  const adminRoles = ['manage-realm', 'view-realm', 'manage-users', 'view-users', 'manage-clients', 'view-clients', 'admin']
  return roles.some((r) => adminRoles.includes(r))
}

// One-shot flag marking that a stale callback already restarted sign-in once.
const RESTART_FLAG = 'issuerd_callback_restart'

export default function Callback() {
  const navigate = useNavigate()
  const setTokenSet = useAuthStore((s) => s.setTokenSet)
  const [error, setError] = useState('')
  const exchangeStarted = useRef(false)
  const realm = sessionStorage.getItem('issuerd_oidc_realm') || CONFIG.REALM

  useEffect(() => {
    // A stale login attempt (restored tab, a parallel sign-in in another tab,
    // a browser restart mid-flow) lands here with a state/code that no longer
    // matches the stored attempt. Restarting sign-in recovers transparently —
    // with an active SSO session the round-trip is invisible — so do that
    // instead of stranding the user on an error page. The one-shot flag breaks
    // the loop if the fresh attempt keeps failing.
    const restartAttempted = sessionStorage.getItem(RESTART_FLAG) === '1'
    sessionStorage.removeItem(RESTART_FLAG)
    const restartSignIn = () => {
      sessionStorage.setItem(RESTART_FLAG, '1')
      window.location.href = '/login.html'
    }

    // If already authenticated (e.g. from a concurrent exchange or prior session),
    // just redirect to the app instead of showing an error.
    const existingTokens = sessionStorage.getItem('issuerd_tokens')
    if (existingTokens) {
      try {
        const parsed = JSON.parse(existingTokens)
        const tokenSet = parsed?.[realm]
        if (tokenSet && tokenSet.expiresAt && tokenSet.expiresAt > Date.now()) {
          // Sync the in-memory store with the restored session: hydration may
          // have pinned a different realm's token (or none) on this page load,
          // which would bounce guarded pages straight back to the login page.
          setTokenSet(realm, tokenSet)
          if (hasAdminRoles(tokenSet.accessToken)) {
            navigate('/realm-picker')
          } else {
            window.location.href = `/realms/${realm}/account`
          }
          return
        }
      } catch {
        // ignore malformed token storage
      }
    }

    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    const errorParam = params.get('error')

    if (errorParam) {
      setError(params.get('error_description') || errorParam)
      return
    }

    if (!code) {
      setError('Missing authorization code in callback URL.')
      return
    }
    if (!state) {
      if (!restartAttempted) {
        restartSignIn()
        return
      }
      setError('Missing state parameter in callback URL.')
      return
    }

    function getCookie(name: string): string | null {
      const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'))
      return match ? decodeURIComponent(match[2]) : null
    }

    const storedState = sessionStorage.getItem('issuerd_oidc_state')
    let codeVerifier = sessionStorage.getItem('issuerd_code_verifier') || getCookie('issuerd_code_verifier')

    if (!codeVerifier) {
      if (!restartAttempted) {
        restartSignIn()
        return
      }
      setError('Missing PKCE verifier. Please start sign-in from the login page.')
      return
    }
    if (state !== storedState) {
      if (!restartAttempted) {
        restartSignIn()
        return
      }
      setError('State mismatch — possible session tampering or expired login attempt. Please try signing in again.')
      return
    }

    if (exchangeStarted.current) {
      return
    }
    exchangeStarted.current = true

    const exchange = async () => {
      try {
        const res = await tokenEndpoint({
          path: { realm },
          credentials: 'include',
          body: {
            grant_type: 'authorization_code',
            code,
            redirect_uri: `${window.location.origin}${CONSOLE_BASENAME}/callback`,
            client_id: CONFIG.CLIENT_ID,
            code_verifier: codeVerifier,
          },
        })

        if (res.error || !res.data) {
          const err = (res.error ?? {}) as { error?: string; error_description?: string }
          throw new Error(err.error_description || 'Token exchange failed')
        }

        const data = res.data
        const accessToken = data.access_token
        const refreshToken = data.refresh_token || ''
        const idToken = data.id_token || ''
        const expiresIn = data.expires_in || 300

        sessionStorage.removeItem('issuerd_oidc_state')
        sessionStorage.removeItem('issuerd_code_verifier')
        sessionStorage.removeItem('issuerd_oidc_realm')
        document.cookie = 'issuerd_code_verifier=; Path=/; Max-Age=0; SameSite=Lax; Secure'
        setTokenSet(realm, {
          accessToken,
          refreshToken,
          idToken,
          expiresAt: Date.now() + expiresIn * 1000,
        })
        startSessionRefresh()

        if (hasAdminRoles(accessToken)) {
          navigate('/realm-picker')
        } else {
          window.location.href = `/realms/${realm}/account`
        }
      } catch (err: any) {
        setError(err.message || 'Authentication failed')
      }
    }

    exchange()
  }, [navigate, setTokenSet, realm])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-obsidian p-4">
        <div className="bg-surface-dark border border-alert-red/30 rounded-xl p-8 max-w-sm w-full text-center">
          <h2 className="font-display text-lg text-alert-red mb-4">Authentication Error</h2>
          <p className="text-sm text-gray-400 mb-6">{error}</p>
          <button
            onClick={() => { window.location.href = '/login.html' }}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all"
          >
            Back to Sign In
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-obsidian p-4">
      <div className="flex flex-col items-center gap-4">
        <Spinner size={32} />
        <span className="text-sm text-gray-400">Completing sign in...</span>
      </div>
    </div>
  )
}
