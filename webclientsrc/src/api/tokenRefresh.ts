// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { tokenEndpoint } from '@generated'
import { CONFIG, getAccountRealm } from '../config'
import { useAuthStore } from '../state/authStore'

/**
 * Proactive access-token refresh for the admin console session.
 *
 * Semantics: while the user is interacting with the console, the access token
 * is refreshed shortly before it expires (each successful refresh also slides
 * the server-side SSO session idle window). When the user goes inactive, the
 * refresh stops: the access token lapses, and once the realm's SSO idle
 * timeout passes the server answers the next refresh attempt with
 * `invalid_grant`, ending the session via the registered expiry handler.
 */

export type RefreshOutcome =
  /** New tokens stored; callers may retry the failed request. */
  | 'ok'
  /** The session is gone server-side (or no refresh token exists). */
  | 'expired'
  /** Transient failure (network, 5xx) — the session may still be valid. */
  | 'error'

const REFRESH_SKEW_MS = 30_000
const MIN_DELAY_MS = 5_000
const ERROR_RETRY_MS = 15_000

let timer: ReturnType<typeof setTimeout> | null = null
let inflight: Promise<RefreshOutcome> | null = null
let lastActivityAt = Date.now()
let scheduledAt = 0
let sessionExpiredHandler: (() => void) | null = null
let listenersAttached = false

function currentTokens() {
  const realm = getAccountRealm()
  return { realm, tokenSet: useAuthStore.getState().getTokenSet(realm) }
}

function clearTimer() {
  if (timer !== null) {
    clearTimeout(timer)
    timer = null
  }
}

function schedule() {
  clearTimer()
  const { tokenSet } = currentTokens()
  if (!tokenSet?.refreshToken) return
  scheduledAt = Date.now()
  const delay = Math.max(tokenSet.expiresAt - Date.now() - REFRESH_SKEW_MS, MIN_DELAY_MS)
  timer = setTimeout(() => void onTimer(), delay)
}

async function onTimer() {
  timer = null
  const { tokenSet } = currentTokens()
  if (!tokenSet?.refreshToken) return
  if (lastActivityAt < scheduledAt) {
    // No interaction during this token's lifetime: let the access token expire
    // rather than sliding the SSO session while nobody is at the keyboard.
    return
  }
  const outcome = await refreshNow()
  if (outcome === 'error') {
    timer = setTimeout(() => void onTimer(), ERROR_RETRY_MS)
  }
  // 'ok' reschedules inside doRefresh; 'expired' fires the expiry handler there.
}

function onTabVisible() {
  if (document.visibilityState !== 'visible') return
  lastActivityAt = Date.now()
  const { tokenSet } = currentTokens()
  // Waking to a stale token: refresh immediately instead of waiting for the
  // first 401.
  if (tokenSet?.refreshToken && tokenSet.expiresAt - REFRESH_SKEW_MS <= Date.now()) {
    void onTimer()
  }
}

function attachActivityListeners() {
  if (listenersAttached || typeof window === 'undefined') return
  listenersAttached = true
  const mark = () => {
    lastActivityAt = Date.now()
  }
  window.addEventListener('pointerdown', mark, { passive: true })
  window.addEventListener('pointermove', mark, { passive: true })
  window.addEventListener('keydown', mark, { passive: true })
  document.addEventListener('visibilitychange', onTabVisible)
}

async function doRefresh(): Promise<RefreshOutcome> {
  const { realm, tokenSet } = currentTokens()
  if (!tokenSet?.refreshToken) return 'expired'

  let res
  try {
    res = await tokenEndpoint({
      path: { realm },
      body: {
        grant_type: 'refresh_token',
        refresh_token: tokenSet.refreshToken,
        client_id: CONFIG.CLIENT_ID,
        scope: 'openid profile',
      },
    })
  } catch {
    return 'error'
  }

  if (res.error || !res.data) {
    const code = (res.error as { error?: string } | undefined)?.error
    if (code === 'invalid_grant' || code === 'invalid_client') {
      sessionExpiredHandler?.()
      return 'expired'
    }
    return 'error'
  }

  const data = res.data
  useAuthStore.getState().setTokenSet(realm, {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || tokenSet.refreshToken,
    idToken: data.id_token || tokenSet.idToken,
    expiresAt: Date.now() + (data.expires_in || 300) * 1000,
  })
  schedule()
  return 'ok'
}

/**
 * Refresh the access token now, deduplicating concurrent calls. Safe to call
 * from the 401 interceptor and the scheduler alike.
 */
export function refreshNow(): Promise<RefreshOutcome> {
  if (!inflight) {
    inflight = doRefresh().finally(() => {
      inflight = null
    })
  }
  return inflight
}

/** Register the handler fired when the server declares the session over. */
export function initTokenRefresh(onSessionExpired: () => void) {
  sessionExpiredHandler = onSessionExpired
  attachActivityListeners()
}

/** (Re)start the refresh schedule, e.g. after login or page load. No-op without tokens. */
export function startSessionRefresh() {
  schedule()
}

/** Stop scheduled refreshes (logout). */
export function stopSessionRefresh() {
  clearTimer()
}
