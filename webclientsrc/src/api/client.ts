// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { authLogout } from '@generated'
import { client } from '@generated/client.gen'
import { getAccountRealm } from '../config'
import { useAuthStore } from '../state/authStore'
import { initTokenRefresh, refreshNow, stopSessionRefresh } from './tokenRefresh'

// The singleton client's base URL and auth resolver are configured once in
// ../config.ts; this module adds the admin console's session handling: a 401
// triggers one token refresh + request retry, and only when the refresh says
// the session is over (or a retried request still comes back 401) do we log
// out and return to the sign-in page.
let loggingOut = false

function forceLogout() {
  if (loggingOut) return
  loggingOut = true
  stopSessionRefresh()
  void postLogout().finally(() => {
    useAuthStore.getState().logout()
    window.location.href = '/login.html?logged_out=1'
  })
}

initTokenRefresh(forceLogout)

client.interceptors.response.use(async (response, request, options) => {
  if (response.status !== 401) return response
  // A 401 from the auth endpoints themselves is a credential failure, not an
  // expired access token — never refresh-retry those.
  if (new URL(request.url).pathname.startsWith('/api/v1/auth/')) return response

  const outcome = await refreshNow()
  if (outcome !== 'ok') return response // 'expired' already triggered forceLogout

  const tokens = useAuthStore.getState().getTokenSet(getAccountRealm())
  if (!tokens) return response

  const headers = new Headers(request.headers)
  headers.set('Authorization', `Bearer ${tokens.accessToken}`)
  const retryInit: RequestInit = {
    method: request.method,
    headers,
    credentials: request.credentials,
    redirect: request.redirect,
  }
  if (request.method !== 'GET' && request.method !== 'HEAD' && options.serializedBody !== undefined) {
    retryInit.body = options.serializedBody
  }
  const doFetch = options.fetch ?? globalThis.fetch
  const retryResponse = await doFetch(new Request(request.url, retryInit))
  if (retryResponse.status === 401) {
    // A freshly minted token was still rejected — the session is broken.
    forceLogout()
  }
  return retryResponse
})

/**
 * Call the backend logout endpoint.
 * Errors are silently ignored — the local session is cleared regardless.
 */
export async function postLogout(): Promise<void> {
  try {
    await authLogout({ credentials: 'same-origin' })
  } catch {
    // ignore
  }
}

export { client }
