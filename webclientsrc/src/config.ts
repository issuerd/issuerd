// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { client } from '@generated/client.gen'
import { useAuthStore } from './state/authStore'

// The SPA is served same-origin by the Issuerd daemon (embedded dist/), so
// there is no runtime config shuttle: the API base URL is always the origin
// the page was loaded from.
export const CONFIG = {
  API_BASE: window.location.origin,
  REALM: 'master',
  CLIENT_ID: 'admin-cli',
}

/**
 * URL prefix the admin console SPA is mounted under. The server serves the SPA
 * shell only below this path (the REST admin API owns `/admin` itself), and the
 * React Router basename is set to it — every `navigate()`/`Link` target inside
 * the console is relative to this prefix.
 */
export const CONSOLE_BASENAME = '/admin/console'

/** Absolute URL path for a console route, for raw anchors / window.location. */
export function consoleHref(path: string): string {
  return `${CONSOLE_BASENAME}${path}`
}

/** Realm of the account-console bundle, parsed from the URL path (`/realms/{realm}/account/...`). */
export function getAccountRealm(): string {
  if (typeof window === 'undefined') return CONFIG.REALM
  const match = window.location.pathname.match(/^\/realms\/([^/]+)\/account/)
  return match?.[1] || CONFIG.REALM
}

// Configure the generated API client exactly once. The auth resolver covers
// both bundles: account-console tokens are stored per-realm in sessionStorage,
// admin-console tokens in the in-memory tokenSet.
client.setConfig({
  baseUrl: CONFIG.API_BASE,
  auth: () => {
    const realm = getAccountRealm()
    const fromStorage = useAuthStore.getState().getTokenSet(realm)
    const fromState = useAuthStore.getState().tokenSet
    return fromStorage?.accessToken ?? fromState?.accessToken ?? undefined
  },
})
