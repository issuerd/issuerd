// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { create } from 'zustand'

interface TokenSet {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
}

interface AuthState {
  tokenSet: TokenSet | null
  currentRealm: string | null
  setTokenSet: (realm: string, tokenSet: TokenSet | null) => void
  setRealm: (realm: string | null) => void
  logout: () => void
  hydrate: () => void
  isAuthenticated: (realm: string) => boolean
  getTokenSet: (realm: string) => TokenSet | null
}

const STORAGE_KEY_TOKENS = 'issuerd_tokens'
const STORAGE_KEY_REALM = 'issuerd_realm'

type TokensByRealm = Record<string, TokenSet>

function isLegacyToken(parsed: unknown): parsed is TokenSet {
  return (
    typeof parsed === 'object' &&
    parsed !== null &&
    'accessToken' in parsed &&
    typeof (parsed as TokenSet).accessToken === 'string'
  )
}

function getStoredTokens(): TokensByRealm {
  const raw = sessionStorage.getItem(STORAGE_KEY_TOKENS)
  if (!raw) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    if (isLegacyToken(parsed)) {
      const realm = localStorage.getItem(STORAGE_KEY_REALM) || 'master'
      const migrated: TokensByRealm = { [realm]: parsed }
      sessionStorage.setItem(STORAGE_KEY_TOKENS, JSON.stringify(migrated))
      return migrated
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as TokensByRealm
    }
  } catch {
    sessionStorage.removeItem(STORAGE_KEY_TOKENS)
  }
  return {}
}

export const useAuthStore = create<AuthState>((set, get) => ({
  tokenSet: null,
  currentRealm: null,

  setTokenSet: (realm, tokenSet) => {
    const existing = getStoredTokens()
    if (tokenSet) {
      existing[realm] = tokenSet
    } else {
      delete existing[realm]
    }
    sessionStorage.setItem(STORAGE_KEY_TOKENS, JSON.stringify(existing))
    set({ tokenSet, currentRealm: realm })
  },

  setRealm: (realm) => {
    if (realm) {
      localStorage.setItem(STORAGE_KEY_REALM, realm)
    } else {
      localStorage.removeItem(STORAGE_KEY_REALM)
    }
    set({ currentRealm: realm })
  },

  logout: () => {
    sessionStorage.removeItem(STORAGE_KEY_TOKENS)
    localStorage.removeItem(STORAGE_KEY_REALM)
    set({ tokenSet: null, currentRealm: null })
  },

  hydrate: () => {
    const tokens = getStoredTokens()
    const realm = localStorage.getItem(STORAGE_KEY_REALM)
    // The realm context is shared across tabs (localStorage) while tokens are
    // per-tab (sessionStorage): after a realm switch in another tab, this tab
    // may have no token for the pinned realm. Fall back to any stored token —
    // the console's primary realm first — so the console does not bounce to
    // the login page despite holding a valid session.
    const tokenSet =
      (realm ? tokens[realm] : undefined) ??
      tokens['master'] ?? // mirrors CONFIG.REALM (importing it would cycle)
      Object.values(tokens)[0] ??
      null
    set({ tokenSet, currentRealm: realm })
  },

  isAuthenticated: (realm) => {
    const ts = get().getTokenSet(realm)
    if (!ts) return false
    return ts.expiresAt > Date.now()
  },

  getTokenSet: (realm) => {
    const tokens = getStoredTokens()
    return tokens[realm] ?? null
  },
}))
