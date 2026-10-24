// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { create } from 'zustand'

interface TokenSet {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
  clientId?: string
}

interface AuthState {
  tokenSet: TokenSet | null
  currentRealm: string | null
  setTokenSet: (realm: string, tokenSet: TokenSet | null) => void
  setRealm: (realm: string | null) => void
  logout: () => void
  hydrate: (clientId?: string) => void
  isAuthenticated: (realm: string, clientId?: string) => boolean
  getTokenSet: (realm: string, clientId?: string) => TokenSet | null
}

const STORAGE_KEY_TOKENS = 'issuerd_tokens'
const STORAGE_KEY_REALM = 'issuerd_realm'
const DEFAULT_CLIENT_ID = 'admin-cli'

type TokensByClient = Record<string, TokenSet>
type TokensByRealm = Record<string, TokensByClient>

function isTokenSet(parsed: unknown): parsed is TokenSet {
  return (
    typeof parsed === 'object' &&
    parsed !== null &&
    'accessToken' in parsed &&
    typeof (parsed as TokenSet).accessToken === 'string'
  )
}

function withClientId(tokenSet: TokenSet, fallbackClientId = DEFAULT_CLIENT_ID) {
  return { ...tokenSet, clientId: tokenSet.clientId || fallbackClientId }
}

function getStoredTokens(): TokensByRealm {
  const raw = sessionStorage.getItem(STORAGE_KEY_TOKENS)
  if (!raw) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    if (isTokenSet(parsed)) {
      const realm = localStorage.getItem(STORAGE_KEY_REALM) || 'master'
      const tokenSet = withClientId(parsed)
      const migrated: TokensByRealm = { [realm]: { [tokenSet.clientId]: tokenSet } }
      sessionStorage.setItem(STORAGE_KEY_TOKENS, JSON.stringify(migrated))
      return migrated
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const tokens: TokensByRealm = {}
      let migrated = false
      for (const [realm, value] of Object.entries(parsed)) {
        if (isTokenSet(value)) {
          const tokenSet = withClientId(value)
          tokens[realm] = { [tokenSet.clientId]: tokenSet }
          migrated = true
          continue
        }
        if (!value || typeof value !== 'object' || Array.isArray(value)) continue
        const byClient: TokensByClient = {}
        for (const [clientId, candidate] of Object.entries(value)) {
          if (!isTokenSet(candidate)) continue
          byClient[clientId] = withClientId(candidate, clientId)
          if (candidate.clientId !== clientId) migrated = true
        }
        if (Object.keys(byClient).length > 0) tokens[realm] = byClient
      }
      if (migrated) sessionStorage.setItem(STORAGE_KEY_TOKENS, JSON.stringify(tokens))
      return tokens
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
    const nextTokenSet = tokenSet ? withClientId(tokenSet) : null
    if (nextTokenSet) {
      existing[realm] = { ...existing[realm], [nextTokenSet.clientId]: nextTokenSet }
    } else {
      delete existing[realm]
    }
    sessionStorage.setItem(STORAGE_KEY_TOKENS, JSON.stringify(existing))
    set({ tokenSet: nextTokenSet, currentRealm: realm })
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

  hydrate: (clientId = DEFAULT_CLIENT_ID) => {
    const tokens = getStoredTokens()
    const realm = localStorage.getItem(STORAGE_KEY_REALM)
    // The realm context is shared across tabs (localStorage) while tokens are
    // per-tab (sessionStorage): after a realm switch in another tab, this tab
    // may have no token for the pinned realm. Fall back to any stored token for
    // this client — the console's primary realm first — so the console does not
    // bounce to the login page despite holding a valid session.
    const tokenSet =
      (realm ? tokens[realm]?.[clientId] : undefined) ??
      tokens['master']?.[clientId] ?? // mirrors CONFIG.REALM (importing it would cycle)
      Object.values(tokens)
        .map((byClient) => byClient[clientId])
        .find((candidate) => candidate !== undefined) ??
      null
    set({ tokenSet, currentRealm: realm })
  },

  isAuthenticated: (realm, clientId = DEFAULT_CLIENT_ID) => {
    const ts = get().getTokenSet(realm, clientId)
    if (!ts) return false
    return ts.expiresAt > Date.now()
  },

  getTokenSet: (realm, clientId = DEFAULT_CLIENT_ID) => {
    const tokens = getStoredTokens()
    return tokens[realm]?.[clientId] ?? null
  },
}))
