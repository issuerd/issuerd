// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore } from './authStore'

describe('authStore', () => {
  beforeEach(() => {
    sessionStorage.clear()
    localStorage.clear()
    useAuthStore.setState({ tokenSet: null, currentRealm: null })
  })

  it('sets token set for a realm and persists to sessionStorage', () => {
    const ts = {
      accessToken: 'at123',
      refreshToken: 'rt456',
      idToken: 'id789',
      expiresAt: Date.now() + 300_000,
    }
    useAuthStore.getState().setTokenSet('master', ts)
    expect(useAuthStore.getState().tokenSet).toEqual(ts)
    expect(useAuthStore.getState().currentRealm).toBe('master')
    const stored = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(stored['master']).toEqual(ts)
  })

  it('clears token set for a single realm without affecting others', () => {
    const masterTs = {
      accessToken: 'a',
      refreshToken: 'r',
      idToken: 'i',
      expiresAt: Date.now() + 300_000,
    }
    const demoTs = {
      accessToken: 'a2',
      refreshToken: 'r2',
      idToken: 'i2',
      expiresAt: Date.now() + 300_000,
    }
    useAuthStore.getState().setTokenSet('master', masterTs)
    useAuthStore.getState().setTokenSet('demo', demoTs)
    useAuthStore.getState().setTokenSet('master', null)
    const stored = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(stored['master']).toBeUndefined()
    expect(stored['demo']).toEqual(demoTs)
  })

  it('sets realm and persists to localStorage', () => {
    useAuthStore.getState().setRealm('master')
    expect(useAuthStore.getState().currentRealm).toBe('master')
    expect(localStorage.getItem('issuerd_realm')).toBe('master')
  })

  it('clears realm', () => {
    useAuthStore.getState().setRealm('master')
    useAuthStore.getState().setRealm(null)
    expect(useAuthStore.getState().currentRealm).toBeNull()
    expect(localStorage.getItem('issuerd_realm')).toBeNull()
  })

  it('clears everything on logout', () => {
    useAuthStore.getState().setTokenSet('master', {
      accessToken: 'at',
      refreshToken: 'rt',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
    })
    useAuthStore.getState().setRealm('master')
    useAuthStore.getState().logout()
    expect(useAuthStore.getState().tokenSet).toBeNull()
    expect(useAuthStore.getState().currentRealm).toBeNull()
    expect(sessionStorage.getItem('issuerd_tokens')).toBeNull()
    expect(localStorage.getItem('issuerd_realm')).toBeNull()
  })

  it('hydrates per-realm tokens from storage', () => {
    const ts = {
      accessToken: 'token-x',
      refreshToken: 'rt',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
    }
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ demo: ts }))
    localStorage.setItem('issuerd_realm', 'demo')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().tokenSet).toEqual(ts)
    expect(useAuthStore.getState().currentRealm).toBe('demo')
  })

  it('hydrate falls back to the master token when the pinned realm has none in this tab', () => {
    const ts = {
      accessToken: 'admin-token',
      refreshToken: 'rt',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
    }
    // Realm context switched in another tab; this tab only holds master.
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ master: ts }))
    localStorage.setItem('issuerd_realm', 'demo')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().tokenSet).toEqual(ts)
    // The shared realm context is preserved, only the token selection falls back.
    expect(useAuthStore.getState().currentRealm).toBe('demo')
  })

  it('hydrate falls back to any stored token when master is absent too', () => {
    const ts = {
      accessToken: 'only-token',
      refreshToken: 'rt',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
    }
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ demo: ts }))
    localStorage.setItem('issuerd_realm', 'other')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().tokenSet).toEqual(ts)
  })

  it('hydrate stays null when no tokens exist at all', () => {
    localStorage.setItem('issuerd_realm', 'demo')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().tokenSet).toBeNull()
    expect(useAuthStore.getState().currentRealm).toBe('demo')
  })

  it('hydrate handles invalid json', () => {
    sessionStorage.setItem('issuerd_tokens', 'not-json')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().tokenSet).toBeNull()
    expect(sessionStorage.getItem('issuerd_tokens')).toBeNull()
  })

  it('isAuthenticated returns false when no token for realm', () => {
    expect(useAuthStore.getState().isAuthenticated('master')).toBe(false)
  })

  it('isAuthenticated returns true when token for realm is not expired', () => {
    useAuthStore.getState().setTokenSet('master', {
      accessToken: 'a',
      refreshToken: 'r',
      idToken: 'i',
      expiresAt: Date.now() + 300_000,
    })
    expect(useAuthStore.getState().isAuthenticated('master')).toBe(true)
  })

  it('isAuthenticated returns false when token for realm is expired', () => {
    useAuthStore.getState().setTokenSet('master', {
      accessToken: 'a',
      refreshToken: 'r',
      idToken: 'i',
      expiresAt: Date.now() - 1000,
    })
    expect(useAuthStore.getState().isAuthenticated('master')).toBe(false)
  })

  it('isAuthenticated is realm-scoped', () => {
    useAuthStore.getState().setTokenSet('master', {
      accessToken: 'a',
      refreshToken: 'r',
      idToken: 'i',
      expiresAt: Date.now() + 300_000,
    })
    expect(useAuthStore.getState().isAuthenticated('master')).toBe(true)
    expect(useAuthStore.getState().isAuthenticated('demo')).toBe(false)
  })

  it('migrates legacy single-realm token format', () => {
    const legacy = {
      accessToken: 'legacy',
      refreshToken: 'rt',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
    }
    sessionStorage.setItem('issuerd_tokens', JSON.stringify(legacy))
    localStorage.setItem('issuerd_realm', 'master')
    useAuthStore.getState().hydrate()
    expect(useAuthStore.getState().getTokenSet('master')).toEqual(legacy)
    expect(JSON.parse(sessionStorage.getItem('issuerd_tokens')!).master).toEqual(legacy)
  })
})
