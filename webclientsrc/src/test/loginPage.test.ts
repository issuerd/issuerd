// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

const LOGIN_HTML = readFileSync(resolve(__dirname, '../../public/login.html'), 'utf8')
const BODY = /<body>([\s\S]*?)<script\b/.exec(LOGIN_HTML)?.[1] ?? ''
const ORIGINAL_LOCATION = window.location

interface LocationStub {
  search: string
  origin: string
  pathname: string
  href: string
}

interface LoadOptions {
  query?: string
  context?: unknown
  contextText?: string
  fetch?: unknown
  inlineStyle?: boolean
  body?: string
  setup?: () => void
}

function stubLocation(search: string): LocationStub {
  const location: LocationStub = {
    search,
    origin: 'http://localhost:3000',
    pathname: '/login.html',
    href: `http://localhost:3000/login.html${search}`,
  }
  Object.defineProperty(window, 'location', { value: location, writable: true, configurable: true })
  return location
}

async function loadLoginPage(options: LoadOptions = {}) {
  const query = options.query ?? '?execution_id=exec-1&realm=test'
  document.body.innerHTML = options.body ?? BODY
  document.head.innerHTML = options.inlineStyle ? '<style id="base-style"></style>' : ''
  window.history.replaceState({}, '', `/login.html${query}`)
  const location = stubLocation(query)
  const contextFetch = vi.fn().mockResolvedValue({
    ok: true,
    text: () => Promise.resolve(options.contextText ?? JSON.stringify(options.context ?? {})),
  })
  vi.stubGlobal('fetch', 'fetch' in options ? options.fetch : contextFetch)
  options.setup?.()
  vi.resetModules()
  await import('../../public/login.js')
  await new Promise((resolve) => setTimeout(resolve, 0))
  return { contextFetch, location }
}

function bodyWithout(...selectors: string[]): string {
  const template = document.createElement('template')
  template.innerHTML = BODY
  for (const selector of selectors) {
    template.content.querySelector(selector)?.remove()
  }
  return template.innerHTML
}

function stubCrypto(digestResult?: Promise<ArrayBuffer>) {
  const getRandomValues = vi.fn((values: Uint8Array) => {
    values.fill(7)
    return values
  })
  const digest = vi.fn(() =>
    digestResult ?? Promise.resolve(Uint8Array.from([251, 255, 190, 61]).buffer),
  )
  vi.stubGlobal('crypto', { getRandomValues, subtle: { digest } })
  return { getRandomValues, digest }
}

function callbackFetch(data: unknown, ok = true, status = 200) {
  return vi.fn()
    .mockResolvedValueOnce({ ok: true, text: () => Promise.resolve('{}') })
    .mockResolvedValueOnce({ ok, status, json: () => Promise.resolve(data) })
}

const display = (id: string) => document.getElementById(id)?.style.display
const banner = () => document.getElementById('banner') as HTMLDivElement

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  Object.defineProperty(window, 'location', {
    value: ORIGINAL_LOCATION,
    writable: true,
    configurable: true,
  })
  sessionStorage.clear()
  localStorage.clear()
  document.cookie = 'issuerd_code_verifier=; Max-Age=0; Path=/'
  document.body.innerHTML = ''
  document.head.innerHTML = ''
  document.documentElement.lang = 'en'
  window.history.replaceState({}, '', '/login.html')
})

describe('login page initialization', () => {
  it('loads the tested production script from the static HTML', () => {
    expect(LOGIN_HTML).toContain('<script src="/login.js"></script>')
  })

  it('initializes the realm-scoped mid-flow form before loading enhancements', async () => {
    const { contextFetch } = await loadLoginPage({
      query: '?execution_id=exec%20%2F1&realm=test%20realm',
    })

    expect((document.getElementById('execution_id') as HTMLInputElement).value).toBe('exec /1')
    expect((document.getElementById('realm') as HTMLInputElement).value).toBe('test realm')
    expect((document.getElementById('login-form') as HTMLFormElement).action).toBe(
      'http://localhost:3000/api/v1/auth/login?realm=test%20realm',
    )
    expect(document.getElementById('realm-display')?.textContent).toBe('Realm: test realm')
    expect(contextFetch).toHaveBeenCalledWith(
      '/realms/test%20realm/login/context?execution_id=exec%20%2F1',
      { headers: { Accept: 'application/json' } },
    )
  })

  it('shows a described authorization error without redirecting into a loop', async () => {
    await loadLoginPage({ query: '?error=invalid_grant&error_description=Bad%20credentials' })

    expect(banner().textContent).toBe('Invalid username or password. (Bad credentials)')
    expect(banner().classList.contains('error')).toBe(true)
    expect(display('login-form')).toBe('none')
    expect(display('pkce-redirect')).toBe('none')
  })

  it('uses the generic error for an unknown error code', async () => {
    await loadLoginPage({ query: '?execution_id=exec-1&error=unknown_error' })

    expect(banner().textContent).toBe('Authentication failed. Please try again.')
  })

  it('shows the signed-out banner', async () => {
    await loadLoginPage({ query: '?execution_id=exec-1&logged_out=1' })

    expect(banner().textContent).toBe('You have been signed out.')
    expect(banner().classList.contains('success')).toBe(true)
  })

  it('clears login state and returns to the realm entry point on sign out', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    sessionStorage.setItem('issuerd_oidc_state', 'state')
    sessionStorage.setItem('issuerd_access_token', 'access')
    sessionStorage.setItem('issuerd_tokens', '{"master":{}}')
    document.cookie = 'issuerd_code_verifier=verifier; Path=/'
    const { location } = await loadLoginPage({ query: '?execution_id=exec-1&realm=test%20realm' })

    ;(document.getElementById('sign-out-btn') as HTMLButtonElement).click()

    expect(sessionStorage.getItem('issuerd_code_verifier')).toBeNull()
    expect(sessionStorage.getItem('issuerd_oidc_state')).toBeNull()
    expect(sessionStorage.getItem('issuerd_access_token')).toBeNull()
    expect(sessionStorage.getItem('issuerd_tokens')).toBeNull()
    expect(document.cookie).not.toContain('issuerd_code_verifier=verifier')
    expect(location.href).toBe('/login.html?realm=test%20realm')
  })
})

describe('login page context loading', () => {
  it('applies localization and inserts the theme after the inline style', async () => {
    await loadLoginPage({
      query: '?execution_id=exec-1&realm=test&logged_out=1&error=invalid_grant&error_description=Denied',
      inlineStyle: true,
      context: {
        locale: 'de',
        messages: {
          'login.title': 'Anmelden',
          'login.username': 'Benutzername',
          'login.password': 'Passwort',
          'login.submit': 'Weiter',
          'login.rememberMe': 'Angemeldet bleiben',
          'login.forgotPassword': 'Passwort vergessen?',
          'login.or': 'oder',
          'login.realmPrefix': 'Bereich:',
          'login.signOut': 'Abmelden',
          'login.signedOut': 'Sie wurden abgemeldet.',
          'login.error.invalid_grant': 'Anmeldung fehlgeschlagen.',
          'login.redirecting': 'Weiterleitung...',
        },
      },
    })

    expect(document.documentElement.lang).toBe('de')
    expect(document.getElementById('card-title')?.textContent).toBe('Anmelden')
    expect(document.querySelector('label[for="username"]')?.textContent).toBe('Benutzername')
    expect(document.querySelector('label[for="password"]')?.textContent).toBe('Passwort')
    expect(document.getElementById('login-submit')?.textContent).toBe('Weiter')
    expect(document.querySelector('#remember-me-container span')?.textContent).toBe(
      'Angemeldet bleiben',
    )
    expect(document.getElementById('forgot-password-link')?.textContent).toBe(
      'Passwort vergessen?',
    )
    expect(document.getElementById('register-link')?.textContent).toBe('Register')
    expect(document.querySelector('#idp-section .idp-divider span')?.textContent).toBe('oder')
    expect(document.getElementById('realm-display')?.textContent).toBe('Bereich: test')
    expect(document.getElementById('sign-out-btn')?.textContent).toBe('Abmelden')
    expect(banner().textContent).toBe('Anmeldung fehlgeschlagen. (Denied)')
    expect(document.querySelector('#pkce-redirect span')?.textContent).toBe('Weiterleitung...')
    const style = document.getElementById('base-style')
    expect((style?.nextSibling as HTMLLinkElement).href).toBe(
      'http://localhost:3000/realms/test/theme/login.css',
    )
  })

  it('appends the theme to head and preserves static fallbacks', async () => {
    await loadLoginPage()

    expect(document.getElementById('card-title')?.textContent).toBe('Sign In')
    expect(document.querySelector('label[for="username"]')?.textContent).toBe('Username')
    expect(document.querySelector('label[for="password"]')?.textContent).toBe('Password')
    expect(document.getElementById('login-submit')?.textContent).toBe('Sign In')
    expect(document.querySelector('#remember-me-container span')?.textContent).toBe('Remember me')
    expect(document.getElementById('register-link')?.textContent).toBe('Register')
    expect(document.querySelector('#idp-section .idp-divider span')?.textContent).toBe('or')
    expect(document.getElementById('sign-out-btn')?.textContent).toBe('Sign Out')
    expect(document.head.lastElementChild?.getAttribute('href')).toBe('/realms/test/theme/login.css')
  })

  it('uses a localized generic authentication failure', async () => {
    await loadLoginPage({
      query: '?execution_id=exec-1&error=other',
      context: { messages: { 'login.authFailed': 'Localized failure.' } },
    })

    expect(banner().textContent).toBe('Localized failure.')
  })

  it('uses the built-in error when its localized key is absent', async () => {
    await loadLoginPage({
      query: '?execution_id=exec-1&error=access_denied',
      context: { messages: {} },
    })

    expect(banner().textContent).toBe('Access denied.')
  })

  it('ignores a non-successful context response', async () => {
    const text = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, text })

    await loadLoginPage({ fetch: fetchMock })

    expect(text).not.toHaveBeenCalled()
    expect(document.head.querySelector('link')).toBeNull()
  })

  it('keeps the static page when the context request rejects', async () => {
    await loadLoginPage({ fetch: vi.fn().mockRejectedValue(new Error('offline')) })

    expect(document.getElementById('card-title')?.textContent).toBe('Sign In')
    expect(document.head.querySelector('link')).toBeNull()
  })

  it('keeps the static page when starting the context request throws', async () => {
    await loadLoginPage({
      fetch: vi.fn(() => {
        throw new Error('unavailable')
      }),
    })

    expect(document.getElementById('card-title')?.textContent).toBe('Sign In')
    expect(document.head.querySelector('link')).toBeNull()
  })

  it.each(['', 'not-json', 'null'])('ignores empty or invalid context text %j', async (text) => {
    await loadLoginPage({ contextText: text })

    expect(document.head.querySelector('link')).toBeNull()
    expect(document.getElementById('card-title')?.textContent).toBe('Sign In')
  })

  it('uses the XHR fallback and ignores incomplete or unsuccessful responses', async () => {
    const xhr = {
      readyState: 0,
      status: 0,
      responseText: '',
      open: vi.fn(),
      setRequestHeader: vi.fn(),
      send: vi.fn(),
      onreadystatechange: undefined as undefined | (() => void),
    }
    function XMLHttpRequestMock() {
      return xhr
    }

    await loadLoginPage({
      fetch: undefined,
      setup: () => vi.stubGlobal('XMLHttpRequest', XMLHttpRequestMock),
    })

    expect(xhr.open).toHaveBeenCalledWith(
      'GET',
      '/realms/test/login/context?execution_id=exec-1',
      true,
    )
    expect(xhr.setRequestHeader).toHaveBeenCalledWith('Accept', 'application/json')
    expect(xhr.send).toHaveBeenCalledOnce()

    xhr.readyState = 3
    xhr.status = 200
    xhr.onreadystatechange?.()
    xhr.readyState = 4
    xhr.status = 199
    xhr.onreadystatechange?.()
    xhr.status = 300
    xhr.onreadystatechange?.()
    expect(document.head.querySelector('link')).toBeNull()

    xhr.status = 204
    xhr.responseText = JSON.stringify({ locale: 'fr' })
    xhr.onreadystatechange?.()
    expect(document.documentElement.lang).toBe('fr')
    expect(document.head.querySelector('link')).not.toBeNull()
  })

  it('works without fetch or XMLHttpRequest', async () => {
    await loadLoginPage({
      fetch: undefined,
      setup: () => vi.stubGlobal('XMLHttpRequest', undefined),
    })

    expect((document.getElementById('realm') as HTMLInputElement).value).toBe('test')
    expect(document.head.querySelector('link')).toBeNull()
  })
})

describe('login page self-service and identity providers', () => {
  it('reveals remember-me, reset-password, and registration controls', async () => {
    await loadLoginPage({
      context: {
        remember_me_enabled: true,
        reset_password_allowed: true,
        registration_enabled: true,
      },
    })

    expect(display('remember-me-container')).toBe('flex')
    expect((document.getElementById('forgot-password-link') as HTMLAnchorElement).href).toBe(
      'http://localhost:3000/realms/test/login/reset-credentials',
    )
    expect((document.getElementById('register-link') as HTMLAnchorElement).href).toBe(
      'http://localhost:3000/realms/test/login/register?execution_id=exec-1',
    )
    expect(display('login-links')).toBe('flex')
  })

  it('builds registration links without an execution during PKCE entry', async () => {
    await loadLoginPage({
      query: '',
      context: {
        registration_enabled: true,
        identity_providers: [{ alias: 'github' }],
      },
      setup: () => stubCrypto(),
    })

    expect((document.getElementById('register-link') as HTMLAnchorElement).href).toBe(
      'http://localhost:3000/realms/master/login/register',
    )
    expect(document.querySelectorAll('.idp-btn')).toHaveLength(0)
  })

  it('switches to email-code login and hides password-only controls', async () => {
    await loadLoginPage({
      context: {
        remember_me_enabled: true,
        reset_password_allowed: true,
        email_code_login: true,
        messages: { 'login.email': 'Work email', 'login.sendCode': 'Email me a code' },
      },
    })

    const password = document.getElementById('password') as HTMLInputElement
    const username = document.getElementById('username') as HTMLInputElement
    expect(password.required).toBe(false)
    expect(password.style.display).toBe('none')
    expect(document.querySelector('label[for="password"]')?.style.display).toBe('none')
    expect(display('remember-me-container')).toBe('none')
    expect(display('forgot-password-link')).toBe('none')
    expect(username.type).toBe('email')
    expect(username.autocomplete).toBe('email')
    expect(document.querySelector('label[for="username"]')?.textContent).toBe('Work email')
    expect(document.getElementById('login-submit')?.textContent).toBe('Email me a code')
  })

  it('renders valid identity providers and skips malformed entries', async () => {
    await loadLoginPage({
      context: {
        identity_providers: [null, {}, { alias: 'github' }, { alias: 'key cloak', display_name: 'Keycloak' }],
        messages: { 'login.continueWith': 'Use {0}' },
      },
    })

    const links = document.querySelectorAll<HTMLAnchorElement>('.idp-btn')
    expect(links).toHaveLength(2)
    expect(links[0].textContent).toBe('Use github')
    expect(links[0].href).toBe(
      'http://localhost:3000/realms/test/broker/github/login?flow=exec-1',
    )
    expect(links[1].textContent).toBe('Use Keycloak')
    expect(links[1].href).toBe(
      'http://localhost:3000/realms/test/broker/key%20cloak/login?flow=exec-1',
    )
    expect(display('idp-section')).toBe('block')
  })

  it('leaves the provider section hidden when no entry is usable', async () => {
    await loadLoginPage({ context: { identity_providers: [null, {}] } })

    expect(document.querySelectorAll('.idp-btn')).toHaveLength(0)
    expect(display('idp-section')).toBe('none')
  })

  it('ignores an empty provider list', async () => {
    await loadLoginPage({ context: { identity_providers: [] } })

    expect(display('idp-section')).toBe('none')
  })

  it('tolerates missing optional controls during a full context update', async () => {
    await loadLoginPage({
      body: bodyWithout(
        '#card-title',
        'label[for="username"]',
        'label[for="password"]',
        '#login-submit',
        '#remember-me-container',
        '#forgot-password-link',
        '#register-link',
        '#realm-display',
        '#pkce-redirect span',
        '#password',
        '#username',
        '#idp-section',
        '#client-logo',
        '#client-links',
      ),
      context: {
        remember_me_enabled: true,
        reset_password_allowed: true,
        registration_enabled: true,
        email_code_login: true,
        identity_providers: [{ alias: 'github' }],
        client_logo_uri: 'https://app.example.com/logo.png',
        client_policy_uri: 'https://app.example.com/policy',
        client_tos_uri: 'https://app.example.com/tos',
      },
    })

    expect(document.head.querySelector('link')).not.toBeNull()
  })

  it('tolerates missing link targets when their container remains', async () => {
    const template = document.createElement('template')
    template.innerHTML = bodyWithout('#client-policy-link', '#client-tos-link')
    const loginLinks = template.content.querySelector('#login-links')!
    for (const child of Array.from(loginLinks.children)) {
      loginLinks.before(child)
    }
    loginLinks.remove()

    await loadLoginPage({
      body: template.innerHTML,
      context: {
        reset_password_allowed: true,
        registration_enabled: true,
        client_policy_uri: 'https://app.example.com/policy',
        client_tos_uri: 'https://app.example.com/tos',
      },
    })

    expect(display('forgot-password-link')).toBe('inline')
    expect(display('register-link')).toBe('inline')
    expect(display('client-links')).toBe('block')
  })

  it('tolerates a missing PKCE status container during form login', async () => {
    await loadLoginPage({ body: bodyWithout('#pkce-redirect') })

    expect(document.head.querySelector('link')).not.toBeNull()
    expect(display('login-form')).not.toBe('none')
  })
})

describe('login page client branding', () => {
  it('renders logo, policy and tos links when the flow client carries them', async () => {
    await loadLoginPage({
      context: {
        client_name: 'Acme App',
        client_logo_uri: 'https://app.example.com/logo.png',
        client_policy_uri: 'https://app.example.com/policy',
        client_tos_uri: 'https://app.example.com/tos',
      },
    })

    const logo = document.getElementById('client-logo') as HTMLImageElement
    expect(logo.style.display).toBe('block')
    expect(logo.src).toBe('https://app.example.com/logo.png')
    expect(logo.alt).toBe('Acme App')

    const policy = document.getElementById('client-policy-link') as HTMLAnchorElement
    expect(policy.style.display).toBe('inline')
    expect(policy.href).toBe('https://app.example.com/policy')
    expect(policy.textContent).toBe('Privacy Policy')

    const tos = document.getElementById('client-tos-link') as HTMLAnchorElement
    expect(tos.style.display).toBe('inline')
    expect(tos.href).toBe('https://app.example.com/tos')
    expect(tos.textContent).toBe('Terms of Service')
    expect(display('client-links')).toBe('block')
  })

  it('changes nothing when the client carries no branding', async () => {
    await loadLoginPage()

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    expect(display('client-tos-link')).toBe('none')
    expect(display('client-links')).toBe('none')
  })

  it('renders only the links that are present', async () => {
    await loadLoginPage({ context: { client_tos_uri: 'https://app.example.com/tos' } })

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    expect(display('client-tos-link')).toBe('inline')
    expect(display('client-links')).toBe('block')
  })

  it('refuses non-http(s) branding URIs', async () => {
    await loadLoginPage({
      context: {
        client_logo_uri: 'javascript:alert(1)',
        client_policy_uri: 'javascript:alert(1)',
      },
    })

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    expect(display('client-links')).toBe('none')
  })

  it('accepts HTTP branding and rejects malformed URIs', async () => {
    await loadLoginPage({
      context: {
        client_logo_uri: 'http://app.example.com/logo.png',
        client_policy_uri: 'http://app.example.com/policy',
        client_tos_uri: 'http://[::1',
      },
    })

    const logo = document.getElementById('client-logo') as HTMLImageElement
    expect(logo.style.display).toBe('block')
    expect(logo.alt).toBe('')
    expect(display('client-policy-link')).toBe('inline')
    expect(display('client-tos-link')).toBe('none')
    expect(display('client-links')).toBe('block')
  })
})

describe('login page PKCE entry', () => {
  it('creates and stores PKCE state and redirects with the default client', async () => {
    const { getRandomValues, digest } = stubCrypto()

    const { location } = await loadLoginPage({ query: '' })

    const verifier = sessionStorage.getItem('issuerd_code_verifier')
    const state = sessionStorage.getItem('issuerd_oidc_state')
    expect(verifier).toHaveLength(128)
    expect(state).toHaveLength(32)
    expect(sessionStorage.getItem('issuerd_oidc_realm')).toBe('master')
    expect(document.cookie).toContain(`issuerd_code_verifier=${encodeURIComponent(verifier!)}`)
    expect(getRandomValues).toHaveBeenCalledTimes(2)
    expect(digest.mock.calls[0][0]).toBe('SHA-256')
    expect(new TextDecoder().decode(digest.mock.calls[0][1])).toBe(verifier)
    expect(display('login-form')).toBe('none')

    const target = new URL(location.href)
    expect(target.origin).toBe('http://localhost:3000')
    expect(target.pathname).toBe('/realms/master/protocol/openid-connect/auth')
    expect(target.searchParams.get('client_id')).toBe('admin-cli')
    expect(target.searchParams.get('response_type')).toBe('code')
    expect(target.searchParams.get('scope')).toBe('openid profile')
    expect(target.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/admin/console/callback',
    )
    expect(target.searchParams.get('code_challenge')).toBe('-_--PQ')
    expect(target.searchParams.get('code_challenge_method')).toBe('S256')
    expect(target.searchParams.get('state')).toBe(state)
  })

  it('reuses an existing verifier and state', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'stored-verifier')
    sessionStorage.setItem('issuerd_oidc_state', 'stored-state')
    const { getRandomValues } = stubCrypto()

    const { location } = await loadLoginPage({ query: '' })

    expect(getRandomValues).not.toHaveBeenCalled()
    expect(sessionStorage.getItem('issuerd_code_verifier')).toBe('stored-verifier')
    expect(new URL(location.href).searchParams.get('state')).toBe('stored-state')
  })

  it('regenerates verifier and state when the login realm changes', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'master-verifier')
    sessionStorage.setItem('issuerd_oidc_state', 'master-state')
    sessionStorage.setItem('issuerd_oidc_realm', 'master')
    const { getRandomValues } = stubCrypto()

    const { location } = await loadLoginPage({ query: '?realm=myrealm&client_id=account-console' })

    expect(getRandomValues).toHaveBeenCalledTimes(2)
    expect(sessionStorage.getItem('issuerd_code_verifier')).not.toBe('master-verifier')
    expect(sessionStorage.getItem('issuerd_oidc_state')).not.toBe('master-state')
    expect(sessionStorage.getItem('issuerd_oidc_realm')).toBe('myrealm')
    expect(new URL(location.href).pathname).toBe('/realms/myrealm/protocol/openid-connect/auth')
    expect(new URL(location.href).searchParams.get('state')).not.toBe('master-state')
  })

  it('falls back to the verifier cookie', async () => {
    document.cookie = 'issuerd_code_verifier=cookie%20verifier; Path=/'
    sessionStorage.setItem('issuerd_oidc_state', 'stored-state')
    const { digest } = stubCrypto()

    await loadLoginPage({ query: '' })

    const encoded = digest.mock.calls[0][1] as Uint8Array
    expect(new TextDecoder().decode(encoded)).toBe('cookie verifier')
  })

  it('regenerates both values when only the verifier exists', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'old-verifier')
    const { getRandomValues } = stubCrypto()

    const { location } = await loadLoginPage({ query: '' })

    expect(getRandomValues).toHaveBeenCalledTimes(2)
    expect(sessionStorage.getItem('issuerd_code_verifier')).not.toBe('old-verifier')
    expect(new URL(location.href).searchParams.get('state')).toHaveLength(32)
  })

  it('uses custom realm, client, and same-origin redirect parameters', async () => {
    stubCrypto()

    const { location } = await loadLoginPage({
      query: '?realm=custom%20realm&client_id=custom-client&redirect_uri=%2Faccount%2Fcallback%3Fx%3D1',
    })

    const target = new URL(location.href)
    expect(target.pathname).toBe('/realms/custom%20realm/protocol/openid-connect/auth')
    expect(target.searchParams.get('client_id')).toBe('custom-client')
    expect(target.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/account/callback?x=1',
    )
  })

  it.each([
    'https://evil.example.com/callback',
    'javascript:alert(1)',
    'http://[::1',
  ])('falls back to the console callback for unsafe redirect %s', async (redirectUri) => {
    stubCrypto()

    const { location } = await loadLoginPage({
      query: `?redirect_uri=${encodeURIComponent(redirectUri)}`,
    })

    expect(new URL(location.href).searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/admin/console/callback',
    )
  })

  it.each([
    { rejection: new Error('digest failed'), expected: 'digest failed' },
    { rejection: 'denied', expected: 'denied' },
    { rejection: null, expected: 'null' },
  ])('restores the form when PKCE fails with $expected', async ({ rejection, expected }) => {
    stubCrypto(Promise.reject(rejection))

    await loadLoginPage({ query: '' })

    expect(banner().textContent).toBe(`PKCE redirect failed: ${expected}`)
    expect(banner().classList.contains('error')).toBe(true)
    expect(display('pkce-redirect')).toBe('none')
    expect(display('login-form')).toBe('block')
  })
})

describe('login page OAuth callback', () => {
  it('exchanges the code, preserves token sets, and uses explicit flow parameters', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    sessionStorage.setItem('issuerd_code_verifier', 'verifier /1')
    sessionStorage.setItem('issuerd_oidc_realm', 'stored realm')
    sessionStorage.setItem('issuerd_tokens', JSON.stringify({ other: { accessToken: 'keep' } }))
    const fetchMock = callbackFetch({
      access_token: 'access',
      refresh_token: 'refresh',
      id_token: 'id',
      expires_in: 60,
    })

    const { location } = await loadLoginPage({
      query:
        '?execution_id=flow-1&code=code%20%2F1&realm=url-realm&client_id=custom-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fadmin%2Fconsole%2Fcallback%3Ffrom%3Dcustom',
      fetch: fetchMock,
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/realms/url-realm/login/context?execution_id=flow-1',
    )
    expect(fetchMock.mock.calls[1][0]).toBe(
      'http://localhost:3000/realms/stored%20realm/protocol/openid-connect/token',
    )
    const init = fetchMock.mock.calls[1][1]
    expect(init.method).toBe('POST')
    expect(init.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' })
    const body = new URLSearchParams(init.body)
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code')).toBe('code /1')
    expect(body.get('redirect_uri')).toBe('http://localhost:3000/admin/console/callback?from=custom')
    expect(body.get('client_id')).toBe('custom-client')
    expect(body.get('code_verifier')).toBe('verifier /1')

    const tokens = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(tokens.other.accessToken).toBe('keep')
    expect(tokens['stored realm']).toEqual({
      accessToken: 'access',
      refreshToken: 'refresh',
      idToken: 'id',
      expiresAt: 1_700_000_060_000,
    })
    expect(sessionStorage.getItem('issuerd_oidc_realm')).toBeNull()
    expect(localStorage.getItem('issuerd_realm')).toBe('stored realm')
    expect(location.href).toBe('http://localhost:3000/admin/console/callback?from=custom')
    expect(document.querySelector('#pkce-redirect span')?.textContent).toBe('Completing sign in...')
  })

  it('uses callback defaults for tokens, realm, client, and redirect', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    const fetchMock = callbackFetch({ access_token: 'access' })

    const { location } = await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    expect(fetchMock.mock.calls[1][0]).toBe(
      'http://localhost:3000/realms/master/protocol/openid-connect/token',
    )
    const body = new URLSearchParams(fetchMock.mock.calls[1][1].body)
    expect(body.get('client_id')).toBe('admin-cli')
    expect(body.get('redirect_uri')).toBe('http://localhost:3000/admin/console/callback')
    const tokens = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(tokens.master).toEqual({
      accessToken: 'access',
      refreshToken: '',
      idToken: '',
      expiresAt: 1_700_000_300_000,
    })
    expect(location.href).toBe('http://localhost:3000/admin/console/callback')
  })

  it.each([
    { legacyRealm: 'legacy-realm', expectedRealm: 'legacy-realm' },
    { legacyRealm: null, expectedRealm: 'master' },
  ])('migrates legacy tokens with realm $expectedRealm', async ({ legacyRealm, expectedRealm }) => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    sessionStorage.setItem(
      'issuerd_tokens',
      JSON.stringify({ accessToken: 'old-access', refreshToken: 'old-refresh' }),
    )
    if (legacyRealm) localStorage.setItem('issuerd_realm', legacyRealm)
    const fetchMock = callbackFetch({ access_token: 'new-access' })

    await loadLoginPage({ query: '?code=abc&realm=new-realm', fetch: fetchMock })

    const tokens = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(tokens[expectedRealm]).toEqual({ accessToken: 'old-access', refreshToken: 'old-refresh' })
    expect(tokens['new-realm'].accessToken).toBe('new-access')
  })

  it.each(['null', '"text"', '[]'])('replaces invalid stored token shape %s', async (rawTokens) => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    sessionStorage.setItem('issuerd_tokens', rawTokens)
    const fetchMock = callbackFetch({ access_token: 'access' })

    await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    const tokens = JSON.parse(sessionStorage.getItem('issuerd_tokens')!)
    expect(Object.keys(tokens)).toEqual(['master'])
    expect(tokens.master.accessToken).toBe('access')
  })

  it('shows an expired-session error when the verifier is missing', async () => {
    const fetchMock = callbackFetch({ access_token: 'unused' })

    await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(banner().textContent).toBe('Session expired. Please sign in again.')
    expect(display('pkce-redirect')).toBe('none')
    expect(display('login-form')).toBe('block')
  })

  it.each([
    { data: { error_description: 'Code expired', error: 'invalid_grant' }, expected: 'Code expired' },
    { data: { error: 'invalid_grant' }, expected: 'invalid_grant' },
    { data: {}, expected: 'Token exchange failed (400)' },
  ])('shows token endpoint error $expected', async ({ data, expected }) => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    const fetchMock = callbackFetch(data, false, 400)

    await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    expect(banner().textContent).toBe(`Sign in failed: ${expected}`)
    expect(display('pkce-redirect')).toBe('none')
    expect(display('login-form')).toBe('block')
  })

  it('shows token request network failures', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, text: () => Promise.resolve('{}') })
      .mockRejectedValueOnce(new Error('offline'))

    await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    expect(banner().textContent).toBe('Sign in failed: offline')
  })

  it('shows malformed stored-token failures', async () => {
    sessionStorage.setItem('issuerd_code_verifier', 'verifier')
    sessionStorage.setItem('issuerd_tokens', 'not-json')
    const fetchMock = callbackFetch({ access_token: 'access' })

    await loadLoginPage({ query: '?code=abc', fetch: fetchMock })

    expect(banner().textContent).toMatch(/^Sign in failed: /)
    expect(display('login-form')).toBe('block')
  })

  it('tolerates a missing sign-out control in the callback path', async () => {
    await loadLoginPage({ query: '?code=abc', body: bodyWithout('#sign-out-btn') })

    expect(banner().textContent).toBe('Session expired. Please sign in again.')
    expect(document.head.querySelector('link')).not.toBeNull()
  })
})
