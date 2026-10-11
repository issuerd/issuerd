// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

// Tests for the static login page (public/login.html) client branding: the
// page is plain HTML+JS (the one non-React surface), so the test loads the
// file into jsdom, runs its inline script with a stubbed login-context
// fetch, and asserts the DOM the conformance suite's browser would see.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, it, expect, vi, afterEach } from 'vitest'

const LOGIN_HTML = readFileSync(resolve(__dirname, '../../public/login.html'), 'utf8')
const SCRIPT = /<script>([\s\S]*)<\/script>/.exec(LOGIN_HTML)?.[1] ?? ''
const BODY = /<body>([\s\S]*?)<script>/.exec(LOGIN_HTML)?.[1] ?? ''

interface LoginContext {
  client_name?: string
  client_logo_uri?: string
  client_policy_uri?: string
  client_tos_uri?: string
}

/// Render login.html mid-flow (execution_id present) and apply the given
/// login-context payload, returning once the context fetch has landed.
async function loadLoginPage(ctx: LoginContext) {
  document.body.innerHTML = BODY
  window.history.replaceState({}, '', '/login.html?execution_id=exec-1&realm=test')
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(JSON.stringify(ctx)),
    }),
  )
  // The page's script is an IIFE: run it in this jsdom window.
  new Function(SCRIPT)()
  // Flush the fetch().then() microtask chain (fetch → text → applyContext).
  await new Promise((resolve) => setTimeout(resolve, 0))
}

const display = (id: string) => document.getElementById(id)?.style.display

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('login page client branding', () => {
  it('renders logo, policy and tos links when the flow client carries them', async () => {
    await loadLoginPage({
      client_name: 'Acme App',
      client_logo_uri: 'https://app.example.com/logo.png',
      client_policy_uri: 'https://app.example.com/policy',
      client_tos_uri: 'https://app.example.com/tos',
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
    await loadLoginPage({})

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    expect(display('client-tos-link')).toBe('none')
    expect(display('client-links')).toBe('none')
  })

  it('renders only the links that are present', async () => {
    await loadLoginPage({ client_tos_uri: 'https://app.example.com/tos' })

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    const tos = document.getElementById('client-tos-link') as HTMLAnchorElement
    expect(tos.style.display).toBe('inline')
    expect(display('client-links')).toBe('block')
  })

  it('refuses non-http(s) branding URIs', async () => {
    await loadLoginPage({
      client_logo_uri: 'javascript:alert(1)',
      client_policy_uri: 'javascript:alert(1)',
    })

    expect(display('client-logo')).toBe('none')
    expect(display('client-policy-link')).toBe('none')
    expect(display('client-links')).toBe('none')
  })
})
