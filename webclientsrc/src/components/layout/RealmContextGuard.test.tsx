// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import RealmContextGuard from './RealmContextGuard'
import { useAuthStore } from '../../state/authStore'

describe('RealmContextGuard', () => {
  beforeEach(() => {
    useAuthStore.setState({ tokenSet: null, currentRealm: null })
    vi.stubGlobal('location', { href: '' })
  })

  it('redirects to login when no token', () => {
    const assignMock = vi.fn()
    Object.defineProperty(window, 'location', {
      value: { href: assignMock },
      writable: true,
    })
    render(
      <MemoryRouter>
        <RealmContextGuard>
          <div data-testid="child">Child</div>
        </RealmContextGuard>
      </MemoryRouter>
    )
    expect(window.location.href).toBe('/login.html')
  })

  it('redirects to realm-picker when no realm', () => {
    useAuthStore.setState({
      tokenSet: { accessToken: 'abc', refreshToken: 'r', idToken: 'i', expiresAt: Date.now() + 300_000 },
      currentRealm: null,
    })
    render(
      <MemoryRouter>
        <RealmContextGuard>
          <div data-testid="child">Child</div>
        </RealmContextGuard>
      </MemoryRouter>
    )
    expect(screen.queryByTestId('child')).not.toBeInTheDocument()
  })

  it('renders children when authenticated and realm set', () => {
    useAuthStore.setState({
      tokenSet: { accessToken: 'abc', refreshToken: 'r', idToken: 'i', expiresAt: Date.now() + 300_000 },
      currentRealm: 'master',
    })
    render(
      <MemoryRouter>
        <RealmContextGuard>
          <div data-testid="child">Child</div>
        </RealmContextGuard>
      </MemoryRouter>
    )
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })
})
