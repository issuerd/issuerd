// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Outlet } from 'react-router-dom'
import App from './App'
import { useAuthStore } from './state/authStore'

vi.mock('./components/layout/AppLayout', () => ({
  default: () => <div><Outlet /></div>,
}))
vi.mock('./pages/realms/RealmListPage', () => ({
  default: () => <div>Master realm list</div>,
}))
vi.mock('./pages/realms/RealmSettingsPage', () => ({
  default: () => <div>Own realm settings</div>,
}))

describe('realm administration navigation', () => {
  beforeEach(() => {
    sessionStorage.clear()
    localStorage.clear()
  })

  function authenticate(realm: string) {
    useAuthStore.getState().setTokenSet(realm, {
      accessToken: 'access',
      refreshToken: 'refresh',
      idToken: 'id',
      expiresAt: Date.now() + 300_000,
      clientId: 'admin-cli',
      realm,
    })
  }

  it('keeps the global realm list for a master-issued admin token', async () => {
    authenticate('master')
    render(<App />, { wrapper: ({ children }) => <MemoryRouter initialEntries={['/realms']}>{children}</MemoryRouter> })
    expect(await screen.findByText('Master realm list')).toBeInTheDocument()
  })

  it('routes a realm-issued admin token to its own realm settings', async () => {
    authenticate('user-sandbox')
    render(<App />, { wrapper: ({ children }) => <MemoryRouter initialEntries={['/realms']}>{children}</MemoryRouter> })
    expect(await screen.findByText('Own realm settings')).toBeInTheDocument()
    expect(screen.queryByText('Master realm list')).not.toBeInTheDocument()
  })

  it('opens own realm settings from the console root with a realm token', async () => {
    authenticate('user-sandbox')
    useAuthStore.getState().hydrate()
    render(<App />, { wrapper: ({ children }) => <MemoryRouter initialEntries={['/']}>{children}</MemoryRouter> })
    expect(await screen.findByText('Own realm settings')).toBeInTheDocument()
  })
})
