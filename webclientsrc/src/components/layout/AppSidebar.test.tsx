// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import AppSidebar from './AppSidebar'
import { SidebarProvider, useSidebar } from '@/components/ui/sidebar'
import { useAuthStore } from '@/state/authStore'

let mockRealmsData: any = [
  { realm: 'master', display_name: 'Master', enabled: true },
  { realm: 'demo', display_name: 'Demo', enabled: true },
]

vi.mock('@/api/hooks/useRealms', () => ({
  useRealms: () => ({ data: mockRealmsData, isLoading: false, error: null }),
}))

beforeAll(() => {
  // Radix DropdownMenu needs pointer-capture APIs jsdom does not implement.
  window.Element.prototype.hasPointerCapture = vi.fn()
  window.Element.prototype.setPointerCapture = vi.fn()
  window.Element.prototype.releasePointerCapture = vi.fn()
  window.Element.prototype.scrollIntoView = vi.fn()
  // SidebarProvider's use-mobile hook needs matchMedia.
  window.matchMedia =
    window.matchMedia ||
    ((query: string) =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }) as unknown as MediaQueryList)
})

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <MemoryRouter>
      <SidebarProvider>{children}</SidebarProvider>
    </MemoryRouter>
  )
}

describe('AppSidebar RealmSwitcher', () => {
  beforeEach(() => {
    mockRealmsData = [
      { realm: 'master', display_name: 'Master', enabled: true },
      { realm: 'demo', display_name: 'Demo', enabled: true },
    ]
    useAuthStore.setState({
      tokenSet: {
        accessToken: 'abc',
        refreshToken: 'r',
        idToken: 'i',
        expiresAt: Date.now() + 300_000,
      },
      currentRealm: 'master',
    })
  })

  it('shows the current realm in the trigger', () => {
    render(<AppSidebar />, { wrapper })
    // The user-menu footer also renders the realm name; the switcher is first
    // in DOM order (sidebar header precedes footer).
    expect(screen.getAllByText('master')[0]).toBeInTheDocument()
  })

  it('falls back to Issuerd when no realm is selected', () => {
    useAuthStore.setState({ currentRealm: null })
    render(<AppSidebar />, { wrapper })
    expect(screen.getByText('Issuerd')).toBeInTheDocument()
  })

  it('lists realms in an inline dropdown and switches on click', async () => {
    const user = userEvent.setup()
    const sink = { path: '' }
    function PathProbe() {
      sink.path = useLocation().pathname
      return null
    }
    render(
      <>
        <PathProbe />
        <AppSidebar />
      </>,
      { wrapper }
    )

    await user.click(screen.getAllByText('master')[0])

    // Menu items render for both realms once the dropdown opens.
    const demoItem = await screen.findByText('demo')
    expect(screen.getAllByText('master').length).toBeGreaterThan(2)

    await user.click(demoItem)
    expect(useAuthStore.getState().currentRealm).toBe('demo')
    // Switching realms leaves deep entity routes behind (they 404 cross-realm).
    expect(sink.path).toBe('/dashboard')
  })

  it('does not navigate when selecting the already-current realm', async () => {
    const user = userEvent.setup()
    const sink = { path: '' }
    function PathProbe() {
      sink.path = useLocation().pathname
      return null
    }
    render(
      <>
        <PathProbe />
        <AppSidebar />
      </>,
      { wrapper }
    )

    await user.click(screen.getAllByText('master')[0])
    const menu = await screen.findByRole('menu')
    await user.click(within(menu).getByText('master'))

    expect(useAuthStore.getState().currentRealm).toBe('master')
    expect(sink.path).toBe('/')
  })

  it('shows an empty state when no realms exist', async () => {
    mockRealmsData = []
    const user = userEvent.setup()
    render(<AppSidebar />, { wrapper })

    await user.click(screen.getAllByText('master')[0])
    expect(await screen.findByText('No realms')).toBeInTheDocument()
  })
})

describe('AppSidebar mobile navigation', () => {
  it('closes the mobile sheet after clicking a nav item', async () => {
    let ctx: ReturnType<typeof useSidebar> | null = null
    function Probe() {
      ctx = useSidebar()
      return null
    }
    const user = userEvent.setup()
    render(
      <MemoryRouter>
        <SidebarProvider>
          <Probe />
          <AppSidebar />
        </SidebarProvider>
      </MemoryRouter>
    )

    act(() => ctx!.setOpenMobile(true))
    expect(ctx!.openMobile).toBe(true)

    await user.click(screen.getByRole('link', { name: 'Users' }))
    expect(ctx!.openMobile).toBe(false)
  })
})
