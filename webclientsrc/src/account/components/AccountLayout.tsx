// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import { User, LogOut, Monitor, KeyRound, Link2, Globe, Menu } from 'lucide-react'
import { LogoMark } from '../../components/ui/Logo'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '../../components/ui/sheet'
import { cn } from '../../lib/utils'
import { ACCOUNT_CLIENT_ID, getAccountRealm } from '../../config'
import { useAuthStore } from '../../state/authStore'
import { postLogout } from '../../api/client'

const NAV_ITEMS = [
  { to: '/profile', label: 'Profile', icon: User },
  { to: '/security', label: 'Security', icon: KeyRound },
  { to: '/consents', label: 'Consents', icon: Link2 },
  { to: '/linked-accounts', label: 'Linked Accounts', icon: Globe },
  { to: '/sessions', label: 'Sessions', icon: Monitor },
]

function AccountNavigation({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Account navigation" className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
      {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-lg transition-colors',
              isActive
                ? 'bg-accent text-primary'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent',
            )
          }
        >
          <Icon className="w-4 h-4 shrink-0" />
          {label}
        </NavLink>
      ))}
    </nav>
  )
}

function SignOutButton({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="p-4 border-t border-border">
      <button
        type="button"
        onClick={onLogout}
        className="flex items-center gap-3 px-4 py-3 text-sm font-medium text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors w-full"
      >
        <LogOut className="w-4 h-4" />
        Sign Out
      </button>
    </div>
  )
}

export default function AccountLayout() {
  const logout = useAuthStore((s) => s.logout)
  const [mobileOpen, setMobileOpen] = useState(false)

  async function handleLogout() {
    await postLogout()
    logout()
    const realm = getAccountRealm()
    const redirectUri = `${window.location.origin}/realms/${encodeURIComponent(realm)}/account`
    window.location.href = `/login.html?logged_out=1&realm=${encodeURIComponent(realm)}&client_id=${ACCOUNT_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}`
  }

  return (
    <div className="min-h-screen bg-background md:flex">
      <aside className="hidden w-64 shrink-0 border-r border-border bg-card flex-col md:flex">
        <div className="p-6 flex items-center gap-3">
          <LogoMark className="w-6 h-6 text-primary" />
          <span className="font-display text-lg text-foreground font-bold tracking-wider uppercase">
            Account
          </span>
        </div>
        <AccountNavigation />
        <SignOutButton onLogout={handleLogout} />
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-top-nav flex items-center justify-between border-b border-border bg-background/95 px-4 py-3 backdrop-blur-sm md:hidden">
          <div className="flex items-center gap-3">
            <LogoMark className="w-6 h-6 text-primary" />
            <span className="font-display text-lg text-foreground font-bold tracking-wider uppercase">
              Account
            </span>
          </div>
          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger asChild>
              <button
                type="button"
                aria-label="Open account navigation"
                className="flex h-11 w-11 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              >
                <Menu className="h-5 w-5" />
              </button>
            </SheetTrigger>
            <SheetContent
              side="left"
              className="w-72 max-w-[85vw] gap-0 border-border bg-card p-0 md:hidden"
            >
              <SheetHeader className="border-b border-border p-6 text-left">
                <SheetTitle className="flex items-center gap-3 font-display text-lg font-bold uppercase tracking-wider">
                  <LogoMark className="w-6 h-6 text-primary" />
                  Account
                </SheetTitle>
              </SheetHeader>
              <AccountNavigation onNavigate={() => setMobileOpen(false)} />
              <SignOutButton onLogout={handleLogout} />
            </SheetContent>
          </Sheet>
        </header>

        <main className="min-w-0 p-4 sm:p-6 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
