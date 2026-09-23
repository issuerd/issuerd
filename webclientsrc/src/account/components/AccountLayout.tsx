// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Outlet, NavLink } from 'react-router-dom'
import { User, LogOut, Monitor, KeyRound, Link2, Globe } from 'lucide-react'
import { LogoMark } from '../../components/ui/Logo'
import { useAuthStore } from '../../state/authStore'
import { postLogout } from '../../api/client'

export default function AccountLayout() {
  const logout = useAuthStore((s) => s.logout)

  async function handleLogout() {
    await postLogout()
    logout()
    window.location.href = '/login.html?logged_out=1'
  }

  const navItemClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-lg transition-colors ${
      isActive
        ? 'bg-accent text-primary'
        : 'text-muted-foreground hover:text-foreground hover:bg-accent'
    }`

  return (
    <div className="min-h-screen bg-background flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <LogoMark className="w-6 h-6 text-primary" />
          <span className="font-display text-lg text-foreground font-bold tracking-wider uppercase">
            Account
          </span>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          <NavLink to="/profile" className={navItemClass}>
            <User className="w-4 h-4" />
            Profile
          </NavLink>
          <NavLink to="/security" className={navItemClass}>
            <KeyRound className="w-4 h-4" />
            Security
          </NavLink>
          <NavLink to="/consents" className={navItemClass}>
            <Link2 className="w-4 h-4" />
            Consents
          </NavLink>
          <NavLink to="/linked-accounts" className={navItemClass}>
            <Globe className="w-4 h-4" />
            Linked Accounts
          </NavLink>
          <NavLink to="/sessions" className={navItemClass}>
            <Monitor className="w-4 h-4" />
            Sessions
          </NavLink>
        </nav>

        <div className="p-4 border-t border-border">
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 px-4 py-3 text-sm font-medium text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors w-full"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
