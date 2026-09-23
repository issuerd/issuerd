// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { Menu, LogOut, Monitor, User } from 'lucide-react'
import { useSidebarStore } from '@/stores/sidebarStore'
import { Logo, LogoMark } from '@/components/ui/Logo'
import { useAuthStore } from '@/state/authStore'
import { postLogout } from '@/api/client'
import { useLiveSessionCount } from '../../api/hooks/useLiveSessionCount'
import { consoleHref } from '@/config'

export default function TopNav() {
  const { toggleMobile, closeMobile } = useSidebarStore()
  const { currentRealm, logout } = useAuthStore()
  const accessToken = useAuthStore((s) => (currentRealm ? s.getTokenSet(currentRealm)?.accessToken : null))
  const adminUsername = useMemo(() => {
    if (!accessToken) return null
    try {
      const base64Url = accessToken.split('.')[1]
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      )
      const payload = JSON.parse(jsonPayload)
      return payload.preferred_username || payload.sub || null
    } catch {
      return null
    }
  }, [accessToken])
  const profileRealm = currentRealm || 'master'

  const { data: sessions } = useLiveSessionCount(currentRealm ?? '')
  const sessionCount = sessions?.length ?? 0

  async function handleLogout() {
    await postLogout()
    logout()
    window.location.href = '/login.html?logged_out=1'
  }

  return (
    <header className="fixed top-0 left-0 right-0 h-top-nav z-top-nav bg-surface-dark/85 backdrop-blur-xl border-b border-border-custom/50 flex items-center justify-between px-4 lg:px-8">
      <div className="flex items-center gap-3">
        <button
          onClick={() => {
            closeMobile()
            toggleMobile()
          }}
          className="lg:hidden p-2 hover:bg-white/5 rounded-lg transition-colors"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-5 h-5 text-text-secondary" aria-hidden="true" />
        </button>
        <LogoMark className="w-6 h-6 text-white" />
        <Logo className="h-4 w-auto text-white hidden sm:inline" />
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-border-custom">
          <span className="w-2 h-2 rounded-full bg-matrix-green status-pulse" />
          <span className="font-mono text-[11px] uppercase text-text-secondary">ONLINE</span>
        </div>

        {currentRealm && (
          <>
            <a
              href={consoleHref('/sessions')}
              className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-border-custom hover:border-cyan-neon/30 transition-colors"
              title="View sessions"
            >
              <Monitor className="w-3.5 h-3.5 text-cyan-neon" />
              <span className="font-mono text-xs text-text-primary">
                {sessionCount} session{sessionCount === 1 ? '' : 's'}
              </span>
              {sessionCount > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-neon animate-pulse" />
              )}
            </a>

            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-border-custom">
              <span className="font-mono text-xs text-text-primary">{currentRealm}</span>
            </div>
          </>
        )}

        <button
          onClick={handleLogout}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-white/5 transition-colors"
        >
          <LogOut className="w-4 h-4" aria-hidden="true" />
          <span className="hidden sm:inline">Logout</span>
        </button>

        <a
          href={`/realms/${encodeURIComponent(profileRealm)}/account`}
          title={adminUsername ? `Profile — ${adminUsername}` : 'Profile'}
          className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-white/5 transition-colors"
        >
          <div className="w-8 h-8 rounded-full bg-surface-card border border-border-custom flex items-center justify-center">
            {adminUsername ? (
              <span className="font-mono text-xs text-text-primary uppercase">
                {adminUsername.slice(0, 2)}
              </span>
            ) : (
              <User className="w-4 h-4 text-text-secondary" aria-hidden="true" />
            )}
          </div>
          {adminUsername && (
            <span className="hidden md:inline text-sm text-text-primary max-w-[140px] truncate">
              {adminUsername}
            </span>
          )}
        </a>
      </div>
    </header>
  )
}
