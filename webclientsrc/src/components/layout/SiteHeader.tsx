// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { Menu, LogOut, Monitor, User, Moon, Sun, Command } from 'lucide-react'
import { useTheme } from 'next-themes'
import { useSidebar } from '@/components/ui/sidebar'
import { Logo, LogoMark } from '@/components/ui/Logo'
import { useAuthStore } from '@/state/authStore'
import { postLogout } from '@/api/client'
import { useLiveSessionCount } from '@/api/hooks/useLiveSessionCount'
import { Button } from '@/components/ui/Button'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { consoleHref } from '@/config'

interface SiteHeaderProps {
  onOpenCommandPalette?: () => void
}

export default function SiteHeader({ onOpenCommandPalette }: SiteHeaderProps) {
  const { toggleSidebar } = useSidebar()
  const { currentRealm, logout } = useAuthStore()
  const { theme, setTheme } = useTheme()
  const accessToken = useAuthStore((s) =>
    currentRealm ? s.getTokenSet(currentRealm)?.accessToken : null
  )
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
    <header className="sticky top-0 z-50 flex h-14 shrink-0 items-center justify-between gap-2 border-b bg-background px-4 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 md:hidden"
          onClick={toggleSidebar}
          aria-label="Toggle navigation menu"
        >
          <Menu className="size-4" />
        </Button>

        <div className="flex items-center gap-2 md:hidden">
          <LogoMark className="size-5" />
          <Logo className="h-4 w-auto" />
        </div>

        <Button
          variant="ghost"
          size="icon"
          className="hidden md:flex h-8 w-8"
          onClick={onOpenCommandPalette}
          aria-label="Open command palette"
        >
          <Command className="size-4" />
          <span className="sr-only">Command palette</span>
        </Button>
      </div>

      <div className="flex items-center gap-2">
        {currentRealm && (
          <a
            href={consoleHref('/sessions')}
            className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-md border bg-background hover:bg-accent transition-colors text-xs"
            title="View sessions"
          >
            <Monitor className="size-3.5" />
            <span className="font-mono">
              {sessionCount} session{sessionCount === 1 ? '' : 's'}
            </span>
            {sessionCount > 0 && (
              <span className="size-1.5 rounded-full bg-primary animate-pulse" />
            )}
          </a>
        )}

        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          aria-label="Toggle theme"
        >
          <Sun className="size-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute size-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full">
              <Avatar className="size-8">
                <AvatarFallback className="text-xs uppercase">
                  {adminUsername ? adminUsername.slice(0, 2) : <User className="size-4" />}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <div className="px-2 py-1.5 text-sm font-medium">
              {adminUsername ?? 'Admin User'}
            </div>
            <div className="px-2 pb-1.5 text-xs text-muted-foreground">
              {currentRealm ?? 'master'}
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <a href={`/realms/${encodeURIComponent(profileRealm)}/account`}>
                <User className="mr-2 size-4" />
                Profile
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={handleLogout}>
              <LogOut className="mr-2 size-4" />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
