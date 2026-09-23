// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  SidebarProvider,
  SidebarInset,
} from '@/components/ui/sidebar'
import AppSidebar from './AppSidebar'
import SiteHeader from './SiteHeader'
import MobileBottomNav from './MobileBottomNav'
import SkipLinks from './SkipLinks'
import ToastContainer from '@/components/interactive/ToastContainer'
import CommandPalette from '@/components/interactive/CommandPalette'
import ShortcutsHelpModal from '@/components/interactive/ShortcutsHelpModal'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'

function trackPage(path: string) {
  if (typeof window === 'undefined') return
  try {
    const existing = JSON.parse(localStorage.getItem('issuerd-recent-pages') ?? '[]') as string[]
    const next = [path, ...existing.filter((p) => p !== path)].slice(0, 5)
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(next))
  } catch {
    // ignore
  }
}

export default function AppLayout() {
  const location = useLocation()
  const navigate = useNavigate()
  const [cmdkOpen, setCmdkOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  useEffect(() => {
    trackPage(location.pathname)
  }, [location.pathname])

  useEffect(() => {
    function onShowShortcuts() {
      setShortcutsOpen(true)
    }
    window.addEventListener('issuerd:show-shortcuts', onShowShortcuts)
    return () => window.removeEventListener('issuerd:show-shortcuts', onShowShortcuts)
  }, [])

  useKeyboardShortcuts([
    { sequence: ['⌘+K'], handler: () => setCmdkOpen(true) },
    { sequence: ['Ctrl+K'], handler: () => setCmdkOpen(true) },
    { sequence: ['⌘+U'], handler: () => navigate('/users') },
    { sequence: ['Ctrl+U'], handler: () => navigate('/users') },
    { sequence: ['⌘+C'], handler: () => navigate('/clients') },
    { sequence: ['Ctrl+C'], handler: () => navigate('/clients') },
    { sequence: ['⌘+E'], handler: () => navigate('/events') },
    { sequence: ['Ctrl+E'], handler: () => navigate('/events') },
    { sequence: ['G', 'D'], handler: () => navigate('/dashboard') },
    { sequence: ['G', 'S'], handler: () => navigate('/sessions') },
    { sequence: ['N', 'U'], handler: () => navigate('/users', { state: { openCreate: true } }) },
    { sequence: ['N', 'C'], handler: () => navigate('/clients', { state: { openCreate: true } }) },
    { sequence: ['?'], handler: () => setShortcutsOpen(true) },
  ])

  return (
    <SidebarProvider defaultOpen>
      <AppSidebar />
      <SidebarInset>
        <SiteHeader onOpenCommandPalette={() => setCmdkOpen(true)} />
        <SkipLinks />
        <main
          id="main-content"
          className="flex-1 p-4 lg:p-8 pb-24 md:pb-8 max-w-[1400px] mx-auto w-full"
        >
          <Outlet />
        </main>
        <MobileBottomNav />
        <ToastContainer />
        <CommandPalette open={cmdkOpen} onClose={() => setCmdkOpen(false)} />
        <ShortcutsHelpModal open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
      </SidebarInset>
    </SidebarProvider>
  )
}
