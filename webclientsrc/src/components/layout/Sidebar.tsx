// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Activity,
  Globe,
  AppWindow,
  Users,
  Shield,
  UsersRound,
  Timer,
  KeyRound,
  GitBranch,
  ShieldCheck,
  Server,
  Layers,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react'
import { useSidebarStore } from '@/stores/sidebarStore'
import { useAuthStore } from '@/state/authStore'

const navSections = [
  {
    label: 'OVERVIEW',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/events', icon: Activity, label: 'Events & Logs' },
    ],
  },
  {
    label: 'MANAGE',
    items: [
      { to: '/realms', icon: Globe, label: 'Realms' },
      { to: '/users', icon: Users, label: 'Users' },
      { to: '/clients', icon: AppWindow, label: 'Clients' },
      { to: '/client-scopes', icon: Layers, label: 'Client Scopes' },
      { to: '/roles', icon: Shield, label: 'Roles' },
      { to: '/groups', icon: UsersRound, label: 'Groups' },
      { to: '/sessions', icon: Timer, label: 'Sessions' },
      { to: '/identity-providers', icon: Globe, label: 'Identity Providers' },
      { to: '/keys', icon: KeyRound, label: 'Keys' },
      { to: '/auth-flows', icon: GitBranch, label: 'Auth Flows' },
      { to: '/security', icon: ShieldCheck, label: 'Security' },
      { to: '/server-info', icon: Server, label: 'Server Info' },
    ],
  },
]

export default function Sidebar() {
  const location = useLocation()
  const { isCollapsed, isMobileOpen, toggleCollapse, closeMobile } = useSidebarStore()
  const realm = useAuthStore((s) => s.currentRealm)

  const sidebarClasses = `
    fixed top-top-nav left-0 h-[calc(100vh-var(--top-nav))] z-sidebar bg-surface-dark border-r border-border-custom overflow-y-auto transition-all duration-300 ease-smooth
    ${isCollapsed ? 'w-sidebar-collapsed' : 'w-sidebar'}
    ${isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
  `

  return (
    <aside className={sidebarClasses} onClick={() => closeMobile()}>
      <div className="p-4 flex flex-col h-full">
        {!isCollapsed && realm && (
          <div className="mb-4 px-4 py-2 rounded-lg bg-white/[0.03] border border-border-custom">
            <div className="text-[10px] uppercase tracking-wider text-text-tertiary">Current Realm</div>
            <div className="text-sm font-medium text-cyan-neon truncate">{realm}</div>
          </div>
        )}

        <nav id="sidebar-nav" className="flex-1" aria-label="Main navigation">
          {navSections.map((section) => (
            <div key={section.label} className="mb-4">
              {!isCollapsed && (
                <div className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-text-tertiary">
                  {section.label}
                </div>
              )}
              {section.items.map((item) => {
                const isActive =
                  location.pathname === item.to || location.pathname.startsWith(`${item.to}/`)
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    onClick={(e) => e.stopPropagation()}
                    className={`flex items-center gap-3 h-10 px-4 rounded-lg transition-all duration-200 group ${
                      isActive
                        ? 'nav-active text-cyan-neon'
                        : 'text-text-secondary hover:text-text-primary hover:bg-white/[0.03]'
                    } ${isCollapsed ? 'justify-center px-0' : ''}`}
                    title={isCollapsed ? item.label : undefined}
                  >
                    <item.icon className="w-[18px] h-[18px] flex-shrink-0" />
                    {!isCollapsed && (
                      <span className="text-sm font-medium">{item.label}</span>
                    )}
                  </NavLink>
                )
              })}
            </div>
          ))}
        </nav>

        <button
          onClick={(e) => {
            e.stopPropagation()
            toggleCollapse()
          }}
          className="hidden lg:flex items-center justify-center h-10 w-full rounded-lg text-text-tertiary hover:text-text-primary hover:bg-white/[0.03] transition-colors mt-auto"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? (
            <PanelLeftOpen className="w-4 h-4" aria-hidden="true" />
          ) : (
            <PanelLeftClose className="w-4 h-4" aria-hidden="true" />
          )}
        </button>
      </div>
    </aside>
  )
}
