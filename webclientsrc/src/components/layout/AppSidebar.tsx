// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { NavLink, useLocation, useNavigate } from 'react-router-dom'
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
  ChevronsUpDown,
  Check,
  LogOut,
  User,
} from 'lucide-react'
import { LogoMark } from '@/components/ui/Logo'
import { useAuthStore } from '@/state/authStore'
import { postLogout } from '@/api/client'
import { useRealms } from '@/api/hooks/useRealms'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from '@/components/ui/sidebar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'

const navSections = [
  {
    label: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/events', icon: Activity, label: 'Events & Logs' },
    ],
  },
  {
    label: 'Manage',
    items: [
      { to: '/realms', icon: Globe, label: 'Realms' },
      { to: '/users', icon: Users, label: 'Users' },
      { to: '/clients', icon: AppWindow, label: 'Clients' },
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

function RealmSwitcher() {
  const realm = useAuthStore((s) => s.currentRealm)
  const setRealm = useAuthStore((s) => s.setRealm)
  const { state } = useSidebar()
  const { data: realms } = useRealms()
  const navigate = useNavigate()

  function handleSwitch(next: string) {
    if (next === realm) return
    setRealm(next)
    // Leave deep entity routes behind — the addressed entity usually does not
    // exist in the newly selected realm and the page would 404.
    navigate('/dashboard')
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton
          size="lg"
          className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
        >
          <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
            <LogoMark className="size-4" />
          </div>
          <div className="grid flex-1 text-left text-sm leading-tight">
            <span className="truncate font-semibold">{realm ?? 'Issuerd'}</span>
            <span className="truncate text-xs text-sidebar-foreground/70">Admin Console</span>
          </div>
          {state === 'expanded' && <ChevronsUpDown className="ml-auto size-4" />}
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
        side="right"
        align="start"
        sideOffset={4}
      >
        {realms && realms.length > 0 ? (
          realms.map((r) => (
            <DropdownMenuItem key={r.realm} onClick={() => handleSwitch(r.realm)}>
              <Globe className="size-4" />
              <span className="truncate">{r.realm}</span>
              {r.realm === realm && <Check className="ml-auto size-4" />}
            </DropdownMenuItem>
          ))
        ) : (
          <DropdownMenuItem disabled>No realms</DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function NavItems() {
  const location = useLocation()
  const { setOpenMobile } = useSidebar()

  return (
    <>
      {navSections.map((section) => (
        <SidebarGroup key={section.label}>
          <SidebarGroupLabel>{section.label}</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {section.items.map((item) => {
                const isActive =
                  location.pathname === item.to ||
                  location.pathname.startsWith(`${item.to}/`)
                return (
                  <SidebarMenuItem key={item.to}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive}
                      tooltip={item.label}
                    >
                      <NavLink to={item.to} onClick={() => setOpenMobile(false)}>
                        <item.icon className="size-4" />
                        <span>{item.label}</span>
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </>
  )
}

function UserMenu() {
  const { currentRealm, logout } = useAuthStore()
  const profileRealm = currentRealm || 'master'
  const adminUsername = null

  async function handleLogout() {
    await postLogout()
    logout()
    window.location.href = '/login.html?logged_out=1'
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Avatar className="size-8 rounded-lg">
                <AvatarFallback className="rounded-lg bg-sidebar-primary text-sidebar-primary-foreground text-xs uppercase">
                  {adminUsername ? (adminUsername as string).slice(0, 2) : <User className="size-4" />}
                </AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-semibold">
                  {adminUsername ?? 'Admin User'}
                </span>
                <span className="truncate text-xs text-sidebar-foreground/70">
                  {currentRealm ?? 'master'}
                </span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
            side="right"
            align="end"
            sideOffset={4}
          >
            <DropdownMenuItem asChild>
              <a href={`/realms/${encodeURIComponent(profileRealm)}/account`}>
                <User className="size-4" />
                Profile
              </a>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout}>
              <LogOut className="size-4" />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

export default function AppSidebar() {
  return (
    <Sidebar
      collapsible="icon"
      className="border-r border-sidebar-border"
    >
      <SidebarHeader>
        <RealmSwitcher />
      </SidebarHeader>
      <SidebarContent>
        <NavItems />
      </SidebarContent>
      <SidebarFooter>
        <UserMenu />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
