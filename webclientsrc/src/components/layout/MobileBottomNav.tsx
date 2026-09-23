// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  AppWindow,
  Activity,
  MoreHorizontal,
  Globe,
  Shield,
  UsersRound,
  Timer,
  KeyRound,
  GitBranch,
  ShieldCheck,
  Server,
  X,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

const primaryItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/users', icon: Users, label: 'Users' },
  { to: '/clients', icon: AppWindow, label: 'Clients' },
  { to: '/events', icon: Activity, label: 'Events' },
]

const moreItems = [
  { to: '/realms', icon: Globe, label: 'Realms' },
  { to: '/roles', icon: Shield, label: 'Roles' },
  { to: '/groups', icon: UsersRound, label: 'Groups' },
  { to: '/sessions', icon: Timer, label: 'Sessions' },
  { to: '/identity-providers', icon: Globe, label: 'IdPs' },
  { to: '/keys', icon: KeyRound, label: 'Keys' },
  { to: '/auth-flows', icon: GitBranch, label: 'Auth Flows' },
  { to: '/security', icon: ShieldCheck, label: 'Security' },
  { to: '/server-info', icon: Server, label: 'Server Info' },
]

export default function MobileBottomNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const [moreOpen, setMoreOpen] = useState(false)

  const activePath = location.pathname

  return (
    <>
      {/* Bottom tab bar */}
      <nav className="fixed bottom-0 left-0 right-0 z-[60] bg-background/95 backdrop-blur-sm border-t border-border md:hidden safe-area-pb" aria-label="Mobile navigation">
        <div className="flex items-center justify-around h-16">
          {primaryItems.map((item) => {
            const isActive = activePath === item.to || activePath.startsWith(`${item.to}/`)
            return (
              <button
                key={item.to}
                onClick={() => navigate(item.to)}
                className={`flex flex-col items-center justify-center gap-0.5 flex-1 h-full transition-colors ${
                  isActive ? 'text-primary' : 'text-muted-foreground'
                }`}
              >
                <item.icon className="w-5 h-5" aria-hidden="true" />
                <span className="text-[10px] font-medium">{item.label}</span>
                {isActive && (
                  <span className="absolute bottom-1 w-1 h-1 rounded-full bg-primary" />
                )}
              </button>
            )
          })}
          <button
            onClick={() => setMoreOpen(true)}
            className={`flex flex-col items-center justify-center gap-0.5 flex-1 h-full transition-colors ${
              moreOpen ? 'text-primary' : 'text-muted-foreground'
            }`}
          >
            <MoreHorizontal className="w-5 h-5" aria-hidden="true" />
            <span className="text-[10px] font-medium">More</span>
          </button>
        </div>
      </nav>

      {/* More drawer */}
      <AnimatePresence>
        {moreOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[70] bg-black/60 md:hidden"
              onClick={() => setMoreOpen(false)}
            />
            <motion.div
              initial={{ y: '100%' }}
              animate={{ y: 0 }}
              exit={{ y: '100%' }}
              transition={{ type: 'tween', duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              className="fixed bottom-0 left-0 right-0 z-[80] bg-background border-t border-border rounded-t-2xl md:hidden max-h-[70vh] overflow-auto"
            >
              <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                <h3 className="font-display text-sm font-medium text-foreground">More</h3>
                <button
                  onClick={() => setMoreOpen(false)}
                  className="p-1.5 hover:bg-accent rounded-lg transition-colors text-muted-foreground"
                  aria-label="Close menu"
                >
                  <X className="w-5 h-5" aria-hidden="true" />
                </button>
              </div>
              <div className="grid grid-cols-3 gap-2 p-4">
                {moreItems.map((item) => {
                  const isActive = activePath === item.to || activePath.startsWith(`${item.to}/`)
                  return (
                    <button
                      key={item.to}
                      onClick={() => {
                        navigate(item.to)
                        setMoreOpen(false)
                      }}
                      className={`flex flex-col items-center gap-2 p-3 rounded-xl border transition-all ${
                        isActive
                          ? 'bg-primary/10 border-primary/20 text-primary'
                          : 'bg-muted/30 border-border text-muted-foreground hover:bg-muted/50'
                      }`}
                    >
                      <item.icon className="w-5 h-5" aria-hidden="true" />
                      <span className="text-[11px] font-medium">{item.label}</span>
                    </button>
                  )
                })}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
