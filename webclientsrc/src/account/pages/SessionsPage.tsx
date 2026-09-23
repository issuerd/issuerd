// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useState } from 'react'
import { Monitor, LogOut, Clock, Globe } from 'lucide-react'
import { accountListSessions, accountLogoutSession } from '@generated'
import type { AccountSession } from '@generated'
import { unwrap } from '../api/errors'
import { getAccountRealm } from '../../config'
import Spinner from '../../components/ui/Spinner'

export default function SessionsPage() {
  const [sessions, setSessions] = useState<AccountSession[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  function loadSessions() {
    setLoading(true)
    accountListSessions({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((data) => {
        setSessions(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }

  useEffect(() => {
    loadSessions()
  }, [])

  async function handleLogout(sessionId: string) {
    try {
      await accountLogoutSession({ path: { realm: getAccountRealm(), id: sessionId } }).then(unwrap)
      loadSessions()
    } catch (err: any) {
      setError(err.message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-card border border-destructive/30 rounded-xl p-6 text-destructive">
        {error}
      </div>
    )
  }

  return (
    <div className="max-w-3xl">
      <h1 className="font-display text-2xl text-foreground font-bold mb-6">Active Sessions</h1>

      {sessions.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-8 text-center">
          <Monitor className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">No active sessions found.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="bg-card border border-border rounded-xl p-5 flex items-center justify-between gap-4"
            >
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Monitor className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground">Session</span>
                    <span className="text-xs text-muted-foreground font-mono">{session.id.slice(0, 8)}...</span>
                  </div>
                  <div className="flex items-center gap-4 mt-1.5">
                    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Globe className="w-3.5 h-3.5" />
                      {session.ip_address}
                    </span>
                    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Clock className="w-3.5 h-3.5" />
                      {new Date(session.started).toLocaleString()}
                    </span>
                  </div>
                  {session.clients.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {session.clients.map((client) => (
                        <span
                          key={client}
                          className="px-2 py-0.5 rounded text-[10px] bg-secondary text-muted-foreground border border-border"
                        >
                          {client}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={() => handleLogout(session.id)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors border border-destructive/20 hover:border-destructive/40 shrink-0"
              >
                <LogOut className="w-4 h-4" />
                Sign Out
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
