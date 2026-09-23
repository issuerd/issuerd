// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Shield, AlertTriangle, Lock, Monitor, KeyRound, RefreshCw } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useUsers } from '../../api/hooks/useUsers'
import { useSessions } from '../../api/hooks/useSessions'
import { useEvents } from '../../api/hooks/useEvents'
import { useClients } from '../../api/hooks/useClients'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useLockedUsers, useClearBruteForceState } from '../../api/hooks/useAttackDetection'
import { subDays, startOfDay } from 'date-fns'
import PageHeader from '@/components/layout/PageHeader'
import StatCard from '@/components/data/StatCard'
import Spinner from '@/components/ui/Spinner'
import PageLoader from '@/components/ui/PageLoader'
import ErrorMessage from '@/components/ui/ErrorMessage'
import EnumBadge from '@/components/ui/EnumBadge'
import Button from '@/components/ui/Button'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'

/** Backend expects RFC-3339 / ISO-8601 timestamps, not date-only strings. */
function toDateParam(d: Date): string {
  return d.toISOString()
}

function RiskScoreCard({ score }: { score: number }) {
  const color =
    score >= 80 ? 'text-matrix-green' : score >= 50 ? 'text-amber' : 'text-alert-red'
  const bg =
    score >= 80 ? 'bg-matrix-green/10 border-matrix-green/20' : score >= 50 ? 'bg-amber/10 border-amber/20' : 'bg-alert-red/10 border-alert-red/20'

  return (
    <div className={`bg-surface-dark border rounded-xl p-6 flex flex-col items-center justify-center gap-3 ${bg}`}>
      <Shield className={`w-8 h-8 ${color}`} />
      <div className={`text-5xl font-bold font-display ${color}`}>{score}</div>
      <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
        Security Score
      </div>
      <div className="text-xs text-text-tertiary text-center max-w-[200px]">
        {score >= 80
          ? 'Your realm is well protected.'
          : score >= 50
          ? 'Some improvements recommended.'
          : 'Critical issues require immediate attention.'}
      </div>
    </div>
  )
}

export default function SecurityDashboard() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { events7dFilters, loginErrorFilters } = useMemo(() => {
    const n = new Date()
    const da = startOfDay(subDays(n, 1))
    const wa = startOfDay(subDays(n, 7))
    return {
      now: n,
      dayAgo: da,
      weekAgo: wa,
      events7dFilters: {
        date_from: toDateParam(wa),
        date_to: toDateParam(n),
        first: 0,
        max: 1000,
      },
      loginErrorFilters: {
        event_type: 'login_error' as const,
        date_from: toDateParam(da),
        date_to: toDateParam(n),
        first: 0,
        max: 500,
      },
    }
  }, [])

  const usersQuery = useUsers(realm)
  const sessionsQuery = useSessions(realm)
  const clientsQuery = useClients(realm)
  const serverInfoQuery = useServerInfo()

  const events7d = useEvents(realm, events7dFilters)

  const loginErrors = useEvents(realm, loginErrorFilters)

  const lockedUsersQuery = useLockedUsers(realm)
  const clearBruteForce = useClearBruteForceState()

  // Unlock resolution: prefer the server-resolved `row.userId`; fall back to
  // username → id via the users list for rows without one (e.g. deleted user).
  const userIdByUsername = useMemo(() => {
    const map = new Map<string, string>()
    for (const u of usersQuery.data ?? []) {
      if (u.username && u.id) map.set(u.username, u.id)
    }
    return map
  }, [usersQuery.data])

  function handleUnlock(userId: string | undefined) {
    if (!userId) return
    clearBruteForce.mutate({ realm, id: userId })
  }

  const isLoading =
    usersQuery.isLoading ||
    sessionsQuery.isLoading ||
    clientsQuery.isLoading ||
    events7d.isLoading ||
    loginErrors.isLoading ||
    serverInfoQuery.isLoading

  const isRefreshing =
    usersQuery.isFetching ||
    sessionsQuery.isFetching ||
    clientsQuery.isFetching ||
    events7d.isFetching ||
    loginErrors.isFetching ||
    serverInfoQuery.isFetching

  function handleRefresh() {
    qc.invalidateQueries({ queryKey: ['users', realm] })
    qc.invalidateQueries({ queryKey: ['sessions', realm] })
    qc.invalidateQueries({ queryKey: ['clients', realm] })
    qc.invalidateQueries({ queryKey: ['events', realm] })
    qc.invalidateQueries({ queryKey: ['serverinfo'] })
    qc.invalidateQueries({ queryKey: ['attack-detection', realm] })
  }

  const data = useMemo(() => {
    if (isLoading) return undefined

    const users = usersQuery.data ?? []
    const sessions = sessionsQuery.data ?? []
    const clients = clientsQuery.data ?? []
    const events = events7d.data ?? []
    const errors = loginErrors.data ?? []

    const usersWithoutEmail = users.filter((u) => !u.email_verified).length

    // Risk score calculation (0-100)
    let score = 100
    const threats: { message: string; severity: 'high' | 'medium' | 'low'; action?: string }[] = []

    if (errors.length > 10) {
      score -= 15
      threats.push({
        message: `${errors.length} failed logins in the last 24h`,
        severity: 'medium',
        action: '/events',
      })
    }

    if (usersWithoutEmail > 0) {
      score -= Math.min(15, usersWithoutEmail)
      threats.push({
        message: `${usersWithoutEmail} users without verified email`,
        severity: 'low',
        action: '/users',
      })
    }

    const publicClients = clients.filter((c) => c.public_client).length
    if (publicClients > 0) {
      score -= Math.min(10, publicClients * 2)
      threats.push({
        message: `${publicClients} public clients (no secret)`,
        severity: 'low',
        action: '/clients',
      })
    }

    if (sessions.length === 0 && users.length > 0) {
      score -= 5
      threats.push({
        message: 'No active sessions — users may be unable to log in',
        severity: 'low',
      })
    }

    // Recent security events
    const securityEvents = events
      .filter((e) => {
        const et = typeof e.event_type === 'string' ? e.event_type : e.event_type?.custom
        return (
          et === 'login_error' ||
          et === 'client_login_error' ||
          et === 'refresh_token_error' ||
          et === 'invalid_signature'
        )
      })
      .slice(0, 10)

    return {
      score: Math.max(0, score),
      threats: threats.sort((a, b) =>
        ({ high: 3, medium: 2, low: 1 }[b.severity] - { high: 3, medium: 2, low: 1 }[a.severity])
      ),
      securityEvents,
      usersWithoutEmail,
      publicClients,
      totalSessions: sessions.length,
      failedLogins24h: errors.length,
    }
  }, [isLoading, usersQuery.data, sessionsQuery.data, clientsQuery.data, events7d.data, loginErrors.data])

  if (isLoading) return <PageLoader />
  if (usersQuery.error) return <ErrorMessage message={usersQuery.error.message} />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Dashboard"
        icon={Shield}
        actions={
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-2 px-4 py-2.5 bg-white/[0.03] border border-border-custom rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        }
      />

      {/* Top row: score + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <RiskScoreCard score={data?.score ?? 100} />
        <StatCard
          title="Failed Logins (24h)"
          value={data?.failedLogins24h ?? 0}
          trend={data?.failedLogins24h && data.failedLogins24h > 10 ? 'down' : 'neutral'}
          icon={AlertTriangle}
        />
        <StatCard
          title="Active Sessions"
          value={data?.totalSessions ?? 0}
          trend="neutral"
          icon={Monitor}
        />
        <StatCard
          title="Public Clients"
          value={data?.publicClients ?? 0}
          trend="neutral"
          icon={KeyRound}
        />
      </div>

      {/* Middle row: threats + recent security events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threats */}
        <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
          <h3 className="font-display text-sm font-medium text-text-secondary mb-4">
            Active Threats
          </h3>
          {data?.threats.length === 0 ? (
            <div className="text-center py-8 text-text-tertiary text-sm">
              <Lock className="w-8 h-8 mx-auto mb-2 text-matrix-green/60" />
              No active threats detected. Great job!
            </div>
          ) : (
            <div className="space-y-3">
              {data?.threats.map((threat, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 bg-white/[0.02] rounded-lg border border-border-custom"
                >
                  <AlertTriangle
                    className={`w-5 h-5 shrink-0 mt-0.5 ${
                      threat.severity === 'high'
                        ? 'text-alert-red'
                        : threat.severity === 'medium'
                        ? 'text-amber'
                        : 'text-text-tertiary'
                    }`}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-text-primary">{threat.message}</p>
                    {threat.action && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="mt-1"
                        onClick={() => navigate(threat.action!)}
                      >
                        Investigate →
                      </Button>
                    )}
                  </div>
                  <span
                    className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded-full ${
                      threat.severity === 'high'
                        ? 'bg-alert-red/10 text-alert-red'
                        : threat.severity === 'medium'
                        ? 'bg-amber/10 text-amber'
                        : 'bg-white/5 text-text-tertiary'
                    }`}
                  >
                    {threat.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent security events */}
        <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
          <h3 className="font-display text-sm font-medium text-text-secondary mb-4">
            Recent Security Events
          </h3>
          {data?.securityEvents.length === 0 ? (
            <div className="text-center py-8 text-text-tertiary text-sm">
              <Shield className="w-8 h-8 mx-auto mb-2 text-matrix-green/60" />
              No security events in the last 7 days.
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-auto">
              {data?.securityEvents.map((event, idx) => {
                const et =
                  typeof event.event_type === 'string'
                    ? event.event_type
                    : event.event_type?.custom ?? 'unknown'
                return (
                  <div
                    key={idx}
                    className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/[0.02] transition-colors"
                  >
                    <div className="w-2 h-2 rounded-full bg-alert-red shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <EnumBadge
                          enumList={serverInfoQuery.data?.event_types}
                          value={et}
                          className="text-[10px]"
                        />
                        <span className="text-xs text-text-tertiary truncate">
                          {event.ip_address} — {event.client_id || 'N/A'}
                        </span>
                      </div>
                      <div className="text-xs text-text-secondary truncate">
                        {event.details && typeof event.details === 'object'
                          ? JSON.stringify(event.details).slice(0, 80)
                          : '—'}
                      </div>
                    </div>
                    <span className="text-[11px] text-text-tertiary shrink-0">
                      {new Date(event.time * 1000).toLocaleDateString()}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Attack detection: brute-force lockouts */}
      <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
        <h3 className="font-display text-sm font-medium text-text-secondary mb-4">
          Attack Detection — Brute Force
        </h3>
        {lockedUsersQuery.isLoading ? (
          <div className="py-4 flex justify-center">
            <Spinner />
          </div>
        ) : lockedUsersQuery.error ? (
          <ErrorMessage message={lockedUsersQuery.error.message} />
        ) : !lockedUsersQuery.data || lockedUsersQuery.data.length === 0 ? (
          <div className="text-center py-8 text-text-tertiary text-sm">
            <Lock className="w-8 h-8 mx-auto mb-2 text-matrix-green/60" />
            No locked-out users or recorded login failures.
          </div>
        ) : (
          <Table>
            <Thead>
              <Tr>
                <Th>Username</Th>
                <Th>IP Address</Th>
                <Th>Failed Logins</Th>
                <Th align="right">Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {lockedUsersQuery.data.map((row) => {
                const userId = row.userId ?? userIdByUsername.get(row.username)
                return (
                  <Tr key={`${row.username}:${row.ip}`}>
                    <Td>{row.username}</Td>
                    <Td className="text-text-secondary">{row.ip}</Td>
                    <Td>{row.numFailures}</Td>
                    <Td align="right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!userId || clearBruteForce.isPending}
                        title={
                          userId
                            ? 'Clear failures and unlock this user'
                            : 'User not found in realm — cannot unlock'
                        }
                        onClick={() => handleUnlock(userId)}
                      >
                        Unlock
                      </Button>
                    </Td>
                  </Tr>
                )
              })}
            </Tbody>
          </Table>
        )}
      </div>

      {/* Bottom: quick actions */}
      <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
        <h3 className="font-display text-sm font-medium text-text-secondary mb-4">
          Quick Security Actions
        </h3>
        <div className="flex flex-wrap gap-3">
          <Button variant="primary" onClick={() => navigate('/events')}>
            View All Events
          </Button>
          <Button variant="ghost" onClick={() => navigate('/sessions')}>
            Manage Sessions
          </Button>
          <Button variant="ghost" onClick={() => navigate('/keys')}>
            Review Keys
          </Button>
          <Button variant="ghost" onClick={() => navigate('/users')}>
            Audit Users
          </Button>
        </div>
      </div>
    </div>
  )
}
