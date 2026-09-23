// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
  Users,
  Activity,
  ShieldAlert,
  KeyRound,
  Server,
  UserPlus,
  PlusSquare,
  Monitor,
  RefreshCw,
  Settings,
  AppWindow,
  Shield,
  ScrollText,
} from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useDashboard } from '../../api/hooks/useDashboard'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import PageHeader from '@/components/layout/PageHeader'
import StatCard from '@/components/data/StatCard'
import QuickActionTile from '@/components/data/QuickActionTile'
import ActivityFeed from '@/components/data/ActivityFeed'
import { SkeletonCard } from '@/components/ui/Skeleton'
import SetupChecklist from '@/components/data/SetupChecklist'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as ReTooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import { consoleHref } from '@/config'

function StatusPill({ status }: { status: 'healthy' | 'warning' | 'error' }) {
  const styles = {
    healthy: 'bg-em-500/10 text-em-600 border-em-500/20 dark:text-em-400',
    warning: 'bg-amber-500/10 text-amber-600 border-amber-500/20 dark:text-amber-400',
    error: 'bg-red-500/10 text-red-600 border-red-500/20 dark:text-red-400',
  }
  const labels = { healthy: 'Healthy', warning: 'Degraded', error: 'Down' }
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${styles[status]}`}
    >
      {labels[status]}
    </span>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const realm = useAuthStore((s) => s.currentRealm)!
  const { data, isLoading } = useDashboard(realm)
  const { data: serverInfo, isFetching: serverInfoFetching } = useServerInfo()

  const isRefreshing = isLoading || serverInfoFetching

  function handleRefresh() {
    qc.invalidateQueries({ queryKey: ['users', realm] })
    qc.invalidateQueries({ queryKey: ['sessions', realm] })
    qc.invalidateQueries({ queryKey: ['events', realm] })
    qc.invalidateQueries({ queryKey: ['serverinfo'] })
  }

  const checklistItems = [
    {
      id: 'realm',
      label: 'Create your first realm',
      description: 'A realm is an isolated IAM space',
      completed: true,
      icon: Settings,
      action: () => navigate('/realms'),
    },
    {
      id: 'client',
      label: 'Create an OIDC client',
      description: 'Enable OAuth2/OIDC authentication for your app',
      completed: (data?.topClients.length ?? 0) > 0,
      icon: AppWindow,
      action: () => navigate('/clients', { state: { openCreate: true } }),
    },
    {
      id: 'user',
      label: 'Add a user',
      description: 'Create at least one user in the realm',
      completed: (data?.totalUsers ?? 0) > 0,
      icon: Users,
      action: () => navigate('/users', { state: { openCreate: true } }),
    },
    {
      id: 'events',
      label: 'Review event logging',
      description: 'Check that events are being recorded',
      completed: (data?.recentEvents.length ?? 0) > 0,
      icon: ScrollText,
      action: () => navigate('/events'),
    },
    {
      id: 'security',
      label: 'Review security dashboard',
      description: 'Check your realm security score',
      completed: false,
      icon: Shield,
      action: () => navigate('/security'),
    },
  ]

  const sparklineData = useMemo(() => {
    if (!data) return undefined
    return [
      Math.max(0, data.activeUsers - 5),
      data.activeUsers - 2,
      data.activeUsers - 1,
      data.activeUsers,
      data.activeUsers + 1,
      data.activeUsers + 3,
      data.activeUsers,
    ]
  }, [data])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        icon={Activity}
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

      {/* Setup checklist */}
      {!isLoading && data && (
        <SetupChecklist realm={realm} items={checklistItems} />
      )}

      {/* Stat grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {isLoading || !data ? (
          <>
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </>
        ) : (
          <>
            <StatCard
              title="Active Users"
              value={data.activeUsers}
              trend="up"
              trendLabel={`of ${data.totalUsers} total`}
              sparklineData={sparklineData}
              icon={Users}
              href={consoleHref('/users')}
            />
            <StatCard
              title="Total Sessions"
              value={data.totalSessions}
              trend={data.totalSessions > 0 ? 'up' : 'neutral'}
              trendLabel={data.totalSessions > 0 ? 'Online now' : 'No active sessions'}
              icon={Monitor}
              href={consoleHref('/sessions')}
            />
            <StatCard
              title="Failed Logins (24h)"
              value={data.failedLogins24h}
              trend={data.failedLogins24h > 0 ? 'down' : 'neutral'}
              trendLabel={data.failedLogins24h > 0 ? 'Requires attention' : 'All clear'}
              icon={ShieldAlert}
            />
            <StatCard
              title="Tokens Issued (24h)"
              value={data.tokenEvents24h}
              trend="neutral"
              trendLabel="Auth events"
              icon={KeyRound}
            />
          </>
        )}
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Token issuance chart */}
        <div className="lg:col-span-2 bg-surface-dark border border-border-custom rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display text-sm font-medium text-text-secondary">
              Token Issuance Rate (24h)
            </h3>
          </div>
          {isLoading || !data ? (
            <div className="h-64 bg-white/5 rounded animate-pulse" />
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <BarChart data={data.hourlyTokens}>
                  <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis
                    dataKey="hour"
                    stroke="#616161"
                    tick={{ fill: '#616161', fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#616161"
                    tick={{ fill: '#616161', fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <ReTooltip
                    contentStyle={{
                      background: '#15151c',
                      border: '1px solid rgba(255,255,255,0.08)',
                      borderRadius: 8,
                      color: '#e0e0e0',
                    }}
                    cursor={{ fill: 'rgba(0,229,255,0.05)' }}
                  />
                  <Bar dataKey="count" fill="rgba(0,229,255,0.7)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Health grid */}
        <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
          <h3 className="font-display text-sm font-medium text-text-secondary mb-4">Realm Health</h3>
          {isLoading || !data ? (
            <div className="h-48 bg-white/5 rounded animate-pulse" />
          ) : (
            <div className="grid grid-cols-2 gap-3">
              {data.health.map((h) => (
                <div
                  key={h.name}
                  className="flex flex-col items-center justify-center gap-2 p-4 bg-white/[0.02] rounded-lg border border-border-custom"
                >
                  <Server className="w-5 h-5 text-text-tertiary" />
                  <span className="text-xs text-text-secondary">{h.name}</span>
                  <StatusPill status={h.status} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity feed */}
        <div className="lg:col-span-2 bg-surface-dark border border-border-custom rounded-xl p-5">
          <h3 className="font-display text-sm font-medium text-text-secondary mb-4">
            Recent Activity
          </h3>
          {isLoading || !data ? (
            <div className="h-48 bg-white/5 rounded animate-pulse" />
          ) : (
            <ActivityFeed events={data.recentEvents} eventTypes={serverInfo?.event_types} />
          )}
        </div>

        {/* Quick actions */}
        <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
          <h3 className="font-display text-sm font-medium text-text-secondary mb-4">Quick Actions</h3>
          <div className="grid grid-cols-2 gap-3">
            <QuickActionTile
              label="Add User"
              icon={UserPlus}
              onClick={() => navigate('/users', { state: { openCreate: true } })}
            />
            <QuickActionTile
              label="Create Client"
              icon={PlusSquare}
              onClick={() => navigate('/clients', { state: { openCreate: true } })}
            />
            <QuickActionTile
              label="View Sessions"
              icon={Monitor}
              onClick={() => navigate('/sessions')}
            />
            <QuickActionTile label="Rotate Keys" icon={RefreshCw} onClick={() => navigate('/keys')} />
          </div>
        </div>
      </div>
    </div>
  )
}
