// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { useUsers, useUserCount } from './useUsers'
import { useSessions, useSessionCount } from './useSessions'
import { useEvents } from './useEvents'
import { useServerInfo } from './useServerInfo'
import { format, subDays, startOfDay } from 'date-fns'
import type { EventRepresentation } from '@generated'

interface DashboardData {
  activeUsers: number
  totalUsers: number
  totalSessions: number
  failedLogins24h: number
  tokenEvents24h: number
  recentEvents: EventRepresentation[]
  topClients: { client_id: string; count: number }[]
  hourlyTokens: { hour: string; count: number }[]
  health: { name: string; status: 'healthy' | 'warning' | 'error' }[]
}

/** Backend expects RFC-3339 / ISO-8601 timestamps, not date-only strings. */
function toDateParam(d: Date): string {
  return d.toISOString()
}

export function useDashboard(realm: string) {
  const { now, dayAgo, weekAgo } = useMemo(() => {
    const n = new Date()
    return {
      now: n,
      dayAgo: startOfDay(subDays(n, 1)),
      weekAgo: startOfDay(subDays(n, 7)),
    }
  }, [])

  const usersQuery = useUsers(realm, { max: 1000 })
  const usersCountQuery = useUserCount(realm)
  const sessionsQuery = useSessions(realm, { max: 1000 })
  const sessionsCountQuery = useSessionCount(realm)
  const serverInfoQuery = useServerInfo()

  const events7dFilters = useMemo(
    () => ({
      date_from: toDateParam(weekAgo),
      date_to: toDateParam(now),
      first: 0,
      max: 1000,
    }),
    [now, weekAgo]
  )

  const loginErrorFilters = useMemo(
    () => ({
      event_type: 'login_error' as const,
      date_from: toDateParam(dayAgo),
      date_to: toDateParam(now),
      first: 0,
      max: 500,
    }),
    [now, dayAgo]
  )

  // Fetch events for last 7 days to compute trends and aggregates
  const events7d = useEvents(realm, events7dFilters)

  // Fetch last 24h login errors specifically
  const loginErrors = useEvents(realm, loginErrorFilters)

  const isLoading =
    usersQuery.isLoading ||
    usersCountQuery.isLoading ||
    sessionsQuery.isLoading ||
    sessionsCountQuery.isLoading ||
    events7d.isLoading ||
    loginErrors.isLoading ||
    serverInfoQuery.isLoading

  const data: DashboardData | undefined = (() => {
    if (isLoading) return undefined

    const users = usersQuery.data ?? []
    const sessions = sessionsQuery.data ?? []
    const events = events7d.data ?? []
    const errors = loginErrors.data ?? []
    const serverInfo = serverInfoQuery.data

    const activeUsers = users.filter((u) => u.enabled !== false).length
    const totalUsers = usersCountQuery.data ?? users.length
    const totalSessions = sessionsCountQuery.data ?? sessions.length

    const tokenEvents = events.filter((e) => {
      const et = typeof e.event_type === 'string' ? e.event_type : e.event_type?.custom
      return et === 'code_to_token' || et === 'refresh_token' || et === 'login'
    })

    const tokenEvents24h = tokenEvents.filter((e) => e.time * 1000 >= dayAgo.getTime()).length

    // Hourly buckets for last 24h
    const hourlyBuckets = new Map<string, number>()
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 60 * 1000)
      const label = format(d, 'HH:00')
      hourlyBuckets.set(label, 0)
    }
    tokenEvents.forEach((e) => {
      const d = new Date(e.time * 1000)
      if (d < dayAgo) return
      const label = format(d, 'HH:00')
      hourlyBuckets.set(label, (hourlyBuckets.get(label) ?? 0) + 1)
    })
    const hourlyTokens = Array.from(hourlyBuckets.entries()).map(([hour, count]) => ({
      hour,
      count,
    }))

    // Top clients by auth events
    const clientCounts = new Map<string, number>()
    events.forEach((e) => {
      if (!e.client_id) return
      const et = typeof e.event_type === 'string' ? e.event_type : e.event_type?.custom
      if (et === 'login' || et === 'code_to_token') {
        clientCounts.set(e.client_id, (clientCounts.get(e.client_id) ?? 0) + 1)
      }
    })
    const topClients = Array.from(clientCounts.entries())
      .map(([client_id, count]) => ({ client_id, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)

    // Health quadrants
    const health = [
      {
        name: 'Database',
        status: (serverInfo?.protocols.length ?? 0) > 0 ? ('healthy' as const) : ('warning' as const),
      },
      {
        name: 'OIDC',
        status: (serverInfo?.response_types.length ?? 0) > 0 ? ('healthy' as const) : ('warning' as const),
      },
      {
        name: 'Cache',
        status: 'healthy' as const,
      },
      {
        name: 'Federation',
        status: (serverInfo?.provider_ids.length ?? 0) > 0 ? ('healthy' as const) : ('warning' as const),
      },
    ]

    return {
      activeUsers,
      totalUsers,
      totalSessions,
      failedLogins24h: errors.length,
      tokenEvents24h,
      recentEvents: events.slice(0, 10),
      topClients,
      hourlyTokens,
      health,
    }
  })()

  return { data, isLoading }
}
