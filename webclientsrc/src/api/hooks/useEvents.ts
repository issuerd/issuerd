// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery } from '@tanstack/react-query'
import { queryEvents, queryAdminEvents, countEvents, countAdminEvents } from '@generated'

function eventsKey(realm: string) {
  return ['events', realm]
}

function adminEventsKey(realm: string) {
  return ['admin-events', realm]
}

export interface EventFilters {
  event_type?: string
  date_from?: string
  date_to?: string
  first?: number
  max?: number
}

export interface AdminEventFilters {
  operation_type?: string
  resource_type?: string
  date_from?: string
  date_to?: string
  first?: number
  max?: number
}

export function useEvents(realm: string, filters?: EventFilters) {
  return useQuery({
    queryKey: [...eventsKey(realm), filters],
    queryFn: async () => {
      const query: Record<string, string | number> = {}
      if (filters?.event_type) query.event_type = filters.event_type
      if (filters?.date_from) query.date_from = filters.date_from
      if (filters?.date_to) query.date_to = filters.date_to
      if (filters?.first !== undefined) query.first = filters.first
      if (filters?.max !== undefined) query.max = filters.max
      const res = await queryEvents({ path: { realm }, query })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

/** Total number of login events matching the filters (first/max ignored). */
export function useEventCount(realm: string, filters?: EventFilters) {
  return useQuery({
    queryKey: [...eventsKey(realm), 'count', filters],
    queryFn: async () => {
      const query: Record<string, string | number> = {}
      if (filters?.event_type) query.event_type = filters.event_type
      if (filters?.date_from) query.date_from = filters.date_from
      if (filters?.date_to) query.date_to = filters.date_to
      const res = await countEvents({ path: { realm }, query })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useAdminEvents(realm: string, filters?: AdminEventFilters) {
  return useQuery({
    queryKey: [...adminEventsKey(realm), filters],
    queryFn: async () => {
      const query: Record<string, string | number> = {}
      if (filters?.operation_type) query.operation_type = filters.operation_type
      if (filters?.resource_type) query.resource_type = filters.resource_type
      if (filters?.date_from) query.date_from = filters.date_from
      if (filters?.date_to) query.date_to = filters.date_to
      if (filters?.first !== undefined) query.first = filters.first
      if (filters?.max !== undefined) query.max = filters.max
      const res = await queryAdminEvents({ path: { realm }, query })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

/** Total number of admin events matching the filters (first/max ignored). */
export function useAdminEventCount(realm: string, filters?: AdminEventFilters) {
  return useQuery({
    queryKey: [...adminEventsKey(realm), 'count', filters],
    queryFn: async () => {
      const query: Record<string, string | number> = {}
      if (filters?.operation_type) query.operation_type = filters.operation_type
      if (filters?.resource_type) query.resource_type = filters.resource_type
      if (filters?.date_from) query.date_from = filters.date_from
      if (filters?.date_to) query.date_to = filters.date_to
      const res = await countAdminEvents({ path: { realm }, query })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}
