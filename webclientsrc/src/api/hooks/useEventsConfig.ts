// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getEventsConfig,
  updateEventsConfig,
  clearEvents,
  clearAdminEvents,
  type RealmEventsConfigRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

function eventsConfigKey(realm: string) {
  return ['events-config', realm]
}

/**
 * Per-realm events configuration, served by
 * `GET /admin/realms/{realm}/events/config`.
 */
export function useEventsConfig(realm: string) {
  return useQuery({
    queryKey: eventsConfigKey(realm),
    queryFn: async () => {
      const res = await getEventsConfig({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useUpdateEventsConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      realm,
      body,
    }: {
      realm: string
      body: RealmEventsConfigRepresentation
    }) => {
      const res = await updateEventsConfig({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: eventsConfigKey(vars.realm) })
      toast({ title: 'Events configuration saved', type: 'success' })
    },
    onError: (err) => {
      toast({
        title: 'Failed to save events configuration',
        message: (err as Error).message,
        type: 'error',
      })
    },
  })
}

/** Wipes every login/user event of the realm (`DELETE .../events`). */
export function useClearEvents() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (realm: string) => {
      const res = await clearEvents({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
    onSuccess: (_, realm) => {
      qc.invalidateQueries({ queryKey: ['events', realm] })
      toast({ title: 'Events cleared', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to clear events', message: (err as Error).message, type: 'error' })
    },
  })
}

/** Wipes every admin (audit) event of the realm (`DELETE .../admin-events`). */
export function useClearAdminEvents() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (realm: string) => {
      const res = await clearAdminEvents({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
    onSuccess: (_, realm) => {
      qc.invalidateQueries({ queryKey: ['admin-events', realm] })
      toast({ title: 'Admin events cleared', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to clear admin events', message: (err as Error).message, type: 'error' })
    },
  })
}
