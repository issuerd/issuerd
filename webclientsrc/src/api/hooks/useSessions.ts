// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient, type UseQueryOptions } from '@tanstack/react-query'
import { listSessions, countSessions, deleteSession } from '@generated'
import { toast } from '../../stores/toastStore'
import type { UserSessionRepresentation } from '@generated'

export interface SessionListOptions {
  first?: number
  max?: number
}

function sessionsKey(realm: string) {
  return ['sessions', realm]
}

export function useSessions(
  realm: string,
  listOptions?: SessionListOptions,
  options?: Omit<UseQueryOptions<UserSessionRepresentation[]>, 'queryKey' | 'queryFn'>
) {
  const { first, max } = listOptions ?? {}
  return useQuery({
    queryKey: [...sessionsKey(realm), 'list', { first, max }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await listSessions({
        path: { realm },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
    ...options,
  })
}

export function useSessionCount(realm: string) {
  return useQuery({
    queryKey: [...sessionsKey(realm), 'count'],
    queryFn: async () => {
      const res = await countSessions({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useDeleteSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, session }: { realm: string; session: string }) => {
      const res = await deleteSession({ path: { realm, session } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, session }) => {
      await qc.cancelQueries({ queryKey: sessionsKey(realm) })
      const previous = qc.getQueryData<UserSessionRepresentation[]>(sessionsKey(realm))
      qc.setQueryData<UserSessionRepresentation[]>(sessionsKey(realm), (old) =>
        old?.filter((s) => s.id !== session)
      )
      return { previous }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData(sessionsKey(vars.realm), context.previous)
      }
      toast({ title: 'Failed to revoke session', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'Session revoked', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: sessionsKey(vars.realm) })
    },
  })
}
