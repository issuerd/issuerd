// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listLockedUsers, clearUserBruteForceState } from '@generated'
import { toast } from '../../stores/toastStore'

function key(realm: string) {
  return ['attack-detection', realm]
}

export function useLockedUsers(realm: string) {
  return useQuery({
    queryKey: [...key(realm), 'brute-force'],
    queryFn: async () => {
      const res = await listLockedUsers({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useClearBruteForceState() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await clearUserBruteForceState({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: key(vars.realm) })
      toast({ title: 'User unlocked', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to unlock user', message: (err as Error).message, type: 'error' })
    },
  })
}
