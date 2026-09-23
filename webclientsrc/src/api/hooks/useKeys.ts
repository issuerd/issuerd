// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getKeys, rotateKeys, disableKey } from '@generated'
import { toast } from '../../stores/toastStore'

function keysKey(realm: string) {
  return ['keys', realm]
}

export function useKeys(realm: string) {
  return useQuery({
    queryKey: keysKey(realm),
    queryFn: async () => {
      const res = await getKeys({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

/**
 * Key lifecycle actions: rotating generates a fresh active signing
 * key; disabling retires a passive-capable key. The API rejects disabling the
 * last active key with a 400 — surfaced verbatim as a toast.
 *
 * Rotation keeps one active key per algorithm — pass `algorithm`
 * to rotate (or create) the active key of a specific algorithm family;
 * leaving it unset rotates the newest active key's algorithm.
 */
export function useRotateKeys() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, algorithm }: { realm: string; algorithm?: string }) => {
      const res = await rotateKeys({
        path: { realm },
        body: algorithm ? { algorithm } : {},
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: keysKey(vars.realm) })
      toast({ title: 'Keys rotated', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to rotate keys', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDisableKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, kid }: { realm: string; kid: string }) => {
      const res = await disableKey({ path: { realm, kid } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: keysKey(vars.realm) })
      toast({ title: 'Key disabled', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to disable key', message: (err as Error).message, type: 'error' })
    },
  })
}
