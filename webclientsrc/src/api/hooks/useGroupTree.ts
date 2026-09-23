// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getGroupMembers,
  createChildGroup,
  updateGroup,
  type GroupRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

/**
 * Group hierarchy hooks: sub-group creation, member listing, and
 * moving a group to a new parent. Keyed under the same `['groups', realm]`
 * prefix as `useGroups` so invalidations cascade across the domain.
 */

function groupsKey(realm: string) {
  return ['groups', realm]
}

export interface GroupMembersOptions {
  first?: number
  max?: number
}

export function useGroupMembers(realm: string, id: string, options?: GroupMembersOptions) {
  const { first, max } = options ?? {}
  return useQuery({
    queryKey: [...groupsKey(realm), id, 'members', { first, max }],
    queryFn: async () => {
      const query: Record<string, number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await getGroupMembers({
        path: { realm, id },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useCreateChildGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: GroupRepresentation }) => {
      const res = await createChildGroup({ path: { realm, id }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: groupsKey(vars.realm) })
      toast({ title: 'Sub-group created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create sub-group', message: (err as Error).message, type: 'error' })
    },
  })
}

/**
 * Moves a group by submitting `updateGroup` with the tri-state `parent_id`:
 * `undefined` preserves the current parent, `null` moves to the root, and a
 * group id moves under that parent. Cycle rejections (400) surface as toasts.
 */
export function useMoveGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      realm,
      id,
      body,
    }: {
      realm: string
      id: string
      body: GroupRepresentation
    }) => {
      const res = await updateGroup({ path: { realm, id }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: groupsKey(vars.realm) })
      toast({ title: 'Group moved', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to move group', message: (err as Error).message, type: 'error' })
    },
  })
}
