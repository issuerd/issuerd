// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listGroups,
  countGroups,
  getGroup,
  createGroup,
  updateGroup,
  deleteGroup,
  getGroupRealmRoles,
  getAvailableGroupRealmRoles,
  addGroupRealmRoles,
  removeGroupRealmRoles,
  getGroupClientRoles,
  getAvailableGroupClientRoles,
  addGroupClientRoles,
  removeGroupClientRoles,
  type GroupRepresentation,
  type RoleRepresentation,
} from '@generated'

export interface GroupListOptions {
  first?: number
  max?: number
}

function groupsKey(realm: string) {
  return ['groups', realm]
}

export function useGroups(realm: string, options?: GroupListOptions) {
  const { first, max } = options ?? {}
  return useQuery({
    queryKey: [...groupsKey(realm), 'list', { first, max }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await listGroups({
        path: { realm },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useGroupCount(realm: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), 'count'],
    queryFn: async () => {
      const res = await countGroups({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useGroup(realm: string, id: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), id],
    queryFn: async () => {
      const res = await getGroup({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useCreateGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: GroupRepresentation }) => {
      const res = await createGroup({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: groupsKey(vars.realm) }),
  })
}

export function useUpdateGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: GroupRepresentation }) => {
      const res = await updateGroup({ path: { realm, id }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: groupsKey(vars.realm) })
      qc.invalidateQueries({ queryKey: [...groupsKey(vars.realm), vars.id] })
    },
  })
}

export function useDeleteGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await deleteGroup({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: groupsKey(vars.realm) }),
  })
}

// ---------------------------------------------------------------------------
// Group role mappings
// ---------------------------------------------------------------------------

export function useGroupRealmRoles(realm: string, id: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), id, 'roles'],
    queryFn: async () => {
      const res = await getGroupRealmRoles({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useAvailableGroupRealmRoles(realm: string, id: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), id, 'roles', 'available'],
    queryFn: async () => {
      const res = await getAvailableGroupRealmRoles({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useGroupClientRoles(realm: string, id: string, clientId: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), id, 'client-roles', clientId],
    queryFn: async () => {
      const res = await getGroupClientRoles({ path: { realm, id, client_id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id && !!clientId,
  })
}

export function useAvailableGroupClientRoles(realm: string, id: string, clientId: string) {
  return useQuery({
    queryKey: [...groupsKey(realm), id, 'client-roles', clientId, 'available'],
    queryFn: async () => {
      const res = await getAvailableGroupClientRoles({ path: { realm, id, client_id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id && !!clientId,
  })
}

export function useAddGroupRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await addGroupRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...groupsKey(vars.realm), vars.id, 'roles'] })
    },
  })
}

export function useRemoveGroupRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await removeGroupRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...groupsKey(vars.realm), vars.id, 'roles'] })
    },
  })
}

export function useAddGroupClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await addGroupClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...groupsKey(vars.realm), vars.id, 'client-roles'] })
    },
  })
}

export function useRemoveGroupClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await removeGroupClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...groupsKey(vars.realm), vars.id, 'client-roles'] })
    },
  })
}
