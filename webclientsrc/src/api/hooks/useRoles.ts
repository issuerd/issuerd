// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listRealmRoles,
  countRealmRoles,
  getRealmRole,
  createRealmRole,
  updateRealmRole,
  deleteRealmRole,
  type RoleRepresentation,
} from '@generated'

export interface RealmRoleListOptions {
  first?: number
  max?: number
}

function rolesKey(realm: string) {
  return ['roles', realm]
}

export function useRealmRoles(realm: string, options?: RealmRoleListOptions) {
  const { first, max } = options ?? {}
  return useQuery({
    queryKey: [...rolesKey(realm), 'list', { first, max }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await listRealmRoles({
        path: { realm },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useRealmRoleCount(realm: string) {
  return useQuery({
    queryKey: [...rolesKey(realm), 'count'],
    queryFn: async () => {
      const res = await countRealmRoles({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useRealmRole(realm: string, name: string) {
  return useQuery({
    queryKey: [...rolesKey(realm), name],
    queryFn: async () => {
      const res = await getRealmRole({ path: { realm, role_name: name } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!name,
  })
}

export function useCreateRealmRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: RoleRepresentation }) => {
      const res = await createRealmRole({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: rolesKey(vars.realm) }),
  })
}

export function useUpdateRealmRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, name, body }: { realm: string; name: string; body: RoleRepresentation }) => {
      const res = await updateRealmRole({ path: { realm, role_name: name }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: rolesKey(vars.realm) })
      qc.invalidateQueries({ queryKey: [...rolesKey(vars.realm), vars.name] })
    },
  })
}

export function useDeleteRealmRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, name }: { realm: string; name: string }) => {
      const res = await deleteRealmRole({ path: { realm, role_name: name } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: rolesKey(vars.realm) }),
  })
}
