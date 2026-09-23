// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listIdps,
  getIdp,
  createIdp,
  updateIdp,
  deleteIdp,
  syncUsers,
  listIdpMappers,
  createIdpMapper,
  updateIdpMapper,
  deleteIdpMapper,
  testIdpConnection,
  type IdentityProviderRepresentation,
  type IdpMapper,
  type IdpTestConnectionResponse,
} from '@generated'

function idpsKey(realm: string) {
  return ['idps', realm]
}

export function useIdps(realm: string) {
  return useQuery({
    queryKey: idpsKey(realm),
    queryFn: async () => {
      const res = await listIdps({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useIdp(realm: string, alias: string) {
  return useQuery({
    queryKey: [...idpsKey(realm), alias],
    queryFn: async () => {
      const res = await getIdp({ path: { realm, alias } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!alias,
  })
}

export function useCreateIdp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: IdentityProviderRepresentation }) => {
      const res = await createIdp({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: idpsKey(vars.realm) }),
  })
}

export function useUpdateIdp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, body }: { realm: string; alias: string; body: IdentityProviderRepresentation }) => {
      const res = await updateIdp({ path: { realm, alias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: idpsKey(vars.realm) })
      qc.invalidateQueries({ queryKey: [...idpsKey(vars.realm), vars.alias] })
    },
  })
}

export function useDeleteIdp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias }: { realm: string; alias: string }) => {
      const res = await deleteIdp({ path: { realm, alias } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: idpsKey(vars.realm) }),
  })
}

export function useSyncUsers() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, strategy }: { realm: string; alias: string; strategy?: string }) => {
      const res = await syncUsers({ path: { realm, provider_id: alias }, query: strategy ? { strategy } : undefined })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['users', vars.realm] })
      qc.invalidateQueries({ queryKey: ['groups', vars.realm] })
    },
  })
}

function mappersKey(realm: string, alias: string) {
  return [...idpsKey(realm), alias, 'mappers']
}

export function useIdpMappers(realm: string, alias: string) {
  return useQuery({
    queryKey: mappersKey(realm, alias),
    queryFn: async () => {
      const res = await listIdpMappers({ path: { realm, alias } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!alias,
  })
}

export function useCreateIdpMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, body }: { realm: string; alias: string; body: IdpMapper }) => {
      const res = await createIdpMapper({ path: { realm, alias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: mappersKey(vars.realm, vars.alias) }),
  })
}

export function useUpdateIdpMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, name, body }: { realm: string; alias: string; name: string; body: IdpMapper }) => {
      const res = await updateIdpMapper({ path: { realm, alias, name }, body })
      if (res.error) throw new Error(res.error.errorMessage)
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: mappersKey(vars.realm, vars.alias) }),
  })
}

export function useDeleteIdpMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, name }: { realm: string; alias: string; name: string }) => {
      const res = await deleteIdpMapper({ path: { realm, alias, name } })
      if (res.error) throw new Error(res.error.errorMessage)
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: mappersKey(vars.realm, vars.alias) }),
  })
}

/**
 * POST test-connection. A 400 response is not thrown — it carries the same
 * {@link IdpTestConnectionResponse} shape with the list of problems, and is
 * returned so the caller can render them.
 */
export function useTestIdpConnection() {
  return useMutation({
    mutationFn: async ({ realm, alias }: { realm: string; alias: string }) => {
      const res = await testIdpConnection({ path: { realm, alias } })
      if (res.error) {
        const err = res.error as Partial<IdpTestConnectionResponse> & { errorMessage?: string }
        if (res.response?.status === 400 && Array.isArray(err.problems)) {
          return { status: err.status ?? 'error', problems: err.problems }
        }
        throw new Error(err.errorMessage ?? `Connection test failed (${res.response?.status ?? 'no response'})`)
      }
      return res.data!
    },
  })
}
