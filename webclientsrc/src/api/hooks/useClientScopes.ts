// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listClientScopes,
  getClientScope,
  createClientScope,
  updateClientScope,
  deleteClientScope,
  listScopeMappers,
  createScopeMapper,
  updateScopeMapper,
  deleteScopeMapper,
  type ClientScopeRepresentation,
  type ProtocolMapperRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

function clientScopesKey(realm: string) {
  return ['client-scopes', realm]
}

export function useClientScopes(realm: string) {
  return useQuery({
    queryKey: [...clientScopesKey(realm), 'list'],
    queryFn: async () => {
      const res = await listClientScopes({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useClientScope(realm: string, id: string) {
  return useQuery({
    queryKey: [...clientScopesKey(realm), id],
    queryFn: async () => {
      const res = await getClientScope({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useCreateClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: ClientScopeRepresentation }) => {
      const res = await createClientScope({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientScopesKey(vars.realm) })
      toast({ title: 'Client scope created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create client scope', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: ClientScopeRepresentation }) => {
      const res = await updateClientScope({ path: { realm, id }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientScopesKey(vars.realm) })
      toast({ title: 'Client scope updated', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Update failed', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await deleteClientScope({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientScopesKey(vars.realm) })
      toast({ title: 'Client scope deleted', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete client scope', message: (err as Error).message, type: 'error' })
    },
  })
}

function scopeMappersKey(realm: string, scopeId: string) {
  return [...clientScopesKey(realm), scopeId, 'mappers']
}

export function useScopeMappers(realm: string, scopeId: string) {
  return useQuery({
    queryKey: scopeMappersKey(realm, scopeId),
    queryFn: async () => {
      const res = await listScopeMappers({ path: { realm, id: scopeId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!scopeId,
  })
}

export function useCreateScopeMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, scopeId, body }: { realm: string; scopeId: string; body: ProtocolMapperRepresentation }) => {
      const res = await createScopeMapper({ path: { realm, id: scopeId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappersKey(vars.realm, vars.scopeId) })
      qc.invalidateQueries({ queryKey: [...clientScopesKey(vars.realm), vars.scopeId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to create mapper', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateScopeMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, scopeId, mapperId, body }: { realm: string; scopeId: string; mapperId: string; body: ProtocolMapperRepresentation }) => {
      const res = await updateScopeMapper({ path: { realm, id: scopeId, mapper_id: mapperId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappersKey(vars.realm, vars.scopeId) })
      qc.invalidateQueries({ queryKey: [...clientScopesKey(vars.realm), vars.scopeId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to update mapper', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteScopeMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, scopeId, mapperId }: { realm: string; scopeId: string; mapperId: string }) => {
      const res = await deleteScopeMapper({ path: { realm, id: scopeId, mapper_id: mapperId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappersKey(vars.realm, vars.scopeId) })
      qc.invalidateQueries({ queryKey: [...clientScopesKey(vars.realm), vars.scopeId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete mapper', message: (err as Error).message, type: 'error' })
    },
  })
}
