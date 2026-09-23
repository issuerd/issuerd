// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listClients,
  countClients,
  getClient,
  createClient,
  updateClient,
  deleteClient,
  rotateClientSecret,
  getClientSecret,
  getInstallationProvider,
  listClientRoles,
  createClientRole,
  deleteClientRole,
  listClientMappers,
  createClientMapper,
  updateClientMapper,
  deleteClientMapper,
  getDefaultClientScopes,
  assignDefaultClientScope,
  unassignDefaultClientScope,
  getOptionalClientScopes,
  assignOptionalClientScope,
  unassignOptionalClientScope,
  getScopeMappingRealmRoles,
  getAvailableScopeMappingRealmRoles,
  addScopeMappingRealmRoles,
  removeScopeMappingRealmRoles,
  getScopeMappingClientRoles,
  getAvailableScopeMappingClientRoles,
  addScopeMappingClientRoles,
  removeScopeMappingClientRoles,
  type ClientRepresentation,
  type RoleRepresentation,
  type ProtocolMapperRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

export interface ClientListOptions {
  first?: number
  max?: number
}

function clientsKey(realm: string) {
  return ['clients', realm]
}

export function useClients(realm: string, options?: ClientListOptions) {
  const { first, max } = options ?? {}
  return useQuery({
    queryKey: [...clientsKey(realm), 'list', { first, max }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await listClients({
        path: { realm },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useClientCount(realm: string) {
  return useQuery({
    queryKey: [...clientsKey(realm), 'count'],
    queryFn: async () => {
      const res = await countClients({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useClient(realm: string, id: string) {
  return useQuery({
    queryKey: [...clientsKey(realm), id],
    queryFn: async () => {
      const res = await getClient({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

/**
 * Fetch a client's downloadable configuration in the given installation
 * provider format (Keycloak's "Download adapter config"). Pass `enabled` to
 * defer the request until the download dialog is open and a format is known.
 */
export function useClientInstallation(realm: string, id: string, providerId: string, enabled = true) {
  return useQuery({
    queryKey: [...clientsKey(realm), id, 'installation', providerId],
    queryFn: async () => {
      const res = await getInstallationProvider({ path: { realm, id, provider_id: providerId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: enabled && !!realm && !!id && !!providerId,
  })
}

function sanitizeClientBody(body: ClientRepresentation): ClientRepresentation {
  return {
    ...body,
    name: body.name?.trim() || null,
  }
}

export function useCreateClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: ClientRepresentation }) => {
      const res = await createClient({ path: { realm }, body: sanitizeClientBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: clientsKey(vars.realm) }),
  })
}

export function useUpdateClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: ClientRepresentation }) => {
      const res = await updateClient({ path: { realm, id }, body: sanitizeClientBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, id, body }) => {
      await qc.cancelQueries({ queryKey: [...clientsKey(realm), id] })
      await qc.cancelQueries({ queryKey: clientsKey(realm) })
      const previous = qc.getQueryData<ClientRepresentation>([...clientsKey(realm), id])
      const previousList = qc.getQueryData<ClientRepresentation[]>(clientsKey(realm))

      qc.setQueryData<ClientRepresentation>([...clientsKey(realm), id], (old) =>
        old ? { ...old, ...body } : old
      )
      qc.setQueryData<ClientRepresentation[]>(clientsKey(realm), (old) =>
        old?.map((c) => (c.id === id ? { ...c, ...body } : c))
      )
      return { previous, previousList }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData([...clientsKey(vars.realm), vars.id], context.previous)
      }
      if (context?.previousList) {
        qc.setQueryData(clientsKey(vars.realm), context.previousList)
      }
      toast({ title: 'Update failed', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'Client updated', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: clientsKey(vars.realm) })
      qc.invalidateQueries({ queryKey: [...clientsKey(vars.realm), vars.id] })
    },
  })
}

export function useDeleteClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await deleteClient({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, id }) => {
      await qc.cancelQueries({ queryKey: clientsKey(realm) })
      const previous = qc.getQueryData<ClientRepresentation[]>(clientsKey(realm))
      qc.setQueryData<ClientRepresentation[]>(clientsKey(realm), (old) => old?.filter((c) => c.id !== id))
      return { previous }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData(clientsKey(vars.realm), context.previous)
      }
      toast({ title: 'Failed to delete client', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'Client deleted', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: clientsKey(vars.realm) })
    },
  })
}

export function useRotateClientSecret() {
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await rotateClientSecret({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
  })
}

export function useGetClientSecret() {
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await getClientSecret({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
  })
}

// ---------------------------------------------------------------------------
// Client roles
// ---------------------------------------------------------------------------

function clientRolesKey(realm: string, clientId: string) {
  return [...clientsKey(realm), clientId, 'roles']
}

export function useClientRoles(realm: string, clientId: string) {
  return useQuery({
    queryKey: clientRolesKey(realm, clientId),
    queryFn: async () => {
      const res = await listClientRoles({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useCreateClientRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, body }: { realm: string; clientId: string; body: RoleRepresentation }) => {
      const res = await createClientRole({ path: { realm, id: clientId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientRolesKey(vars.realm, vars.clientId) })
      toast({ title: 'Role created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create role', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteClientRole() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, roleName }: { realm: string; clientId: string; roleName: string }) => {
      const res = await deleteClientRole({ path: { realm, id: clientId, role_name: roleName } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientRolesKey(vars.realm, vars.clientId) })
      toast({ title: 'Role deleted', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete role', message: (err as Error).message, type: 'error' })
    },
  })
}

// ---------------------------------------------------------------------------
// Client protocol mappers
// ---------------------------------------------------------------------------

function clientMappersKey(realm: string, clientId: string) {
  return [...clientsKey(realm), clientId, 'mappers']
}

export function useClientMappers(realm: string, clientId: string) {
  return useQuery({
    queryKey: clientMappersKey(realm, clientId),
    queryFn: async () => {
      const res = await listClientMappers({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useCreateClientMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, body }: { realm: string; clientId: string; body: ProtocolMapperRepresentation }) => {
      const res = await createClientMapper({ path: { realm, id: clientId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientMappersKey(vars.realm, vars.clientId) })
      qc.invalidateQueries({ queryKey: [...clientsKey(vars.realm), vars.clientId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to create mapper', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateClientMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, mapperId, body }: { realm: string; clientId: string; mapperId: string; body: ProtocolMapperRepresentation }) => {
      const res = await updateClientMapper({ path: { realm, id: clientId, mapper_id: mapperId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientMappersKey(vars.realm, vars.clientId) })
      qc.invalidateQueries({ queryKey: [...clientsKey(vars.realm), vars.clientId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to update mapper', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteClientMapper() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, mapperId }: { realm: string; clientId: string; mapperId: string }) => {
      const res = await deleteClientMapper({ path: { realm, id: clientId, mapper_id: mapperId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: clientMappersKey(vars.realm, vars.clientId) })
      qc.invalidateQueries({ queryKey: [...clientsKey(vars.realm), vars.clientId] })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete mapper', message: (err as Error).message, type: 'error' })
    },
  })
}

// ---------------------------------------------------------------------------
// Client ↔ client-scope assignments
// ---------------------------------------------------------------------------

function defaultClientScopesKey(realm: string, clientId: string) {
  return [...clientsKey(realm), clientId, 'default-client-scopes']
}

function optionalClientScopesKey(realm: string, clientId: string) {
  return [...clientsKey(realm), clientId, 'optional-client-scopes']
}

export function useDefaultClientScopes(realm: string, clientId: string) {
  return useQuery({
    queryKey: defaultClientScopesKey(realm, clientId),
    queryFn: async () => {
      const res = await getDefaultClientScopes({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useOptionalClientScopes(realm: string, clientId: string) {
  return useQuery({
    queryKey: optionalClientScopesKey(realm, clientId),
    queryFn: async () => {
      const res = await getOptionalClientScopes({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useAssignDefaultClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, scopeId }: { realm: string; clientId: string; scopeId: string }) => {
      const res = await assignDefaultClientScope({ path: { realm, id: clientId, scope_id: scopeId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: defaultClientScopesKey(vars.realm, vars.clientId) })
    },
    onError: (err) => {
      toast({ title: 'Failed to assign scope', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUnassignDefaultClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, scopeId }: { realm: string; clientId: string; scopeId: string }) => {
      const res = await unassignDefaultClientScope({ path: { realm, id: clientId, scope_id: scopeId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: defaultClientScopesKey(vars.realm, vars.clientId) })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove scope', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useAssignOptionalClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, scopeId }: { realm: string; clientId: string; scopeId: string }) => {
      const res = await assignOptionalClientScope({ path: { realm, id: clientId, scope_id: scopeId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: optionalClientScopesKey(vars.realm, vars.clientId) })
    },
    onError: (err) => {
      toast({ title: 'Failed to assign scope', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUnassignOptionalClientScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, clientId, scopeId }: { realm: string; clientId: string; scopeId: string }) => {
      const res = await unassignOptionalClientScope({ path: { realm, id: clientId, scope_id: scopeId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: optionalClientScopesKey(vars.realm, vars.clientId) })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove scope', message: (err as Error).message, type: 'error' })
    },
  })
}

// ---------------------------------------------------------------------------
// Client scope-mappings — token role subset when full_scope_allowed is off
// ---------------------------------------------------------------------------

function scopeMappingsKey(realm: string, clientId: string) {
  return [...clientsKey(realm), clientId, 'scope-mappings']
}

export function useScopeMappingRealmRoles(realm: string, clientId: string) {
  return useQuery({
    queryKey: [...scopeMappingsKey(realm, clientId), 'realm'],
    queryFn: async () => {
      const res = await getScopeMappingRealmRoles({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useAvailableScopeMappingRealmRoles(realm: string, clientId: string) {
  return useQuery({
    queryKey: [...scopeMappingsKey(realm, clientId), 'realm', 'available'],
    queryFn: async () => {
      const res = await getAvailableScopeMappingRealmRoles({ path: { realm, id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId,
  })
}

export function useAddScopeMappingRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await addScopeMappingRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappingsKey(vars.realm, vars.id) })
    },
    onError: (err) => {
      toast({ title: 'Failed to add roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useRemoveScopeMappingRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await removeScopeMappingRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappingsKey(vars.realm, vars.id) })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useScopeMappingClientRoles(realm: string, clientId: string, targetClientId: string) {
  return useQuery({
    queryKey: [...scopeMappingsKey(realm, clientId), 'clients', targetClientId],
    queryFn: async () => {
      const res = await getScopeMappingClientRoles({ path: { realm, id: clientId, client_id: targetClientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId && !!targetClientId,
  })
}

export function useAvailableScopeMappingClientRoles(realm: string, clientId: string, targetClientId: string) {
  return useQuery({
    queryKey: [...scopeMappingsKey(realm, clientId), 'clients', targetClientId, 'available'],
    queryFn: async () => {
      const res = await getAvailableScopeMappingClientRoles({ path: { realm, id: clientId, client_id: targetClientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!clientId && !!targetClientId,
  })
}

export function useAddScopeMappingClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await addScopeMappingClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappingsKey(vars.realm, vars.id) })
    },
    onError: (err) => {
      toast({ title: 'Failed to add roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useRemoveScopeMappingClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await removeScopeMappingClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: scopeMappingsKey(vars.realm, vars.id) })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove roles', message: (err as Error).message, type: 'error' })
    },
  })
}
