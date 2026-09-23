// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listUsers,
  countUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  resetPassword,
  getUserSessions,
  getUserGroups,
  getUserRealmRoles,
  getAvailableUserRealmRoles,
  addUserGroup,
  removeUserGroup,
  addUserRealmRoles,
  removeUserRealmRoles,
  getUserClientRoles,
  getAvailableUserClientRoles,
  addUserClientRoles,
  removeUserClientRoles,
  type UserRepresentation,
  type CredentialRepresentation,
  type RoleRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

export interface UserListOptions {
  first?: number
  max?: number
  search?: string
}

function usersKey(realm: string) {
  return ['users', realm]
}

export function useUsers(realm: string, options?: UserListOptions) {
  const { first, max, search } = options ?? {}
  return useQuery({
    queryKey: [...usersKey(realm), 'list', { first, max, search }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      if (search) query.search = search
      const res = await listUsers({
        path: { realm },
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useUserCount(realm: string, search?: string) {
  return useQuery({
    queryKey: [...usersKey(realm), 'count', search],
    queryFn: async () => {
      const res = await countUsers({
        path: { realm },
        query: search ? { search } : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
    enabled: !!realm,
  })
}

export function useUser(realm: string, id: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id],
    queryFn: async () => {
      const res = await getUser({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

function sanitizeUserBody(body: UserRepresentation): UserRepresentation {
  return {
    ...body,
    email: body.email?.trim() || null,
    first_name: body.first_name?.trim() || null,
    last_name: body.last_name?.trim() || null,
  }
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: UserRepresentation }) => {
      const res = await createUser({ path: { realm }, body: sanitizeUserBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: usersKey(vars.realm) })
      toast({ title: 'User created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create user', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: UserRepresentation }) => {
      const res = await updateUser({ path: { realm, id }, body: sanitizeUserBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, id, body }) => {
      await qc.cancelQueries({ queryKey: [...usersKey(realm), id] })
      await qc.cancelQueries({ queryKey: usersKey(realm) })
      const previous = qc.getQueryData<UserRepresentation>([...usersKey(realm), id])
      const previousList = qc.getQueryData<UserRepresentation[]>(usersKey(realm))

      qc.setQueryData<UserRepresentation>([...usersKey(realm), id], (old) =>
        old ? { ...old, ...body } : old
      )
      qc.setQueryData<UserRepresentation[]>(usersKey(realm), (old) =>
        old?.map((u) => (u.id === id ? { ...u, ...body } : u))
      )
      return { previous, previousList }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData([...usersKey(vars.realm), vars.id], context.previous)
      }
      if (context?.previousList) {
        qc.setQueryData(usersKey(vars.realm), context.previousList)
      }
      toast({ title: 'Update failed', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'User updated', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: usersKey(vars.realm) })
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id] })
    },
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await deleteUser({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, id }) => {
      await qc.cancelQueries({ queryKey: usersKey(realm) })
      const previous = qc.getQueryData<UserRepresentation[]>(usersKey(realm))
      qc.setQueryData<UserRepresentation[]>(usersKey(realm), (old) => old?.filter((u) => u.id !== id))
      return { previous }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData(usersKey(vars.realm), context.previous)
      }
      toast({ title: 'Failed to delete user', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'User deleted', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: usersKey(vars.realm) })
    },
  })
}

export function useResetPassword() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, body }: { realm: string; id: string; body: CredentialRepresentation }) => {
      const res = await resetPassword({ path: { realm, id }, body })
      if (res.error) {
        // Surface each password-policy violation on its own line so the toast
        // shows exactly which rules failed, not just a generic message.
        const violations = res.error.policyViolations
        const detail = violations?.length
          ? violations.map((v) => `• ${v.message}`).join('\n')
          : res.error.errorMessage
        throw new Error(detail)
      }
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id] })
      toast({ title: 'Password reset', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Password reset failed', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUserSessions(realm: string, id: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'sessions'],
    queryFn: async () => {
      const res = await getUserSessions({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useUserGroups(realm: string, id: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'groups'],
    queryFn: async () => {
      const res = await getUserGroups({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useUserRealmRoles(realm: string, id: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'roles'],
    queryFn: async () => {
      const res = await getUserRealmRoles({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useAvailableUserRealmRoles(realm: string, id: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'roles', 'available'],
    queryFn: async () => {
      const res = await getAvailableUserRealmRoles({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id,
  })
}

export function useUserClientRoles(realm: string, id: string, clientId: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'client-roles', clientId],
    queryFn: async () => {
      const res = await getUserClientRoles({ path: { realm, id, client_id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id && !!clientId,
  })
}

export function useAvailableUserClientRoles(realm: string, id: string, clientId: string) {
  return useQuery({
    queryKey: [...usersKey(realm), id, 'client-roles', clientId, 'available'],
    queryFn: async () => {
      const res = await getAvailableUserClientRoles({ path: { realm, id, client_id: clientId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!id && !!clientId,
  })
}

export function useAddUserGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, groupId }: { realm: string; id: string; groupId: string }) => {
      const res = await addUserGroup({ path: { realm, id, group_id: groupId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'groups'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to add group', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useRemoveUserGroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, groupId }: { realm: string; id: string; groupId: string }) => {
      const res = await removeUserGroup({ path: { realm, id, group_id: groupId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'groups'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove group', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useAddUserRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await addUserRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'roles'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to add roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useRemoveUserRealmRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, roles }: { realm: string; id: string; roles: RoleRepresentation[] }) => {
      const res = await removeUserRealmRoles({ path: { realm, id }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'roles'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useAddUserClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await addUserClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'client-roles'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to add roles', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useRemoveUserClientRoles() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, id, clientId, roles }: { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }) => {
      const res = await removeUserClientRoles({ path: { realm, id, client_id: clientId }, body: roles })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: [...usersKey(vars.realm), vars.id, 'client-roles'] })
    },
    onError: (err) => {
      toast({ title: 'Failed to remove roles', message: (err as Error).message, type: 'error' })
    },
  })
}
