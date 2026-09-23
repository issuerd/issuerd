// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listRealms,
  countRealms,
  createRealm,
  getRealm,
  updateRealm,
  deleteRealm,
  testSmtpConnection,
  type RealmRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

export interface RealmListOptions {
  first?: number
  max?: number
}

const key = 'realms'

export function useRealms(options?: RealmListOptions) {
  const { first, max } = options ?? {}
  return useQuery({
    queryKey: [key, 'list', { first, max }],
    queryFn: async () => {
      const query: Record<string, string | number | undefined> = {}
      if (first !== undefined) query.first = first
      if (max !== undefined) query.max = max
      const res = await listRealms({
        query: Object.keys(query).length > 0 ? query : undefined,
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
  })
}

export function useRealmCount() {
  return useQuery({
    queryKey: [key, 'count'],
    queryFn: async () => {
      const res = await countRealms()
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!.count
    },
  })
}

function sanitizeRealmBody(body: RealmRepresentation): RealmRepresentation {
  return {
    ...body,
    display_name: body.display_name?.trim() || null,
  }
}

export function useCreateRealm() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: RealmRepresentation) => {
      const res = await createRealm({ body: sanitizeRealmBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: [key] }),
  })
}

export function useRealm(name: string) {
  return useQuery({
    queryKey: [key, name],
    queryFn: async () => {
      const res = await getRealm({ path: { realm: name } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
  })
}

export function useUpdateRealm() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: RealmRepresentation }) => {
      const res = await updateRealm({ path: { realm }, body: sanitizeRealmBody(body) })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async ({ realm, body }) => {
      await qc.cancelQueries({ queryKey: [key, realm] })
      await qc.cancelQueries({ queryKey: [key] })
      const previous = qc.getQueryData<RealmRepresentation>([key, realm])
      const previousList = qc.getQueryData<RealmRepresentation[]>([key])

      qc.setQueryData<RealmRepresentation>([key, realm], (old) =>
        old ? { ...old, ...body } : old
      )
      qc.setQueryData<RealmRepresentation[]>([key], (old) =>
        old?.map((r) => (r.realm === realm ? { ...r, ...body } : r))
      )
      return { previous, previousList }
    },
    onError: (err, vars, context) => {
      if (context?.previous) {
        qc.setQueryData([key, vars.realm], context.previous)
      }
      if (context?.previousList) {
        qc.setQueryData([key], context.previousList)
      }
      toast({ title: 'Update failed', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'Realm updated', type: 'success' })
    },
    onSettled: (_, __, vars) => {
      qc.invalidateQueries({ queryKey: [key] })
      qc.invalidateQueries({ queryKey: [key, vars.realm] })
    },
  })
}

export function useTestSmtpConnection() {
  return useMutation({
    mutationFn: async ({ realm, email }: { realm: string; email: string }) => {
      const res = await testSmtpConnection({ path: { realm }, body: { email } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
  })
}

export function useDeleteRealm() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (realm: string) => {
      const res = await deleteRealm({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onMutate: async (realm) => {
      await qc.cancelQueries({ queryKey: [key] })
      const previous = qc.getQueryData<RealmRepresentation[]>([key])
      qc.setQueryData<RealmRepresentation[]>([key], (old) => old?.filter((r) => r.realm !== realm))
      return { previous }
    },
    onError: (err, _vars, context) => {
      if (context?.previous) {
        qc.setQueryData([key], context.previous)
      }
      toast({ title: 'Failed to delete realm', message: (err as Error).message, type: 'error' })
    },
    onSuccess: () => {
      toast({ title: 'Realm deleted', type: 'success' })
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: [key] })
    },
  })
}
