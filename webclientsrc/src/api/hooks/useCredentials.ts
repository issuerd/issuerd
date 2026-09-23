// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listUserCredentials,
  updateCredentialLabel,
  deleteCredential,
  moveCredentialAfter,
} from '@generated'
import { toast } from '../../stores/toastStore'

/**
 * User credential management: list, relabel, delete, and reorder
 * credentials. Secret data is never returned by the API — these hooks only
 * shuttle metadata.
 */

function credentialsKey(realm: string, userId: string) {
  return ['users', realm, userId, 'credentials']
}

export function useUserCredentials(realm: string, userId: string) {
  return useQuery({
    queryKey: credentialsKey(realm, userId),
    queryFn: async () => {
      const res = await listUserCredentials({ path: { realm, id: userId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!userId,
  })
}

export function useUpdateCredentialLabel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      realm,
      id,
      credentialId,
      label,
    }: {
      realm: string
      id: string
      credentialId: string
      /** `null` clears the label. */
      label: string | null
    }) => {
      const res = await updateCredentialLabel({
        path: { realm, id, credential_id: credentialId },
        body: { userLabel: label },
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: credentialsKey(vars.realm, vars.id) })
      toast({ title: 'Credential label updated', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to update label', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      realm,
      id,
      credentialId,
    }: {
      realm: string
      id: string
      credentialId: string
    }) => {
      const res = await deleteCredential({ path: { realm, id, credential_id: credentialId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: credentialsKey(vars.realm, vars.id) })
      toast({ title: 'Credential deleted', type: 'success' })
    },
    // The API rejects deleting the user's last credential with a 400 — the
    // message is surfaced verbatim so the admin sees the guard reason.
    onError: (err) => {
      toast({ title: 'Failed to delete credential', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useMoveCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({
      realm,
      id,
      credentialId,
      newPreviousCredentialId,
    }: {
      realm: string
      id: string
      credentialId: string
      newPreviousCredentialId: string
    }) => {
      const res = await moveCredentialAfter({
        path: {
          realm,
          id,
          credential_id: credentialId,
          new_previous_credential_id: newPreviousCredentialId,
        },
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: credentialsKey(vars.realm, vars.id) })
    },
    onError: (err) => {
      toast({ title: 'Failed to reorder credentials', message: (err as Error).message, type: 'error' })
    },
  })
}
