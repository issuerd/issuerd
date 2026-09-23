// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMutation } from '@tanstack/react-query'
import { impersonateUser, executeActionsEmail } from '@generated'
import { toast } from '../../stores/toastStore'

/**
 * One-shot user administration actions: impersonation and the
 * execute-actions email. Neither is cached domain state, so these are plain
 * mutations with no query keys.
 */

export function useImpersonateUser() {
  return useMutation({
    mutationFn: async ({ realm, id }: { realm: string; id: string }) => {
      const res = await impersonateUser({ path: { realm, id } })
      if (res.error) throw new Error(res.error.errorMessage)
      // The response carries session tokens for the impersonated user. They are
      // deliberately dropped here — the admin console must not store or display
      // them; the audit events on the backend are the record of the action.
    },
    onSuccess: () => {
      toast({ title: 'Impersonation session started', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Impersonation failed', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useExecuteActionsEmail() {
  return useMutation({
    mutationFn: async ({
      realm,
      id,
      actions,
      redirectUri,
      lifespan,
    }: {
      realm: string
      id: string
      /** Required-action ids, e.g. `["UPDATE_PASSWORD", "VERIFY_EMAIL"]`. */
      actions: string[]
      redirectUri?: string
      /** Action-token validity in seconds; the backend defaults to 12 h. */
      lifespan?: number
    }) => {
      const res = await executeActionsEmail({
        path: { realm, id },
        body: actions,
        query: {
          ...(redirectUri ? { redirect_uri: redirectUri } : {}),
          ...(lifespan !== undefined ? { lifespan } : {}),
        },
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: () => {
      toast({ title: 'Action email sent', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to send action email', message: (err as Error).message, type: 'error' })
    },
  })
}
