// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMutation } from '@tanstack/react-query'
import {
  partialImport,
  exportRealm,
  pushRevocation,
  type IfResourceExists,
  type PartialImportRepresentation,
} from '@generated'
import { toast } from '../../stores/toastStore'

/**
 * Realm-level administrative actions: partial import, full realm
 * export, and revocation push. These are one-shot operations rather than
 * cached domain state, so they are plain mutations with no query keys.
 */

export function usePartialImport() {
  return useMutation({
    mutationFn: async ({
      realm,
      body,
      ifResourceExists,
    }: {
      realm: string
      body: PartialImportRepresentation
      ifResourceExists: IfResourceExists
    }) => {
      // The strategy goes in the query string so the UI selection always wins
      // over an `ifResourceExists` field embedded in the pasted document.
      const res = await partialImport({
        path: { realm },
        body,
        query: { ifResourceExists },
      })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onError: (err) => {
      toast({ title: 'Import failed', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useExportRealm() {
  return useMutation({
    mutationFn: async (realm: string) => {
      const res = await exportRealm({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onError: (err) => {
      toast({ title: 'Export failed', message: (err as Error).message, type: 'error' })
    },
  })
}

export function usePushRevocation() {
  return useMutation({
    mutationFn: async (realm: string) => {
      const res = await pushRevocation({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data
    },
    onSuccess: () => {
      toast({ title: 'Revocation pushed', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to push revocation', message: (err as Error).message, type: 'error' })
    },
  })
}
