// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listFlows,
  getFlow,
  createFlow,
  copyFlow,
  deleteFlow,
  addExecution,
  addFlowExecution,
  updateExecution,
  deleteExecution,
  getExecutionConfig,
  createExecutionConfig,
  updateExecutionConfig,
  deleteExecutionConfig,
  type FlowRepresentation,
  type CopyFlowRequest,
  type AddExecutionRequest,
  type AddFlowExecutionRequest,
  type UpdateExecutionRequest,
  type AuthenticatorConfigRequest,
} from '@generated'
import { toast } from '../../stores/toastStore'

function flowsKey(realm: string) {
  return ['flows', realm]
}

export function useFlows(realm: string) {
  return useQuery({
    queryKey: flowsKey(realm),
    queryFn: async () => {
      const res = await listFlows({ path: { realm } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm,
  })
}

export function useFlow(realm: string, alias: string) {
  return useQuery({
    queryKey: [...flowsKey(realm), alias],
    queryFn: async () => {
      const res = await getFlow({ path: { realm, flow_alias: alias } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    enabled: !!realm && !!alias,
  })
}

export function useCreateFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, body }: { realm: string; body: FlowRepresentation }) => {
      const res = await createFlow({ path: { realm }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Flow created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create flow', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useCopyFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias, body }: { realm: string; alias: string; body: CopyFlowRequest }) => {
      const res = await copyFlow({ path: { realm, flow_alias: alias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Flow copied', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to copy flow', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, alias }: { realm: string; alias: string }) => {
      const res = await deleteFlow({ path: { realm, flow_alias: alias } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Flow deleted', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete flow', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useAddExecution() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, flowAlias, body }: { realm: string; flowAlias: string; body: AddExecutionRequest }) => {
      const res = await addExecution({ path: { realm, flow_alias: flowAlias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Execution added', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to add execution', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useAddFlowExecution() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, flowAlias, body }: { realm: string; flowAlias: string; body: AddFlowExecutionRequest }) => {
      const res = await addFlowExecution({ path: { realm, flow_alias: flowAlias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Sub-flow added', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to add sub-flow', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateExecution() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, flowAlias, body }: { realm: string; flowAlias: string; body: UpdateExecutionRequest }) => {
      const res = await updateExecution({ path: { realm, flow_alias: flowAlias }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Execution updated', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to update execution', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteExecution() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, executionId }: { realm: string; executionId: string }) => {
      const res = await deleteExecution({ path: { realm, execution_id: executionId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Execution deleted', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete execution', message: (err as Error).message, type: 'error' })
    },
  })
}

function executionConfigKey(realm: string, executionId: string) {
  return [...flowsKey(realm), 'execution-config', executionId]
}

/**
 * Fetches an execution's authenticator configuration. A missing configuration
 * (404) resolves to `null` rather than an error — the stage simply has no
 * config attached yet.
 */
export function useExecutionConfig(realm: string, executionId: string, enabled = true) {
  return useQuery({
    queryKey: executionConfigKey(realm, executionId),
    queryFn: async () => {
      const res = await getExecutionConfig({ path: { realm, execution_id: executionId } })
      if (res.error) {
        if (res.response?.status === 404) return null
        throw new Error(res.error.errorMessage)
      }
      return res.data!
    },
    enabled: enabled && !!realm && !!executionId,
  })
}

export function useCreateExecutionConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, executionId, body }: { realm: string; executionId: string; body: AuthenticatorConfigRequest }) => {
      const res = await createExecutionConfig({ path: { realm, execution_id: executionId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Configuration created', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to create configuration', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useUpdateExecutionConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, executionId, body }: { realm: string; executionId: string; body: AuthenticatorConfigRequest }) => {
      const res = await updateExecutionConfig({ path: { realm, execution_id: executionId }, body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Configuration updated', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to update configuration', message: (err as Error).message, type: 'error' })
    },
  })
}

export function useDeleteExecutionConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ realm, executionId }: { realm: string; executionId: string }) => {
      const res = await deleteExecutionConfig({ path: { realm, execution_id: executionId } })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: flowsKey(vars.realm) })
      toast({ title: 'Configuration deleted', type: 'success' })
    },
    onError: (err) => {
      toast({ title: 'Failed to delete configuration', message: (err as Error).message, type: 'error' })
    },
  })
}
