// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { GitBranch, Info, Copy } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useFlow,
  useCopyFlow,
  useAddExecution,
  useAddFlowExecution,
  useUpdateExecution,
  useDeleteExecution,
  useExecutionConfig,
  useCreateExecutionConfig,
  useUpdateExecutionConfig,
  useDeleteExecutionConfig,
} from '../../api/hooks/useAuthFlows'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import PageHeader from '@/components/layout/PageHeader'
import Badge from '../../components/ui/Badge'
import Modal from '../../components/ui/Modal'
import Input from '../../components/ui/Input'
import FlowEditorExecutions from '../../components/domain/FlowEditorExecutions'
import FlowEditorConfigDialog from '../../components/domain/FlowEditorConfigDialog'
import type { FlowStageRepresentation, Requirement } from '@generated'

export default function AuthFlowDetailPage() {
  const { alias } = useParams<{ alias: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: flow, isLoading, error } = useFlow(realm, alias ?? '')
  const copy = useCopyFlow()
  const addExecution = useAddExecution()
  const addSubFlow = useAddFlowExecution()
  const updateExecution = useUpdateExecution()
  const deleteExecution = useDeleteExecution()

  const [copyOpen, setCopyOpen] = useState(false)
  const [copyName, setCopyName] = useState('')
  const [copyError, setCopyError] = useState('')

  const builtIn = !!flow?.built_in
  const stages = [...(flow?.stages ?? [])].sort((a, b) => a.priority - b.priority)

  const [configStage, setConfigStage] = useState<FlowStageRepresentation | null>(null)
  // Resolve the fresh stage object on every render: the copy held in state goes
  // stale when the flows list refetches, which is exactly when a config mutation
  // flips has_config and the probe must start (or stop). Stages without a config
  // are never probed — the endpoint answers 404 for those by design.
  const liveConfigStage = stages.find((s) => s.id === configStage?.id) ?? configStage
  const wantsConfig = !!liveConfigStage?.has_config
  const configQuery = useExecutionConfig(realm, liveConfigStage?.id ?? '', wantsConfig)
  const createConfig = useCreateExecutionConfig()
  const updateConfig = useUpdateExecutionConfig()
  const deleteConfig = useDeleteExecutionConfig()

  function openCopy() {
    setCopyName(`${alias} copy`)
    setCopyError('')
    setCopyOpen(true)
  }

  async function handleCopy() {
    if (!alias) return
    setCopyError('')
    try {
      await copy.mutateAsync({ realm, alias, body: { newName: copyName.trim() } })
      setCopyOpen(false)
    } catch (err) {
      setCopyError((err as Error).message)
    }
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!flow) return <ErrorMessage message="Flow not found" />

  return (
    <div>
      <PageHeader
        title={flow.alias}
        icon={GitBranch}
        breadcrumbs={[
          { label: 'Auth Flows', to: '/auth-flows' },
          { label: flow.alias },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <Badge variant={flow.top_level ? 'success' : 'info'}>
              {flow.top_level ? 'Top Level' : 'Sub Flow'}
            </Badge>
            {builtIn && <Badge variant="info">Built In</Badge>}
            <button
              onClick={openCopy}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <Copy className="w-4 h-4" /> Copy
            </button>
          </div>
        }
      />

      {builtIn && (
        <div className="mb-6 rounded-lg border border-cyan-neon/20 bg-cyan-neon/5 px-4 py-3 text-sm text-text-secondary flex items-center gap-3">
          <Info className="w-4 h-4 text-cyan-neon shrink-0" />
          <span>
            This is a built-in flow and cannot be modified. Use <span className="text-cyan-neon">Copy</span> to
            create an editable copy.
          </span>
        </div>
      )}

      <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
        <FlowEditorExecutions
          stages={stages}
          readOnly={builtIn}
          onRequirementChange={async (stage, requirement) => {
            await updateExecution.mutateAsync({
              realm,
              flowAlias: flow.alias,
              body: { id: stage.id, requirement: requirement as Requirement },
            })
          }}
          onAddExecution={async (body) => {
            await addExecution.mutateAsync({ realm, flowAlias: flow.alias, body })
          }}
          onAddSubFlow={async (body) => {
            await addSubFlow.mutateAsync({ realm, flowAlias: flow.alias, body })
          }}
          onDeleteExecution={async (stage) => {
            await deleteExecution.mutateAsync({ realm, executionId: stage.id })
          }}
          onConfigure={(stage) => setConfigStage(stage)}
          saving={
            addExecution.isPending ||
            addSubFlow.isPending ||
            updateExecution.isPending ||
            deleteExecution.isPending
          }
        />
      </div>

      <FlowEditorConfigDialog
        open={!!configStage}
        onClose={() => setConfigStage(null)}
        stage={liveConfigStage}
        config={wantsConfig ? configQuery.data : null}
        configLoading={wantsConfig && (configQuery.isLoading || configQuery.isFetching)}
        readOnly={builtIn}
        onCreate={async (body) => {
          await createConfig.mutateAsync({ realm, executionId: configStage!.id, body })
        }}
        onUpdate={async (body) => {
          await updateConfig.mutateAsync({ realm, executionId: configStage!.id, body })
        }}
        onDelete={async () => {
          await deleteConfig.mutateAsync({ realm, executionId: configStage!.id })
        }}
        saving={createConfig.isPending || updateConfig.isPending || deleteConfig.isPending}
      />

      <Modal open={copyOpen} onClose={() => setCopyOpen(false)} title={`Copy Flow: ${flow.alias}`}>
        <div className="flex flex-col gap-4">
          {copyError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {copyError}
            </div>
          )}
          <Input
            label="New Name"
            placeholder="my-flow-copy"
            value={copyName}
            onChange={(e) => setCopyName(e.target.value)}
            required
          />
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setCopyOpen(false)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleCopy}
              disabled={copy.isPending || !copyName.trim()}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {copy.isPending ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
