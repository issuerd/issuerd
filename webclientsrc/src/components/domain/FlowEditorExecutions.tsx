// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Plus, Trash2, Settings, GitBranch } from 'lucide-react'
import type {
  AddExecutionRequest,
  AddFlowExecutionRequest,
  FlowStageRepresentation,
} from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormContextLine from '../ui/FormContextLine'
import Modal from '../ui/Modal'
import EnumBadge from '../ui/EnumBadge'
import Badge from '../ui/Badge'
import DeleteConfirmModal from './DeleteConfirmModal'
import { Table, Thead, Tbody, Tr, Th, Td } from '../ui/Table'

export interface FlowEditorExecutionsProps {
  stages: FlowStageRepresentation[]
  /** Built-in flows reject all mutations server-side — controls render disabled. */
  readOnly?: boolean
  onRequirementChange: (stage: FlowStageRepresentation, requirement: string) => Promise<unknown>
  onAddExecution: (body: AddExecutionRequest) => Promise<unknown>
  onAddSubFlow: (body: AddFlowExecutionRequest) => Promise<unknown>
  onDeleteExecution: (stage: FlowStageRepresentation) => Promise<unknown>
  onConfigure: (stage: FlowStageRepresentation) => void
  saving?: boolean
}

/**
 * Execution tree/table for a single authentication flow: requirement editing,
 * execution/sub-flow creation, deletion, and entry points into the per-stage
 * authenticator-config dialog. The parent wires the domain hooks.
 */
export default function FlowEditorExecutions({
  stages,
  readOnly = false,
  onRequirementChange,
  onAddExecution,
  onAddSubFlow,
  onDeleteExecution,
  onConfigure,
  saving = false,
}: FlowEditorExecutionsProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const [addExecOpen, setAddExecOpen] = useState(false)
  const [execProvider, setExecProvider] = useState('')
  const [execRequirement, setExecRequirement] = useState('')
  const [execError, setExecError] = useState('')

  const [addFlowOpen, setAddFlowOpen] = useState(false)
  const [flowAlias, setFlowAlias] = useState('')
  const [flowRequirement, setFlowRequirement] = useState('')
  const [flowError, setFlowError] = useState('')

  const [deleteTarget, setDeleteTarget] = useState<FlowStageRepresentation | null>(null)

  const requirementOptions =
    serverInfo?.requirements.map((r) => ({
      value: r.id,
      label: r.name ?? r.id,
      description: r.description,
    })) ?? []

  const providerOptions =
    serverInfo?.authenticators.map((p) => ({
      value: p.id,
      label: p.name ?? p.id,
      description: p.description,
    })) ?? []

  function openAddExecution() {
    setExecProvider('')
    setExecRequirement('')
    setExecError('')
    setAddExecOpen(true)
  }

  function openAddSubFlow() {
    setFlowAlias('')
    setFlowRequirement('')
    setFlowError('')
    setAddFlowOpen(true)
  }

  async function handleAddExecution() {
    setExecError('')
    try {
      await onAddExecution({
        provider: execProvider,
        ...(execRequirement ? { requirement: execRequirement as AddExecutionRequest['requirement'] } : {}),
      })
      setAddExecOpen(false)
    } catch (err) {
      setExecError((err as Error).message)
    }
  }

  async function handleAddSubFlow() {
    setFlowError('')
    try {
      await onAddSubFlow({
        alias: flowAlias.trim(),
        ...(flowRequirement ? { requirement: flowRequirement as AddFlowExecutionRequest['requirement'] } : {}),
      })
      setAddFlowOpen(false)
    } catch (err) {
      setFlowError((err as Error).message)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await onDeleteExecution(deleteTarget)
    } finally {
      setDeleteTarget(null)
    }
  }

  const selectedProvider = serverInfo?.authenticators.find((p) => p.id === execProvider)

  return (
    <div>
      {!readOnly && (
        <div className="flex items-center justify-end gap-3 mb-4">
          <button
            onClick={openAddExecution}
            className="px-4 py-2 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Add Execution
          </button>
          <button
            onClick={openAddSubFlow}
            className="px-4 py-2 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Add Sub-Flow
          </button>
        </div>
      )}

      {stages.length === 0 ? (
        <p className="text-sm text-text-tertiary py-4 text-center">No executions in this flow.</p>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Authenticator</Th>
              <Th>Requirement</Th>
              <Th>Priority</Th>
              <Th>Config</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {stages.map((stage) => (
              <Tr key={stage.id}>
                <Td>
                  <div className="flex items-center gap-2">
                    <EnumBadge enumList={serverInfo?.authenticators} value={stage.authenticator} />
                    {stage.sub_flow_alias && (
                      <span
                        className="inline-flex items-center gap-1 text-[11px] text-text-tertiary"
                        title={`Sub-flow: ${stage.sub_flow_alias}`}
                      >
                        <GitBranch className="w-3 h-3" />
                        {stage.sub_flow_alias}
                      </span>
                    )}
                  </div>
                </Td>
                <Td>
                  <select
                    value={stage.requirement}
                    onChange={(e) => {
                      // Errors surface via the mutation hook's toast.
                      void onRequirementChange(stage, e.target.value).catch(() => {})
                    }}
                    disabled={readOnly || saving || infoLoading}
                    aria-label={`Requirement for ${stage.authenticator}`}
                    className="h-9 px-2 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {requirementOptions.map((opt) => (
                      <option key={opt.value} value={opt.value} title={opt.description ?? undefined}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </Td>
                <Td className="text-text-secondary">{stage.priority}</Td>
                <Td>
                  {stage.authenticator_config ? (
                    <Badge variant="success">Configured</Badge>
                  ) : (
                    <span className="text-xs text-text-tertiary">—</span>
                  )}
                </Td>
                <Td align="right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => onConfigure(stage)}
                      className="p-1.5 text-text-secondary hover:text-cyan-neon hover:bg-cyan-neon/10 rounded-lg transition-colors"
                      aria-label={`Configure ${stage.authenticator}`}
                    >
                      <Settings className="w-4 h-4" />
                    </button>
                    {!readOnly && (
                      <button
                        onClick={() => setDeleteTarget(stage)}
                        className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors"
                        aria-label={`Delete execution ${stage.authenticator}`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}

      <Modal open={addExecOpen} onClose={() => setAddExecOpen(false)} title="Add Execution">
        <div className="flex flex-col gap-4">
          {execError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {execError}
            </div>
          )}

          <FormSelect
            label="Provider"
            options={providerOptions}
            value={execProvider}
            onChange={setExecProvider}
            placeholder={infoLoading ? 'Loading...' : 'Select authenticator provider'}
          />
          {execProvider && <FormContextLine text={selectedProvider?.description} />}

          <FormSelect
            label="Requirement"
            options={requirementOptions}
            value={execRequirement}
            onChange={setExecRequirement}
            placeholder={infoLoading ? 'Loading...' : 'Select requirement'}
          />

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setAddExecOpen(false)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleAddExecution}
              disabled={saving || !execProvider}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </Modal>

      <Modal open={addFlowOpen} onClose={() => setAddFlowOpen(false)} title="Add Sub-Flow">
        <div className="flex flex-col gap-4">
          {flowError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {flowError}
            </div>
          )}

          <Input
            label="Alias"
            placeholder="my-sub-flow"
            value={flowAlias}
            onChange={(e) => setFlowAlias(e.target.value)}
            required
          />

          <FormSelect
            label="Requirement"
            options={requirementOptions}
            value={flowRequirement}
            onChange={setFlowRequirement}
            placeholder={infoLoading ? 'Loading...' : 'Select requirement'}
          />

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setAddFlowOpen(false)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleAddSubFlow}
              disabled={saving || !flowAlias.trim()}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </Modal>

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete Execution"
        description={`Remove "${deleteTarget?.authenticator}" from this flow?`}
        loading={saving}
      />
    </div>
  )
}
