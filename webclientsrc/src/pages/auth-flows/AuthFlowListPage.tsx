// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../state/authStore'
import {
  useFlows,
  useCreateFlow,
  useCopyFlow,
  useDeleteFlow,
} from '../../api/hooks/useAuthFlows'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import Input from '../../components/ui/Input'
import PageHeader from '@/components/layout/PageHeader'
import Badge from '../../components/ui/Badge'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import { GitBranch, Plus, Copy, Trash2 } from 'lucide-react'
import type { FlowRepresentation } from '@generated'

export default function AuthFlowListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: flows, isLoading, error } = useFlows(realm)
  const create = useCreateFlow()
  const copy = useCopyFlow()
  const remove = useDeleteFlow()

  const [createOpen, setCreateOpen] = useState(false)
  const [createAlias, setCreateAlias] = useState('')
  const [createError, setCreateError] = useState('')
  const [copyTarget, setCopyTarget] = useState<FlowRepresentation | null>(null)
  const [copyName, setCopyName] = useState('')
  const [copyError, setCopyError] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<FlowRepresentation | null>(null)

  function openCreate() {
    setCreateAlias('')
    setCreateError('')
    setCreateOpen(true)
  }

  async function handleCreate() {
    setCreateError('')
    try {
      await create.mutateAsync({ realm, body: { alias: createAlias.trim() } })
      setCreateOpen(false)
    } catch (err) {
      setCreateError((err as Error).message)
    }
  }

  function openCopy(flow: FlowRepresentation) {
    setCopyTarget(flow)
    setCopyName(`${flow.alias} copy`)
    setCopyError('')
  }

  async function handleCopy() {
    if (!copyTarget) return
    setCopyError('')
    try {
      await copy.mutateAsync({ realm, alias: copyTarget.alias, body: { newName: copyName.trim() } })
      setCopyTarget(null)
    } catch (err) {
      setCopyError((err as Error).message)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    try {
      await remove.mutateAsync({ realm, alias: deleteTarget.alias })
      setDeleteTarget(null)
    } catch {
      // Server rejects bound/built-in flows — the hook surfaces the message as a toast.
      setDeleteTarget(null)
    }
  }

  const columns = useMemo<ColumnDef<FlowRepresentation>[]>(() => [
    {
      key: 'alias',
      header: 'Alias',
      accessor: (f) => f.alias ?? '',
      cell: (f) => <span className="text-sm font-medium text-white">{f.alias}</span>,
      sortable: true,
    },
    {
      key: 'top_level',
      header: 'Type',
      accessor: (f) => (f.top_level ? 'top level' : 'sub flow'),
      cell: (f) => (
        <Badge variant={f.top_level ? 'success' : 'info'}>{f.top_level ? 'Top Level' : 'Sub Flow'}</Badge>
      ),
      sortable: true,
    },
    {
      key: 'built_in',
      header: 'Built In',
      accessor: (f) => (f.built_in ? 'yes' : 'no'),
      cell: (f) => <Badge variant={f.built_in ? 'success' : 'info'}>{f.built_in ? 'Yes' : 'No'}</Badge>,
      sortable: true,
    },
    {
      key: 'stages',
      header: 'Executions',
      accessor: (f) => f.stages?.length ?? 0,
      cell: (f) => <span className="text-text-secondary">{f.stages?.length ?? 0}</span>,
      sortable: true,
    },
    {
      key: 'actions',
      header: ' ',
      accessor: () => '',
      cell: (f) => (
        <div className="flex items-center justify-end gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation()
              openCopy(f)
            }}
            className="p-1.5 text-text-secondary hover:text-cyan-neon hover:bg-cyan-neon/10 rounded-lg transition-colors"
            aria-label={`Copy flow ${f.alias}`}
          >
            <Copy className="w-4 h-4" />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation()
              setDeleteTarget(f)
            }}
            className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors"
            aria-label={`Delete flow ${f.alias}`}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      ),
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Auth Flows"
        icon={GitBranch}
        actions={
          <button
            onClick={openCreate}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Flow
          </button>
        }
      />

      <DataTable
        data={flows ?? []}
        columns={columns}
        rowId={(f) => f.alias}
        tableKey="flows"
        emptyState={
          <EmptyState icon={GitBranch} title="No auth flows" description="No authentication flows configured." />
        }
        onRowClick={(f) => navigate(`/auth-flows/${encodeURIComponent(f.alias)}`)}
      />

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create Flow">
        <div className="flex flex-col gap-4">
          {createError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {createError}
            </div>
          )}
          <Input
            label="Alias"
            placeholder="my-flow"
            value={createAlias}
            onChange={(e) => setCreateAlias(e.target.value)}
            required
          />
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleCreate}
              disabled={create.isPending || !createAlias.trim()}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {create.isPending ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </Modal>

      <Modal open={!!copyTarget} onClose={() => setCopyTarget(null)} title={`Copy Flow: ${copyTarget?.alias ?? ''}`}>
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
              onClick={() => setCopyTarget(null)}
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

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        description={`Delete flow "${deleteTarget?.alias}"? Flows referenced by realm bindings or other flows cannot be deleted.`}
        loading={remove.isPending}
      />
    </div>
  )
}
