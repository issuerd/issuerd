// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useIdps, useCreateIdp, useDeleteIdp } from '../../api/hooks/useIdentityProviders'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import IdPForm from '../../components/domain/IdPForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import StatusBadge from '@/components/data/StatusBadge'
import EnumBadge from '../../components/ui/EnumBadge'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import type { IdentityProviderRepresentation, ProviderId } from '@generated'

function providerIdToString(pid: ProviderId | null | undefined): string {
  if (!pid) return ''
  if (typeof pid === 'string') return pid
  return pid.Custom
}

export default function IdPListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const { data: idps, isLoading, error } = useIdps(realm)
  const create = useCreateIdp()
  const remove = useDeleteIdp()
  const { data: serverInfo } = useServerInfo()

  async function handleCreate(data: IdentityProviderRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await remove.mutateAsync({ realm, alias: deleteTarget })
    setDeleteTarget(null)
  }

  const columns = useMemo<ColumnDef<IdentityProviderRepresentation>[]>(() => [
    {
      key: 'alias',
      header: 'Alias',
      accessor: (i) => i.alias ?? '',
      cell: (i) => <span className="text-sm font-medium text-white">{i.alias}</span>,
      sortable: true,
    },
    {
      key: 'display_name',
      header: 'Display Name',
      accessor: (i) => i.display_name ?? '',
      cell: (i) => <span className="text-text-secondary">{i.display_name || '—'}</span>,
      sortable: true,
    },
    {
      key: 'provider_id',
      header: 'Provider',
      accessor: (i) => providerIdToString(i.provider_id),
      cell: (i) => (
        <EnumBadge
          enumList={serverInfo?.provider_ids}
          value={providerIdToString(i.provider_id)}
        />
      ),
      sortable: true,
      enumList: serverInfo?.provider_ids,
    },
    {
      key: 'enabled',
      header: 'Enabled',
      accessor: (i) => (i.enabled !== false ? 'active' : 'inactive'),
      cell: (i) => <StatusBadge status={i.enabled !== false ? 'active' : 'inactive'} />,
      sortable: true,
    },
  ], [serverInfo?.provider_ids])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Identity Providers"
        icon={Globe}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Add Provider
          </button>
        }
      />

      <DataTable
        data={idps ?? []}
        columns={columns}
        rowId={(i) => i.alias}
        tableKey="idps"
        emptyState={
          <EmptyState
            icon={Globe}
            title="No identity providers"
            description='Add an identity provider to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} provider(s)?`)) {
                ids.forEach((id) => remove.mutate({ realm, alias: id }))
              }
            },
          },
        ]}
        onRowClick={(i) => navigate(`/identity-providers/${encodeURIComponent(i.alias)}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Identity Provider">
        <IdPForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}
