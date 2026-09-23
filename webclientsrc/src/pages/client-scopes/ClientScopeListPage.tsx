// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useClientScopes,
  useCreateClientScope,
  useDeleteClientScope,
} from '../../api/hooks/useClientScopes'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import EnumBadge from '../../components/ui/EnumBadge'
import ClientScopeForm from '../../components/domain/ClientScopeForm'
import PageHeader from '@/components/layout/PageHeader'
import type { ClientScopeRepresentation } from '@generated'

export default function ClientScopeListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)

  const { data: scopes, isLoading, error } = useClientScopes(realm)
  const create = useCreateClientScope()
  const remove = useDeleteClientScope()
  const { data: serverInfo } = useServerInfo()

  async function handleCreate(data: ClientScopeRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  const columns = useMemo<ColumnDef<ClientScopeRepresentation>[]>(() => [
    {
      key: 'name',
      header: 'Name',
      accessor: (s) => s.name ?? '',
      cell: (s) => <span className="text-sm font-medium text-white">{s.name}</span>,
      sortable: true,
    },
    {
      key: 'description',
      header: 'Description',
      accessor: (s) => s.description ?? '',
      cell: (s) => <span className="text-text-secondary">{s.description || '—'}</span>,
      sortable: true,
    },
    {
      key: 'protocol',
      header: 'Protocol',
      accessor: (s) => s.protocol ?? '',
      cell: (s) => (
        <EnumBadge
          enumList={serverInfo?.protocols}
          value={s.protocol ?? 'openid-connect'}
        />
      ),
      sortable: true,
      enumList: serverInfo?.protocols,
    },
  ], [serverInfo?.protocols])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Client Scopes"
        icon={Layers}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Client Scope
          </button>
        }
      />

      <DataTable
        data={scopes ?? []}
        columns={columns}
        rowId={(s) => s.id ?? s.name}
        tableKey="client-scopes"
        emptyState={
          <EmptyState
            icon={Layers}
            title="No client scopes"
            description="Create a client scope to bundle protocol mappers."
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} client scope(s)?`)) {
                ids.forEach((id) => remove.mutate({ realm, id }))
              }
            },
          },
        ]}
        onRowClick={(s) => s.id && navigate(`/client-scopes/${s.id}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Client Scope">
        <ClientScopeForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>
    </div>
  )
}
