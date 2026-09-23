// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { AppWindow, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useClients, useClientCount, useCreateClient, useDeleteClient } from '../../api/hooks/useClients'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import ClientWizardForm from '../../components/domain/ClientWizardForm'
import PageHeader from '@/components/layout/PageHeader'
import StatusBadge from '@/components/data/StatusBadge'
import EnumBadge from '../../components/ui/EnumBadge'
import type { ClientRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function ClientListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)

  const first = (page - 1) * perPage
  const { data: clients, isLoading, error } = useClients(realm, { first, max: perPage })
  const { data: totalCount } = useClientCount(realm)
  const create = useCreateClient()
  const del = useDeleteClient()
  const { data: serverInfo } = useServerInfo()

  async function handleCreate(data: ClientRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  const columns = useMemo<ColumnDef<ClientRepresentation>[]>(() => [
    {
      key: 'client_id',
      header: 'Client ID',
      accessor: (c) => c.client_id ?? '',
      cell: (c) => <span className="text-sm font-medium text-white">{c.client_id}</span>,
      sortable: true,
    },
    {
      key: 'name',
      header: 'Name',
      accessor: (c) => c.name ?? '',
      cell: (c) => <span className="text-text-secondary">{c.name || '—'}</span>,
      sortable: true,
    },
    {
      key: 'protocol',
      header: 'Protocol',
      accessor: (c) => c.protocol ?? '',
      cell: (c) => (
        <EnumBadge
          enumList={serverInfo?.protocols}
          value={c.protocol ?? ''}
        />
      ),
      sortable: true,
      enumList: serverInfo?.protocols,
    },
    {
      key: 'enabled',
      header: 'Enabled',
      accessor: (c) => (c.enabled !== false ? 'active' : 'inactive'),
      cell: (c) => <StatusBadge status={c.enabled !== false ? 'active' : 'inactive'} />,
      sortable: true,
    },
  ], [serverInfo?.protocols])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Clients"
        icon={AppWindow}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Client
          </button>
        }
      />

      <DataTable
        data={clients ?? []}
        columns={columns}
        rowId={(c) => c.id ?? c.client_id}
        tableKey="clients"
        backendPagination
        totalCount={totalCount}
        page={page}
        perPage={perPage}
        onPageChange={setPage}
        onPerPageChange={(pp) => {
          setPerPage(pp)
          setPage(1)
        }}
        emptyState={
          <EmptyState
            illustration="clients"
            title="No clients"
            description='Create a client to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} client(s)?`)) {
                ids.forEach((id) => del.mutate({ realm, id }))
              }
            },
          },
        ]}
        onRowClick={(c) => c.id && navigate(`/clients/${c.id}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Client" className="max-w-2xl">
        <ClientWizardForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>
    </div>
  )
}
