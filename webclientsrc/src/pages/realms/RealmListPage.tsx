// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useRealms, useRealmCount, useCreateRealm, useDeleteRealm } from '../../api/hooks/useRealms'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import RealmForm from '../../components/domain/RealmForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import StatusBadge from '@/components/data/StatusBadge'
import type { RealmRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function RealmListPage() {
  const navigate = useNavigate()
  const currentRealm = useAuthStore((s) => s.currentRealm)
  const setRealm = useAuthStore((s) => s.setRealm)
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)

  const first = (page - 1) * perPage
  const { data: realms, isLoading, error } = useRealms({ first, max: perPage })
  const { data: totalCount } = useRealmCount()
  const create = useCreateRealm()
  const remove = useDeleteRealm()

  async function handleCreate(data: RealmRepresentation) {
    await create.mutateAsync(data)
    setShowCreate(false)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await remove.mutateAsync(deleteTarget)
    if (deleteTarget === currentRealm) {
      setRealm(null)
    }
    setDeleteTarget(null)
  }

  const columns = useMemo<ColumnDef<RealmRepresentation>[]>(() => [
    {
      key: 'realm',
      header: 'Name',
      accessor: (r) => r.realm ?? '',
      cell: (r) => <span className="text-sm font-medium text-white">{r.realm}</span>,
      sortable: true,
    },
    {
      key: 'display_name',
      header: 'Display Name',
      accessor: (r) => r.display_name ?? '',
      cell: (r) => <span className="text-text-secondary">{r.display_name || '—'}</span>,
      sortable: true,
    },
    {
      key: 'enabled',
      header: 'Enabled',
      accessor: (r) => (r.enabled !== false ? 'active' : 'inactive'),
      cell: (r) => <StatusBadge status={r.enabled !== false ? 'active' : 'inactive'} />,
      sortable: true,
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Realms"
        icon={Globe}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Realm
          </button>
        }
      />

      <DataTable
        data={realms ?? []}
        columns={columns}
        rowId={(r) => r.realm}
        tableKey="realms"
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
            icon={Globe}
            title="No realms"
            description='Create a realm to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} realm(s)?`)) {
                ids.forEach((id) => remove.mutate(id))
              }
            },
          },
        ]}
        onRowClick={(r) => navigate(`/realms/${r.realm}/settings`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Realm">
        <RealmForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
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
