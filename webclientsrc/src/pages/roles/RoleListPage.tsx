// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useRealmRoles, useRealmRoleCount, useCreateRealmRole, useDeleteRealmRole } from '../../api/hooks/useRoles'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import RoleForm from '../../components/domain/RoleForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import type { RoleRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function RoleListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)

  const first = (page - 1) * perPage
  const { data: roles, isLoading, error } = useRealmRoles(realm, { first, max: perPage })
  const { data: totalCount } = useRealmRoleCount(realm)
  const create = useCreateRealmRole()
  const remove = useDeleteRealmRole()

  async function handleCreate(data: RoleRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await remove.mutateAsync({ realm, name: deleteTarget })
    setDeleteTarget(null)
  }

  const columns = useMemo<ColumnDef<RoleRepresentation>[]>(() => [
    {
      key: 'name',
      header: 'Name',
      accessor: (r) => r.name ?? '',
      cell: (r) => <span className="text-sm font-medium text-white">{r.name}</span>,
      sortable: true,
    },
    {
      key: 'description',
      header: 'Description',
      accessor: (r) => r.description ?? '',
      cell: (r) => <span className="text-text-secondary">{r.description || '—'}</span>,
      sortable: true,
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Roles"
        icon={Shield}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Role
          </button>
        }
      />

      <DataTable
        data={roles ?? []}
        columns={columns}
        rowId={(r) => r.id ?? r.name}
        tableKey="roles"
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
            icon={Shield}
            title="No roles"
            description='Create a role to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} role(s)?`)) {
                ids.forEach((id) => remove.mutate({ realm, name: id }))
              }
            },
          },
        ]}
        onRowClick={(r) => navigate(`/roles/${encodeURIComponent(r.name)}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Role">
        <RoleForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
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
