// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { UsersRound, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useGroups, useGroupCount, useCreateGroup, useDeleteGroup } from '../../api/hooks/useGroups'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import GroupForm from '../../components/domain/GroupForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import type { GroupRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function GroupListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)

  const first = (page - 1) * perPage
  const { data: groups, isLoading, error } = useGroups(realm, { first, max: perPage })
  const { data: totalCount } = useGroupCount(realm)
  const create = useCreateGroup()
  const remove = useDeleteGroup()

  async function handleCreate(data: GroupRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await remove.mutateAsync({ realm, id: deleteTarget })
    setDeleteTarget(null)
  }

  const columns = useMemo<ColumnDef<GroupRepresentation>[]>(() => [
    {
      key: 'name',
      header: 'Name',
      accessor: (g) => g.name ?? '',
      cell: (g) => <span className="text-sm font-medium text-white">{g.name}</span>,
      sortable: true,
    },
    {
      key: 'path',
      header: 'Path',
      accessor: (g) => g.path ?? '',
      cell: (g) => <span className="text-text-secondary font-mono text-xs">{g.path || '—'}</span>,
      sortable: true,
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Groups"
        icon={UsersRound}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Create Group
          </button>
        }
      />

      <DataTable
        data={groups ?? []}
        columns={columns}
        rowId={(g) => g.id ?? g.name}
        tableKey="groups"
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
            icon={UsersRound}
            title="No groups"
            description='Create a group to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} group(s)?`)) {
                ids.forEach((id) => remove.mutate({ realm, id }))
              }
            },
          },
        ]}
        onRowClick={(g) => g.id && navigate(`/groups/${g.id}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Group">
        <GroupForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
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
