// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Users, UserPlus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { useAuthStore } from '../../state/authStore'
import { useUsers, useUserCount, useCreateUser, useDeleteUser } from '../../api/hooks/useUsers'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import UserForm from '../../components/domain/UserForm'
import PageHeader from '@/components/layout/PageHeader'
import StatusBadge from '@/components/data/StatusBadge'
import { DataTable } from '../../components/ui/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable'
import type { UserRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function UserListPage() {
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [showCreate, setShowCreate] = useState(false)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)
  const [search, setSearch] = useState('')

  const first = (page - 1) * perPage
  const { data: users, isLoading, error } = useUsers(realm, {
    first,
    max: perPage,
    search: search || undefined,
  })
  const { data: totalCount } = useUserCount(realm, search || undefined)
  const create = useCreateUser()
  const del = useDeleteUser()

  async function handleCreate(data: UserRepresentation) {
    await create.mutateAsync({ realm, body: data })
    setShowCreate(false)
  }

  function getInitials(u: UserRepresentation) {
    const firstName = u.first_name?.[0] ?? ''
    const last = u.last_name?.[0] ?? ''
    const fallback = u.username?.[0] ?? ''
    return `${firstName}${last}`.toUpperCase() || fallback.toUpperCase()
  }

  const columns = useMemo<ColumnDef<UserRepresentation>[]>(() => [
    {
      key: 'user',
      header: 'User',
      accessor: (u) => u.username ?? '',
      cell: (u) => (
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-muted border border-border flex items-center justify-center flex-shrink-0">
            <span className="font-mono text-xs text-foreground">{getInitials(u)}</span>
          </div>
          <div>
            <span className="text-sm font-medium text-foreground">{u.username}</span>
            <p className="text-xs text-muted-foreground">{u.first_name} {u.last_name}</p>
          </div>
        </div>
      ),
      sortable: true,
    },
    {
      key: 'email',
      header: 'Email',
      accessor: (u) => u.email ?? '',
      cell: (u) => <span className="text-muted-foreground">{u.email || '—'}</span>,
      sortable: true,
    },
    {
      key: 'enabled',
      header: 'Enabled',
      accessor: (u) => (u.enabled !== false ? 'active' : 'inactive'),
      cell: (u) => <StatusBadge status={u.enabled !== false ? 'active' : 'inactive'} />,
      sortable: true,
    },
    {
      key: 'created_at',
      header: 'Created At',
      accessor: (u) => u.created_at ?? 0,
      cell: (u) => (
        <span className="text-muted-foreground text-xs font-mono">
          {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
        </span>
      ),
      sortable: true,
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Users"
        icon={Users}
        actions={
          <Button
            onClick={() => setShowCreate(true)}
            variant="primary"
            className="flex items-center gap-2"
          >
            <UserPlus className="w-4 h-4" /> Add User
          </Button>
        }
      />

      <DataTable
        data={users ?? []}
        columns={columns}
        rowId={(u) => u.id ?? u.username}
        tableKey="users"
        backendPagination
        totalCount={totalCount}
        page={page}
        perPage={perPage}
        onPageChange={setPage}
        onPerPageChange={(pp) => {
          setPerPage(pp)
          setPage(1)
        }}
        search={search}
        onSearchChange={(value) => {
          setSearch(value)
          setPage(1)
        }}
        emptyState={
          <EmptyState
            illustration="users"
            title="No users"
            description='Create a user to get started.'
          />
        }
        bulkActions={[
          {
            label: 'Delete',
            variant: 'danger',
            icon: <Trash2 className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Delete ${ids.length} user(s)?`)) {
                ids.forEach((id) => del.mutate({ realm, id }))
              }
            },
          },
        ]}
        onRowClick={(u) => u.id && navigate(`/users/${u.id}`)}
      />

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create User">
        <UserForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>
    </div>
  )
}
