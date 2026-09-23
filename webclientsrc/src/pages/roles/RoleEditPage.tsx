// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Shield, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useRealmRole, useUpdateRealmRole, useDeleteRealmRole } from '../../api/hooks/useRoles'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import RoleForm from '../../components/domain/RoleForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import type { RoleRepresentation } from '@generated'

export default function RoleEditPage() {
  const navigate = useNavigate()
  const { name } = useParams<{ name: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: role, isLoading, error } = useRealmRole(realm, decodeURIComponent(name!))
  const update = useUpdateRealmRole()
  const remove = useDeleteRealmRole()

  const [deleteOpen, setDeleteOpen] = useState(false)

  async function handleUpdate(data: RoleRepresentation) {
    await update.mutateAsync({ realm, name: decodeURIComponent(name!), body: data })
    navigate('/roles')
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, name: decodeURIComponent(name!) })
    navigate('/roles')
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!role) return <ErrorMessage message="Role not found" />

  return (
    <div>
      <PageHeader
        title="Edit Role"
        icon={Shield}
        breadcrumbs={[
          { label: 'Roles', to: '/roles' },
          { label: role.name },
        ]}
        actions={
          <button
            onClick={() => setDeleteOpen(true)}
            className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center gap-2"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        }
      />

      <div className="bg-surface-dark border border-border-custom rounded-xl p-6 max-w-2xl">
        <RoleForm
          defaultValues={role}
          onSubmit={handleUpdate}
          onCancel={() => navigate('/roles')}
          loading={update.isPending}
        />
      </div>

      <DeleteConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}
