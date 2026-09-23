// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Globe, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useRealm, useUpdateRealm, useDeleteRealm } from '../../api/hooks/useRealms'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import RealmForm from '../../components/domain/RealmForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import type { RealmRepresentation } from '@generated'

export default function RealmEditPage() {
  const navigate = useNavigate()
  const { realm: realmName } = useParams<{ realm: string }>()
  const currentRealm = useAuthStore((s) => s.currentRealm)
  const setRealm = useAuthStore((s) => s.setRealm)

  const { data: realm, isLoading, error } = useRealm(realmName!)
  const update = useUpdateRealm()
  const remove = useDeleteRealm()

  const [deleteOpen, setDeleteOpen] = useState(false)

  async function handleUpdate(data: RealmRepresentation) {
    await update.mutateAsync({ realm: realmName!, body: data })
    navigate('/realms')
  }

  async function handleDelete() {
    await remove.mutateAsync(realmName!)
    if (realmName === currentRealm) {
      setRealm(null)
    }
    navigate('/realms')
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!realm) return <ErrorMessage message="Realm not found" />

  return (
    <div>
      <PageHeader
        title="Edit Realm"
        icon={Globe}
        breadcrumbs={[
          { label: 'Realms', to: '/realms' },
          { label: realmName! },
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
        <RealmForm
          defaultValues={realm}
          onSubmit={handleUpdate}
          onCancel={() => navigate('/realms')}
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

