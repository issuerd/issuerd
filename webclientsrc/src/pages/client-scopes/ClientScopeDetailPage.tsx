// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Layers, Trash2 } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useClientScope,
  useUpdateClientScope,
  useDeleteClientScope,
  useScopeMappers,
  useCreateScopeMapper,
  useUpdateScopeMapper,
  useDeleteScopeMapper,
} from '../../api/hooks/useClientScopes'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import ClientScopeForm from '../../components/domain/ClientScopeForm'
import ProtocolMapperEditor from '../../components/domain/ProtocolMapperEditor'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'

import type { ClientScopeRepresentation } from '@generated'

export default function ClientScopeDetailPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: scope, isLoading, error } = useClientScope(realm, id!)
  const update = useUpdateClientScope()
  const remove = useDeleteClientScope()
  const { data: mappers, isLoading: mappersLoading, error: mappersError } = useScopeMappers(realm, id!)
  const createMapper = useCreateScopeMapper()
  const updateMapper = useUpdateScopeMapper()
  const deleteMapper = useDeleteScopeMapper()

  const [deleteOpen, setDeleteOpen] = useState(false)

  async function handleUpdate(data: ClientScopeRepresentation) {
    await update.mutateAsync({ realm, id: id!, body: data })
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, id: id! })
    navigate('/client-scopes')
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!scope) return <ErrorMessage message="Client scope not found" />

  return (
    <div>
      <PageHeader
        title={scope.name}
        icon={Layers}
        breadcrumbs={[
          { label: 'Client Scopes', to: '/client-scopes' },
          { label: scope.name },
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

      <Tabs defaultValue="settings">
        <TabsList variant="line" className="mb-6">
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="mappers">Mappers</TabsTrigger>
        </TabsList>

        <TabsContent value="settings">
          <div className="bg-surface-dark border border-border-custom rounded-xl p-6 max-w-2xl">
            <ClientScopeForm
              defaultValues={scope}
              editing
              onSubmit={handleUpdate}
              onCancel={() => navigate('/client-scopes')}
              loading={update.isPending}
            />
          </div>
        </TabsContent>

        <TabsContent value="mappers">
          <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
            <ProtocolMapperEditor
              mappers={mappers}
              isLoading={mappersLoading}
              error={mappersError}
              onCreate={async (body) => { await createMapper.mutateAsync({ realm, scopeId: id!, body }) }}
              onUpdate={async (mapperId, body) => { await updateMapper.mutateAsync({ realm, scopeId: id!, mapperId, body }) }}
              onDelete={async (mapperId) => { await deleteMapper.mutateAsync({ realm, scopeId: id!, mapperId }) }}
              saving={createMapper.isPending || updateMapper.isPending}
              deleting={deleteMapper.isPending}
            />
          </div>
        </TabsContent>
      </Tabs>

      <DeleteConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}
