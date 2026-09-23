// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Globe, Trash2, RefreshCw, PlugZap } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useIdp,
  useUpdateIdp,
  useDeleteIdp,
  useSyncUsers,
  useTestIdpConnection,
} from '../../api/hooks/useIdentityProviders'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import IdPForm from '../../components/domain/IdPForm'
import IdpMappersSection from '../../components/domain/IdpMappersSection'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import PageHeader from '@/components/layout/PageHeader'
import type { IdentityProviderRepresentation, IdpTestConnectionResponse } from '@generated'

export default function IdPEditPage() {
  const navigate = useNavigate()
  const { alias } = useParams<{ alias: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: idp, isLoading, error } = useIdp(realm, decodeURIComponent(alias!))
  const update = useUpdateIdp()
  const remove = useDeleteIdp()
  const sync = useSyncUsers()
  const testConnection = useTestIdpConnection()

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [testResult, setTestResult] = useState<IdpTestConnectionResponse | null>(null)
  const [testError, setTestError] = useState('')

  async function handleUpdate(data: IdentityProviderRepresentation) {
    await update.mutateAsync({ realm, alias: decodeURIComponent(alias!), body: data })
    navigate('/identity-providers')
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, alias: decodeURIComponent(alias!) })
    navigate('/identity-providers')
  }

  async function handleTestConnection() {
    setTestResult(null)
    setTestError('')
    try {
      const result = await testConnection.mutateAsync({ realm, alias: decodeURIComponent(alias!) })
      setTestResult(result)
    } catch (e: any) {
      setTestError(e.message || 'Connection test failed')
    }
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!idp) return <ErrorMessage message="Identity provider not found" />

  return (
    <div>
      <PageHeader
        title="Edit Identity Provider"
        icon={Globe}
        breadcrumbs={[
          { label: 'Identity Providers', to: '/identity-providers' },
          { label: idp.alias },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <button
              onClick={handleTestConnection}
              disabled={testConnection.isPending}
              className="px-4 py-2.5 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <PlugZap className="w-4 h-4" />
              {testConnection.isPending ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={async () => {
                try {
                  const result = await sync.mutateAsync({ realm, alias: decodeURIComponent(alias!) })
                  alert(`Sync complete: ${result.added} added, ${result.updated} updated, ${result.removed} removed, ${result.failed} failed`)
                } catch (e: any) {
                  alert('Sync failed: ' + (e.message || 'Unknown error'))
                }
              }}
              disabled={sync.isPending}
              className="px-4 py-2.5 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${sync.isPending ? 'animate-spin' : ''}`} />
              {sync.isPending ? 'Syncing...' : 'Sync Users'}
            </button>
            <button
              onClick={() => setDeleteOpen(true)}
              className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        }
      />

      {testResult && testResult.status === 'ok' && (
        <div className="mb-4 max-w-2xl rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-3 text-sm text-green-500">
          Connection test passed — the provider configuration is usable.
        </div>
      )}

      {testResult && testResult.status !== 'ok' && (
        <div className="mb-4 max-w-2xl rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
          <p className="font-semibold mb-1">Connection test failed:</p>
          <ul className="list-disc list-inside space-y-0.5">
            {testResult.problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </div>
      )}

      {testError && (
        <div className="mb-4 max-w-2xl rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
          {testError}
        </div>
      )}

      <div className="bg-surface-dark border border-border-custom rounded-xl p-6 max-w-2xl">
        <IdPForm
          defaultValues={idp}
          onSubmit={handleUpdate}
          onCancel={() => navigate('/identity-providers')}
          loading={update.isPending}
        />
      </div>

      <IdpMappersSection realm={realm} alias={decodeURIComponent(alias!)} />

      <DeleteConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}
