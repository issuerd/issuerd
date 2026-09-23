// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo, useState } from 'react'
import { useAuthStore } from '../../state/authStore'
import { useKeys, useRotateKeys, useDisableKey } from '../../api/hooks/useKeys'
import { useRealm, useUpdateRealm } from '../../api/hooks/useRealms'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import PageHeader from '@/components/layout/PageHeader'
import StatusBadge from '@/components/data/StatusBadge'
import { KeyRound, RefreshCw } from 'lucide-react'

interface KeyRow {
  kid: string
  algorithm: string
  provider_id: string
  status: 'active' | 'passive'
}

/** Realm attribute selecting which active (server-global) key signs the realm's tokens. */
const DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE = 'default_signature_algorithm'

export default function KeysPage() {
  const realm = useAuthStore((s) => s.currentRealm)!
  const { data: keysMeta, isLoading, error } = useKeys(realm)
  const rotate = useRotateKeys()
  const disable = useDisableKey()
  const { data: realmData } = useRealm(realm)
  const updateRealm = useUpdateRealm()
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  // The realm's configured signing algorithm (server default RS256 when unset).
  const realmAlg = realmData?.attributes?.[DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE] ?? 'RS256'
  // Algorithm the next rotation generates a key for; follows the realm algorithm.
  const [rotateAlgOverride, setRotateAlgOverride] = useState<string | null>(null)
  const rotateAlg = rotateAlgOverride ?? realmAlg

  const data = useMemo<KeyRow[]>(() => {
    const activeKeys = Object.entries(keysMeta?.active ?? {}).map(([algorithm, kid]) => ({
      kid,
      algorithm,
      provider_id: '—',
      status: 'active' as const,
    }))
    const passiveKeys = (keysMeta?.passive ?? []).map((k) => ({ ...k, status: 'passive' as const }))
    return [...activeKeys, ...passiveKeys]
  }, [keysMeta])

  const columns = useMemo<ColumnDef<KeyRow>[]>(() => [
    {
      key: 'kid',
      header: 'KID',
      accessor: (k) => k.kid ?? '',
      cell: (k) => <span className="font-mono text-xs text-white">{k.kid}</span>,
      sortable: true,
    },
    {
      key: 'algorithm',
      header: 'Algorithm',
      accessor: (k) => k.algorithm ?? '',
      cell: (k) => <span className="text-text-secondary">{k.algorithm || '—'}</span>,
      sortable: true,
    },
    {
      key: 'status',
      header: 'Status',
      accessor: (k) => k.status,
      cell: (k) => (
        k.status === 'active' ? (
          <StatusBadge status="active" />
        ) : (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase tracking-wider bg-white/5 text-text-secondary">
            Passive
          </span>
        )
      ),
      sortable: true,
    },
    {
      key: 'provider_id',
      header: 'Provider',
      accessor: (k) => k.provider_id ?? '',
      cell: (k) => <span className="text-text-secondary">{k.provider_id || '—'}</span>,
      sortable: true,
    },
    {
      key: 'actions',
      header: '',
      cell: (k) =>
        k.status === 'active' ? (
          <button
            onClick={() => disable.mutate({ realm, kid: k.kid })}
            disabled={disable.isPending}
            className="px-3 py-1.5 border border-alert-red/30 rounded-lg text-xs text-alert-red hover:bg-alert-red/10 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Disable
          </button>
        ) : null,
    },
  ], [disable, realm])

  function onRealmAlgChange(algorithm: string) {
    if (!realmData) return
    updateRealm.mutate({
      realm,
      body: {
        ...realmData,
        attributes: {
          ...realmData.attributes,
          [DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE]: algorithm,
        },
      },
    })
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader
        title="Keys"
        icon={KeyRound}
        actions={
          <div className="flex items-center gap-3">
            <select
              aria-label="Rotation algorithm"
              value={rotateAlg}
              disabled={infoLoading}
              onChange={(e) => setRotateAlgOverride(e.target.value)}
              className="px-3 py-2.5 bg-surface-dark border border-border-custom rounded-lg text-sm text-text-primary focus:outline-none focus:border-cyan-neon/50"
            >
              {(serverInfo?.algorithms ?? []).map((a) => (
                <option key={a.id} value={a.id} title={a.description ?? undefined}>
                  {a.name}
                </option>
              ))}
            </select>
            <button
              onClick={() => rotate.mutate({ realm, algorithm: rotateAlg })}
              disabled={rotate.isPending}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${rotate.isPending ? 'animate-spin' : ''}`} />
              Rotate Keys
            </button>
          </div>
        }
      />

      <div className="mb-6 p-4 bg-surface-card border border-border-custom rounded-xl max-w-2xl">
        <label
          htmlFor="realm-signature-algorithm"
          className="block text-sm font-semibold text-text-primary mb-2"
        >
          Realm signing algorithm
        </label>
        <select
          id="realm-signature-algorithm"
          value={realmAlg}
          disabled={infoLoading || !realmData || updateRealm.isPending}
          onChange={(e) => onRealmAlgChange(e.target.value)}
          className="w-full px-3 py-2.5 bg-surface-dark border border-border-custom rounded-lg text-sm text-text-primary focus:outline-none focus:border-cyan-neon/50"
        >
          {(serverInfo?.algorithms ?? []).map((a) => (
            <option key={a.id} value={a.id} title={a.description ?? undefined}>
              {a.name}
            </option>
          ))}
        </select>
        <p className="mt-2 text-xs text-text-secondary">
          Tokens issued for this realm are signed with the newest active key of this algorithm.
          Signing keys are shared by all realms; rotation (above) keeps one active key per
          algorithm, so changing this setting does not affect other realms. If no active key
          exists for the selected algorithm, the realm falls back to the default signing key —
          rotate with this algorithm to create one.
        </p>
      </div>

      <DataTable
        data={data}
        columns={columns}
        rowId={(k) => k.kid}
        tableKey="keys"
        emptyState={
          <EmptyState icon={KeyRound} title="No keys" description="No key metadata available." />
        }
      />
    </div>
  )
}
