// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Server, Info } from 'lucide-react'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import PageHeader from '@/components/layout/PageHeader'
import PageLoader from '@/components/ui/PageLoader'
import ErrorMessage from '@/components/ui/ErrorMessage'
import Tooltip from '@/components/ui/Tooltip'

function EnumTable({
  title,
  items,
}: {
  title: string
  items: { id: string; name: string; description?: string | null }[] | undefined
}) {
  const [search, setSearch] = useState('')
  const filtered =
    items?.filter(
      (i) =>
        i.name.toLowerCase().includes(search.toLowerCase()) ||
        i.id.toLowerCase().includes(search.toLowerCase()) ||
        (i.description?.toLowerCase().includes(search.toLowerCase()) ?? false)
    ) ?? []

  if (!items) return null

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-border-custom flex items-center justify-between gap-4">
        <h3 className="font-display text-sm font-medium text-text-primary">{title}</h3>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter..."
          className="h-8 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none w-48"
        />
      </div>
      <div className="max-h-64 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-surface-dark z-10">
            <tr className="bg-white/[0.02]">
              <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-text-secondary">
                ID
              </th>
              <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-text-secondary">
                Name
              </th>
              <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-text-secondary">
                Description
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-4 py-4 text-center text-text-tertiary text-sm">
                  No results
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr key={item.id} className="border-t border-border-custom">
                  <td className="px-4 py-2.5 text-sm font-mono text-cyan-neon">{item.id}</td>
                  <td className="px-4 py-2.5 text-sm text-text-primary">{item.name}</td>
                  <td className="px-4 py-2.5 text-sm text-text-secondary">
                    {item.description || '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="px-5 py-2 border-t border-border-custom text-xs text-text-tertiary">
        {filtered.length} of {items.length} values
      </div>
    </div>
  )
}

export default function ServerInfoPage() {
  const { data: serverInfo, isLoading, error } = useServerInfo()

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!serverInfo) return <ErrorMessage message="No server information available" />

  const diagnostics = {
    version: 'Issuerd 0.1.0',
    rustVersion: '1.95+',
    edition: '2021',
    protocols: serverInfo.protocols?.length ?? 0,
    algorithms: serverInfo.algorithms?.length ?? 0,
    eventTypes: serverInfo.event_types?.length ?? 0,
    providerIds: serverInfo.provider_ids?.length ?? 0,
  }

  const jsonBlob = JSON.stringify(serverInfo, null, 2)

  return (
    <div className="space-y-6">
      <PageHeader title="Server Information" icon={Server} />

      {/* Overview cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Version', value: diagnostics.version },
          { label: 'Rust Edition', value: diagnostics.rustVersion },
          { label: 'Protocols', value: String(diagnostics.protocols) },
          { label: 'Algorithms', value: String(diagnostics.algorithms) },
        ].map((card) => (
          <div
            key={card.label}
            className="bg-surface-dark border border-border-custom rounded-xl p-4 flex flex-col gap-1"
          >
            <span className="text-[11px] font-semibold uppercase tracking-wider text-text-tertiary">
              {card.label}
            </span>
            <span className="text-lg font-medium text-text-primary">{card.value}</span>
          </div>
        ))}
      </div>

      {/* Health indicators */}
      <div className="bg-surface-dark border border-border-custom rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-sm font-medium text-text-secondary">System Health</h3>
          <Tooltip content="Derived from available enum counts and API reachability">
            <Info className="w-4 h-4 text-text-tertiary cursor-help" />
          </Tooltip>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { name: 'Database', status: 'healthy' as const },
            { name: 'OIDC Protocol', status: serverInfo.response_types.length > 0 ? 'healthy' : 'warning' },
            { name: 'Event System', status: serverInfo.event_types.length > 0 ? 'healthy' : 'warning' },
            { name: 'Federation', status: serverInfo.provider_ids.length > 0 ? 'healthy' : 'warning' },
          ].map((h) => (
            <div
              key={h.name}
              className="flex flex-col items-center justify-center gap-2 p-4 bg-white/[0.02] rounded-lg border border-border-custom"
            >
              <span className="text-xs text-text-secondary">{h.name}</span>
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${
                  h.status === 'healthy'
                    ? 'bg-matrix-green/10 text-matrix-green border-matrix-green/20'
                    : 'bg-amber/10 text-amber border-amber/20'
                }`}
              >
                {h.status === 'healthy' ? 'Healthy' : 'Degraded'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Enum catalogs */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-display text-sm font-medium text-text-secondary">Enum Catalogs</h3>
          <button
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(jsonBlob)
              } catch { /* ignore */ }
            }}
            className="px-3 py-1.5 text-xs font-medium text-cyan-neon border border-cyan-neon/30 rounded-lg hover:bg-cyan-neon/10 transition-colors"
          >
            Export JSON
          </button>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <EnumTable title="Protocols" items={serverInfo.protocols} />
          <EnumTable title="SSL Required" items={serverInfo.ssl_required} />
          <EnumTable title="Client Authenticator Types" items={serverInfo.client_authenticator_types} />
          <EnumTable title="Grant Types" items={serverInfo.grant_types} />
          <EnumTable title="Response Types" items={serverInfo.response_types} />
          <EnumTable title="Response Modes" items={serverInfo.response_modes} />
          <EnumTable title="PKCE Code Challenge Methods" items={serverInfo.pkce_code_challenge_methods} />
          <EnumTable title="Event Types" items={serverInfo.event_types} />
          <EnumTable title="Operation Types" items={serverInfo.operation_types} />
          <EnumTable title="Resource Types" items={serverInfo.resource_types} />
          <EnumTable title="Credential Types" items={serverInfo.credential_types} />
          <EnumTable title="Provider IDs" items={serverInfo.provider_ids} />
        </div>
      </div>
    </div>
  )
}
