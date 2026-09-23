// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import FormLabelWithTooltip from '../ui/FormLabelWithTooltip'
import FormContextLine from '../ui/FormContextLine'

export interface AdminFilterState {
  operation_type?: string
  resource_type?: string
  date_from?: string
  date_to?: string
  first?: number
  max?: number
}

interface AdminEventFilterBarProps {
  filters: AdminFilterState
  onChange: (filters: AdminFilterState) => void
  onApply: () => void
}

export default function AdminEventFilterBar({ filters, onChange, onApply }: AdminEventFilterBarProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const operationDesc = useEnumDescription(serverInfo?.operation_types, filters.operation_type)
  const resourceDesc = useEnumDescription(serverInfo?.resource_types, filters.resource_type)

  return (
    <div className="flex flex-wrap gap-3 items-end">
      <div className="flex flex-col gap-1.5">
        <FormLabelWithTooltip
          label="Operation"
          tooltipText="The administrative operation that was performed"
        />
        <select
          value={filters.operation_type ?? ''}
          onChange={(e) => onChange({ ...filters, operation_type: e.target.value || undefined })}
          disabled={infoLoading}
          className="h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none appearance-none cursor-pointer min-w-[180px] disabled:opacity-50"
        >
          <option value="">All</option>
          {serverInfo?.operation_types.map((ot) => (
            <option key={ot.id} value={ot.id} title={ot.description ?? undefined}>
              {ot.name}
            </option>
          ))}
        </select>
        <FormContextLine text={operationDesc?.description} />
      </div>
      <div className="flex flex-col gap-1.5">
        <FormLabelWithTooltip
          label="Resource Type"
          tooltipText="The type of resource that was changed"
        />
        <select
          value={filters.resource_type ?? ''}
          onChange={(e) => onChange({ ...filters, resource_type: e.target.value || undefined })}
          disabled={infoLoading}
          className="h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none appearance-none cursor-pointer min-w-[180px] disabled:opacity-50"
        >
          <option value="">All</option>
          {serverInfo?.resource_types.map((rt) => (
            <option key={rt.id} value={rt.id} title={rt.description ?? undefined}>
              {rt.name}
            </option>
          ))}
        </select>
        <FormContextLine text={resourceDesc?.description} />
      </div>
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-semibold uppercase tracking-wider text-text-secondary">From</label>
        <input
          type="date"
          value={filters.date_from ? filters.date_from.slice(0, 10) : ''}
          onChange={(e) => {
            const v = e.target.value
            onChange({ ...filters, date_from: v ? `${v}T00:00:00.000Z` : undefined })
          }}
          className="h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none"
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-semibold uppercase tracking-wider text-text-secondary">To</label>
        <input
          type="date"
          value={filters.date_to ? filters.date_to.slice(0, 10) : ''}
          onChange={(e) => {
            const v = e.target.value
            onChange({ ...filters, date_to: v ? `${v}T23:59:59.999Z` : undefined })
          }}
          className="h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none"
        />
      </div>
      <button
        onClick={onApply}
        className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all"
      >
        Apply
      </button>
    </div>
  )
}
