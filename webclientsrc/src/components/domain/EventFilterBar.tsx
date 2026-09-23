// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import FormLabelWithTooltip from '../ui/FormLabelWithTooltip'
import FormContextLine from '../ui/FormContextLine'

export interface FilterState {
  event_type?: string
  date_from?: string
  date_to?: string
  first?: number
  max?: number
}

interface EventFilterBarProps {
  filters: FilterState
  onChange: (filters: FilterState) => void
  onApply: () => void
}

export default function EventFilterBar({ filters, onChange, onApply }: EventFilterBarProps) {
  const { data: serverInfo } = useServerInfo()
  const selectedDesc = useEnumDescription(serverInfo?.event_types, filters.event_type)

  const selectedEventType = serverInfo?.event_types.find((et) => et.id === filters.event_type)

  return (
    <div className="flex flex-wrap gap-3 items-end">
      <div className="flex flex-col gap-1.5">
        <FormLabelWithTooltip
          label="Event Type"
          tooltipText={selectedEventType?.description ?? 'Filter events by their type'}
        />
        <select
          value={filters.event_type ?? ''}
          onChange={(e) => onChange({ ...filters, event_type: e.target.value || undefined })}
          className="h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none appearance-none cursor-pointer min-w-[180px]"
        >
          <option value="">All</option>
          {serverInfo?.event_types.map((et) => (
            <option key={et.id} value={et.id} title={et.description ?? undefined}>
              {et.name}
            </option>
          ))}
        </select>
        <FormContextLine text={selectedDesc?.description} />
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
