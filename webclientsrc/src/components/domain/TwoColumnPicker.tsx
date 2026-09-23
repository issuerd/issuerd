// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

export interface PickerItem {
  id: string
  label: string
  description?: string | null
}

interface TwoColumnPickerProps {
  leftTitle: string
  rightTitle: string
  leftItems: PickerItem[]
  rightItems: PickerItem[]
  onAdd: (id: string) => Promise<void>
  onRemove: (id: string) => Promise<void>
}

export default function TwoColumnPicker({
  leftTitle,
  rightTitle,
  leftItems,
  rightItems,
  onAdd,
  onRemove,
}: TwoColumnPickerProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-4 items-start">
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-3">{leftTitle}</h4>
        <div className="flex flex-col gap-2 max-h-[320px] overflow-y-auto">
          {leftItems.map((item) => (
            <button
              key={item.id}
              onClick={() => onAdd(item.id)}
              title={item.description ?? undefined}
              className="text-left px-3 py-2 bg-surface-dark border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              <span className="block">{item.label}</span>
              {item.description && (
                <span className="block text-[11px] text-text-tertiary leading-tight">{item.description}</span>
              )}
            </button>
          ))}
          {leftItems.length === 0 && <span className="text-sm text-text-secondary">None</span>}
        </div>
      </div>
      <div className="hidden md:flex flex-col justify-center items-center h-full text-text-tertiary text-xs py-8">
        <span>↔</span>
      </div>
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-3">{rightTitle}</h4>
        <div className="flex flex-col gap-2 max-h-[320px] overflow-y-auto">
          {rightItems.map((item) => (
            <button
              key={item.id}
              onClick={() => onRemove(item.id)}
              title={item.description ?? undefined}
              className="text-left px-3 py-2 bg-surface-dark border border-border-custom rounded-lg text-sm text-text-primary hover:border-alert-red/30 hover:bg-alert-red/5 transition-all"
            >
              <span className="block">{item.label}</span>
              {item.description && (
                <span className="block text-[11px] text-text-tertiary leading-tight">{item.description}</span>
              )}
            </button>
          ))}
          {rightItems.length === 0 && <span className="text-sm text-text-secondary">None</span>}
        </div>
      </div>
    </div>
  )
}
