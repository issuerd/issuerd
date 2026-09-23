// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useForm } from 'react-hook-form'
import type { RealmRepresentation } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import Input from '../ui/Input'
import FormLabelWithTooltip from '../ui/FormLabelWithTooltip'
import FormContextLine from '../ui/FormContextLine'

interface RealmFormProps {
  defaultValues?: Partial<RealmRepresentation>
  onSubmit: (data: RealmRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

export default function RealmForm({ defaultValues, onSubmit, onCancel, loading }: RealmFormProps) {
  const { register, handleSubmit, watch, formState: { errors } } = useForm<RealmRepresentation>({
    defaultValues: {
      realm: '',
      display_name: '',
      enabled: true,
      ssl_required: 'external',
      ...defaultValues,
    },
  })

  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const sslValue = watch('ssl_required')
  const sslDesc = useEnumDescription(serverInfo?.ssl_required, sslValue)

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4">
      <Input
        label="Realm Name"
        {...register('realm', { required: 'Realm name is required' })}
        error={errors.realm?.message}
      />
      <Input
        label="Display Name"
        {...register('display_name')}
      />
      <div className="flex flex-col gap-1.5">
        <FormLabelWithTooltip
          label="SSL Required"
          tooltipText="Controls whether HTTPS is required for all endpoints, only external requests, or not at all"
        />
        <select
          {...register('ssl_required')}
          className="w-full h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all appearance-none cursor-pointer"
        >
          {infoLoading && <option>Loading...</option>}
          {serverInfo?.ssl_required.map((opt) => (
            <option key={opt.id} value={opt.id} title={opt.description ?? undefined}>
              {opt.name}
            </option>
          ))}
        </select>
        <FormContextLine text={sslDesc?.description} />
      </div>
      <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
        <input
          type="checkbox"
          {...register('enabled')}
          className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
        />
        Enabled
      </label>
      <div className="flex justify-end gap-3 mt-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={loading || infoLoading}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Save
        </button>
      </div>
    </form>
  )
}
