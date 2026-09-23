// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useForm } from 'react-hook-form'
import type { GroupRepresentation } from '@generated'
import Input from '../ui/Input'

interface GroupFormProps {
  defaultValues?: Partial<GroupRepresentation>
  onSubmit: (data: GroupRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

export default function GroupForm({ defaultValues, onSubmit, onCancel, loading }: GroupFormProps) {
  const { register, handleSubmit, formState: { errors } } = useForm<GroupRepresentation>({
    defaultValues: {
      name: '',
      ...defaultValues,
    },
  })

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4">
      <Input
        label="Name"
        {...register('name', { required: 'Name is required' })}
        error={errors.name?.message}
      />
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
          disabled={loading}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Save
        </button>
      </div>
    </form>
  )
}
