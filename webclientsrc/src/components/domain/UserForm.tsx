// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useForm, Controller } from 'react-hook-form'
import type { UserRepresentation } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import Input from '../ui/Input'
import FormSwitch from '../ui/FormSwitch'
import Button from '../ui/Button'

interface UserFormProps {
  defaultValues?: Partial<UserRepresentation>
  onSubmit: (data: UserRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

export default function UserForm({ defaultValues, onSubmit, onCancel, loading }: UserFormProps) {
  const { register, handleSubmit, control, formState: { errors } } = useForm<UserRepresentation>({
    defaultValues: {
      username: '',
      email: '',
      first_name: '',
      last_name: '',
      enabled: true,
      ...defaultValues,
    },
  })

  // Dynamic enum rule: required-action options come from the backend, never hardcoded.
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4">
      <Input
        label="Username"
        helperText="Unique username for login"
        {...register('username', { required: 'Username is required' })}
        error={errors.username?.message}
      />
      <Input
        label="Email"
        type="email"
        helperText="User's email address"
        {...register('email')}
      />
      <Input
        label="First Name"
        {...register('first_name')}
      />
      <Input
        label="Last Name"
        {...register('last_name')}
      />
      <Controller
        name="enabled"
        control={control}
        render={({ field }) => (
          <FormSwitch
            label="Enabled"
            helperText="Disabled users cannot log in"
            checked={field.value ?? true}
            onChange={field.onChange}
          />
        )}
      />
      <Controller
        name="requiredActions"
        control={control}
        render={({ field }) => {
          const selected = field.value ?? []
          return (
            <div className="flex flex-col gap-1.5">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Required Actions
              </span>
              <div className="flex flex-col gap-2 rounded-md border border-border-custom p-3">
                {infoLoading && (
                  <span className="text-xs text-text-tertiary">Loading...</span>
                )}
                {!infoLoading && (serverInfo?.required_actions.length ?? 0) === 0 && (
                  <span className="text-xs text-text-tertiary">No required actions available</span>
                )}
                {serverInfo?.required_actions.map((action) => {
                  const checked = selected.includes(action.id)
                  return (
                    <label
                      key={action.id}
                      className="flex items-start gap-2 cursor-pointer"
                      title={action.description ?? undefined}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          field.onChange(
                            checked
                              ? selected.filter((v) => v !== action.id)
                              : [...selected, action.id]
                          )
                        }
                        className="mt-0.5 w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                      />
                      <span className="flex flex-col">
                        <span className="text-sm text-text-primary">
                          {action.name ?? action.id}
                        </span>
                        {action.description && (
                          <span className="text-[11px] text-text-tertiary leading-tight">
                            {action.description}
                          </span>
                        )}
                      </span>
                    </label>
                  )
                })}
              </div>
              <span className="text-xs text-text-tertiary">
                Actions the user must complete on next login
              </span>
            </div>
          )
        }}
      />
      <div className="flex justify-end gap-3 mt-2">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" loading={loading}>
          Save
        </Button>
      </div>
    </form>
  )
}
