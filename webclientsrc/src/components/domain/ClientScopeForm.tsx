// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useForm, Controller } from 'react-hook-form'
import type { ClientProtocol, ClientScopeRepresentation } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormContextLine from '../ui/FormContextLine'
import Button from '../ui/Button'

interface ClientScopeFormProps {
  defaultValues?: Partial<ClientScopeRepresentation>
  onSubmit: (data: ClientScopeRepresentation) => void
  onCancel: () => void
  loading?: boolean
  /** Disable the name field when editing (name is the scope's identity). */
  editing?: boolean
}

interface ClientScopeFormValues {
  name: string
  description: string
  protocol: string
}

export default function ClientScopeForm({ defaultValues, onSubmit, onCancel, loading, editing }: ClientScopeFormProps) {
  const {
    register,
    handleSubmit,
    control,
    watch,
    formState: { errors },
  } = useForm<ClientScopeFormValues>({
    defaultValues: {
      name: defaultValues?.name ?? '',
      description: defaultValues?.description ?? '',
      protocol: defaultValues?.protocol ?? 'openid-connect',
    },
  })

  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const protocolOptions =
    serverInfo?.protocols.map((p) => ({ value: p.id, label: p.name ?? p.id, description: p.description })) ?? []
  const protocolDesc = useEnumDescription(serverInfo?.protocols, watch('protocol'))

  const submit = handleSubmit((data) => {
    onSubmit({
      ...defaultValues,
      name: data.name,
      description: data.description.trim() || null,
      protocol: data.protocol as ClientProtocol,
    })
  })

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Input
        label="Name"
        {...register('name', { required: 'Name is required' })}
        error={errors.name?.message}
        helperText="Unique scope name (e.g. profile)"
        disabled={editing}
      />
      <Input
        label="Description"
        {...register('description')}
        helperText="Human-readable description"
      />
      <Controller
        name="protocol"
        control={control}
        render={({ field }) => (
          <div className="flex flex-col gap-1.5">
            <FormSelect
              label="Protocol"
              options={protocolOptions}
              value={field.value}
              onChange={field.onChange}
              placeholder={infoLoading ? 'Loading...' : 'Select protocol'}
            />
            <FormContextLine text={protocolDesc?.description} />
          </div>
        )}
      />
      <div className="flex justify-end gap-3 mt-2">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" loading={loading || infoLoading}>
          Save
        </Button>
      </div>
    </form>
  )
}
