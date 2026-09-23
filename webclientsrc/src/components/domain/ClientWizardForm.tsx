// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useForm, Controller } from 'react-hook-form'
import type { ClientRepresentation, ClientProtocol, ClientAuthenticatorType } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import Input from '../ui/Input'
import FormSwitch from '../ui/FormSwitch'
import FormSelect from '../ui/FormSelect'
import FormTagInput from '../ui/FormTagInput'
import FormTextarea from '../ui/FormTextarea'
import FormContextLine from '../ui/FormContextLine'
import FormWizard from '../ui/FormWizard'

interface ClientWizardFormProps {
  onSubmit: (data: ClientRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

interface ClientWizardValues {
  client_id: string
  name: string
  protocol: string
  client_authenticator_type: string
  public_client: boolean
  enabled: boolean
  consent_required: boolean
  bearer_only: boolean
  full_scope_allowed: boolean
  redirect_uris: string[]
  web_origins: string[]
  default_scopes: string[]
  optional_scopes: string[]
}

export default function ClientWizardForm({ onSubmit, onCancel, loading }: ClientWizardFormProps) {
  const {
    register,
    handleSubmit,
    control,
    watch,
    trigger,
    formState: { errors },
  } = useForm<ClientWizardValues>({
    defaultValues: {
      client_id: '',
      name: '',
      protocol: 'openid-connect',
      client_authenticator_type: 'client-secret',
      public_client: false,
      enabled: true,
      consent_required: false,
      bearer_only: false,
      full_scope_allowed: false,
      redirect_uris: [],
      web_origins: [],
      default_scopes: [],
      optional_scopes: [],
    },
  })

  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const protocolDesc = useEnumDescription(serverInfo?.protocols, watch('protocol'))
  const authenticatorDesc = useEnumDescription(
    serverInfo?.client_authenticator_types,
    watch('client_authenticator_type')
  )

  const protocolOptions =
    serverInfo?.protocols.map((p) => ({ value: p.id, label: p.name ?? p.id, description: p.description })) ?? []

  const authenticatorOptions =
    serverInfo?.client_authenticator_types.map((t) => ({
      value: t.id,
      label: t.name ?? t.id,
      description: t.description,
    })) ?? []

  const submit = handleSubmit((data) => {
    onSubmit({
      client_id: data.client_id,
      name: data.name,
      protocol: data.protocol as ClientProtocol,
      client_authenticator_type: data.client_authenticator_type as ClientAuthenticatorType,
      public_client: data.public_client,
      enabled: data.enabled,
      consent_required: data.consent_required,
      bearer_only: data.bearer_only,
      full_scope_allowed: data.full_scope_allowed,
      redirect_uris: data.redirect_uris,
      web_origins: data.web_origins,
      default_scopes: data.default_scopes,
      optional_scopes: data.optional_scopes,
    })
  })

  const steps = [
    {
      id: 'basic',
      title: 'Basic Settings',
      description: 'Identification and protocol',
      validate: async () => await trigger(['client_id', 'name']),
      content: (
        <div className="flex flex-col gap-4">
          <Input
            label="Client ID"
            copyable
            {...register('client_id', {
              required: 'Client ID is required',
              minLength: { value: 2, message: 'Must be at least 2 characters' },
            })}
            error={errors.client_id?.message}
            helperText="Unique identifier for this client"
          />
          <Input label="Name" {...register('name')} helperText="Human-readable display name" />
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
          <Controller
            name="client_authenticator_type"
            control={control}
            render={({ field }) => (
              <div className="flex flex-col gap-1.5">
                <FormSelect
                  label="Client Authenticator"
                  options={authenticatorOptions}
                  value={field.value}
                  onChange={field.onChange}
                  placeholder={infoLoading ? 'Loading...' : 'Select authenticator'}
                />
                <FormContextLine text={authenticatorDesc?.description} />
              </div>
            )}
          />
        </div>
      ),
    },
    {
      id: 'auth',
      title: 'Authentication',
      description: 'Client type and consent',
      content: (
        <div className="flex flex-col gap-4">
          <Controller
            name="public_client"
            control={control}
            render={({ field }) => (
              <FormSwitch
                label="Public Client"
                helperText="No client secret required (e.g. SPA, mobile apps)"
                checked={field.value}
                onChange={field.onChange}
              />
            )}
          />
          <Controller
            name="bearer_only"
            control={control}
            render={({ field }) => (
              <FormSwitch
                label="Bearer Only"
                helperText="This client only accepts bearer tokens"
                checked={field.value}
                onChange={field.onChange}
              />
            )}
          />
          <Controller
            name="consent_required"
            control={control}
            render={({ field }) => (
              <FormSwitch
                label="Consent Required"
                helperText="Users must grant consent for this client"
                checked={field.value}
                onChange={field.onChange}
              />
            )}
          />
          <Controller
            name="full_scope_allowed"
            control={control}
            render={({ field }) => (
              <FormSwitch
                label="Full Scope Allowed"
                helperText="Allow all realm roles and client roles"
                checked={field.value}
                onChange={field.onChange}
              />
            )}
          />
        </div>
      ),
    },
    {
      id: 'advanced',
      title: 'Advanced',
      description: 'URIs, origins, and scopes',
      content: (
        <div className="flex flex-col gap-4">
          <Controller
            name="redirect_uris"
            control={control}
            render={({ field }) => (
              <FormTagInput
                label="Redirect URIs"
                tags={field.value}
                onChange={field.onChange}
                helperText="Valid redirect URIs for this client"
                placeholder="https://app.example.com/callback"
              />
            )}
          />
          <Controller
            name="web_origins"
            control={control}
            render={({ field }) => (
              <FormTagInput
                label="Web Origins"
                tags={field.value}
                onChange={field.onChange}
                helperText="Allowed CORS origins"
                placeholder="https://app.example.com"
              />
            )}
          />
          <Controller
            name="default_scopes"
            control={control}
            render={({ field }) => (
              <FormTextarea
                label="Default Scopes (one per line)"
                value={field.value.join('\n')}
                onChange={(e) =>
                  field.onChange(
                    e.target.value
                      .split('\n')
                      .map((s) => s.trim())
                      .filter(Boolean)
                  )
                }
                rows={3}
                helperText="Scopes automatically granted to this client"
              />
            )}
          />
        </div>
      ),
    },
    {
      id: 'review',
      title: 'Review',
      description: 'Confirm before creating',
      content: (
        <div className="bg-surface-card border border-border-custom rounded-xl p-5 space-y-3 text-sm">
          <ReviewRow label="Client ID" value={watch('client_id')} />
          <ReviewRow label="Name" value={watch('name') || '—'} />
          <ReviewRow label="Protocol" value={watch('protocol')} />
          <ReviewRow label="Authenticator" value={watch('client_authenticator_type')} />
          <ReviewRow label="Public Client" value={watch('public_client') ? 'Yes' : 'No'} />
          <ReviewRow label="Bearer Only" value={watch('bearer_only') ? 'Yes' : 'No'} />
          <ReviewRow label="Consent Required" value={watch('consent_required') ? 'Yes' : 'No'} />
          <ReviewRow
            label="Redirect URIs"
            value={watch('redirect_uris').join(', ') || 'None'}
          />
        </div>
      ),
    },
  ]

  return <FormWizard steps={steps} onSubmit={submit} onCancel={onCancel} loading={loading || infoLoading} />
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-text-secondary">{label}</span>
      <span className="text-text-primary font-medium text-right">{value}</span>
    </div>
  )
}
