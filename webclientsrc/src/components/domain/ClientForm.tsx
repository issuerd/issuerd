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
import FormSection from '../ui/FormSection'
import FormContextLine from '../ui/FormContextLine'
import Button from '../ui/Button'
import { cn } from '@/lib/utils'

interface ClientFormProps {
  defaultValues?: Partial<ClientRepresentation>
  onSubmit: (data: ClientRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

interface ClientFormValues {
  client_id: string
  name: string
  protocol: string
  client_authenticator_type: string
  public_client: boolean
  enabled: boolean
  consent_required: boolean
  bearer_only: boolean
  full_scope_allowed: boolean
  service_accounts_enabled: boolean
  token_exchange_enabled: boolean
  subject_type: string
  sector_identifier_uri: string
  redirect_uris: string[]
  web_origins: string[]
  default_scopes: string[]
  optional_scopes: string[]
  jwks_source: 'inline' | 'url'
  jwks_string: string
  jwks_url: string
}

export default function ClientForm({ defaultValues, onSubmit, onCancel, loading }: ClientFormProps) {
  const {
    register,
    handleSubmit,
    control,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ClientFormValues>({
    defaultValues: {
      client_id: defaultValues?.client_id ?? '',
      name: defaultValues?.name ?? '',
      protocol: defaultValues?.protocol ?? 'openid-connect',
      client_authenticator_type: defaultValues?.client_authenticator_type ?? 'client-secret',
      public_client: defaultValues?.public_client ?? false,
      enabled: defaultValues?.enabled ?? true,
      consent_required: defaultValues?.consent_required ?? false,
      bearer_only: defaultValues?.bearer_only ?? false,
      full_scope_allowed: defaultValues?.full_scope_allowed ?? false,
      service_accounts_enabled: defaultValues?.service_accounts_enabled ?? false,
      token_exchange_enabled: defaultValues?.attributes?.['token.exchange.enabled'] === 'true',
      subject_type: defaultValues?.attributes?.['subject_type'] ?? 'public',
      sector_identifier_uri: defaultValues?.attributes?.['sector_identifier_uri'] ?? '',
      redirect_uris: defaultValues?.redirect_uris ?? [],
      web_origins: defaultValues?.web_origins ?? [],
      default_scopes: defaultValues?.default_scopes ?? [],
      optional_scopes: defaultValues?.optional_scopes ?? [],
      jwks_source:
        defaultValues?.attributes?.['use.jwks.url'] === 'true' &&
        defaultValues?.attributes?.['use.jwks.string'] !== 'true'
          ? 'url'
          : 'inline',
      jwks_string: defaultValues?.attributes?.['jwks.string'] ?? '',
      jwks_url: defaultValues?.attributes?.['jwks.url'] ?? '',
    },
  })

  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const protocolOptions =
    serverInfo?.protocols.map((p) => ({ value: p.id, label: p.name ?? p.id, description: p.description })) ?? []

  const authenticatorOptions =
    serverInfo?.client_authenticator_types.map((t) => ({
      value: t.id,
      label: t.name ?? t.id,
      description: t.description,
    })) ?? []

  const subjectTypeOptions =
    serverInfo?.subject_types.map((t) => ({
      value: t.id,
      label: t.name ?? t.id,
      description: t.description,
    })) ?? []

  const watched = watch()
  const protocolDesc = useEnumDescription(serverInfo?.protocols, watched.protocol)
  const authenticatorDesc = useEnumDescription(serverInfo?.client_authenticator_types, watched.client_authenticator_type)
  const subjectTypeDesc = useEnumDescription(serverInfo?.subject_types, watched.subject_type)

  const basicConfigured = [watched.client_id, watched.name].filter(Boolean).length
  const basicTotal = 2
  const authConfigured = [watched.public_client, watched.bearer_only, watched.consent_required, watched.full_scope_allowed, watched.service_accounts_enabled, watched.token_exchange_enabled, watched.subject_type === 'pairwise', watched.sector_identifier_uri !== ''].filter(Boolean).length
  const authTotal = 8
  const advConfigured = [watched.redirect_uris.length > 0, watched.web_origins.length > 0].filter(Boolean).length
  const advTotal = 2

  const submit = handleSubmit((data) => {
    // Round-trip attributes the form does not manage, then apply the
    // JWKS keys: exactly one source is kept for `client-jwt`;
    // the keys are stripped for every other authenticator (and for public
    // clients, which do not authenticate).
    const attributes: Record<string, string> = { ...(defaultValues?.attributes ?? {}) }
    delete attributes['use.jwks.string']
    delete attributes['jwks.string']
    delete attributes['use.jwks.url']
    delete attributes['jwks.url']
    if (!data.public_client && data.client_authenticator_type === 'client-jwt') {
      if (data.jwks_source === 'url') {
        attributes['use.jwks.url'] = 'true'
        attributes['jwks.url'] = data.jwks_url
      } else {
        attributes['use.jwks.string'] = 'true'
        attributes['jwks.string'] = data.jwks_string
      }
    }
    // The token-exchange permission flag rides the attributes map.
    delete attributes['token.exchange.enabled']
    if (data.token_exchange_enabled) {
      attributes['token.exchange.enabled'] = 'true'
    }
    // Pairwise subject identifiers (OIDC Core §8). `public` is the
    // backend default, so the key is only stored for `pairwise`; the sector
    // identifier URI is optional and stripped when empty or not pairwise.
    delete attributes['subject_type']
    delete attributes['sector_identifier_uri']
    if (data.subject_type === 'pairwise') {
      attributes['subject_type'] = 'pairwise'
      if (data.sector_identifier_uri !== '') {
        attributes['sector_identifier_uri'] = data.sector_identifier_uri
      }
    }
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
      service_accounts_enabled: data.service_accounts_enabled,
      redirect_uris: data.redirect_uris,
      web_origins: data.web_origins,
      default_scopes: data.default_scopes,
      optional_scopes: data.optional_scopes,
      attributes,
    })
  })

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <FormSection
        title="Basic Settings"
        description="Client identification and protocol"
        sectionId="client-basic"
        configuredCount={basicConfigured}
        totalCount={basicTotal}
      >
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
        <Input
          label="Name"
          {...register('name')}
          helperText="Human-readable display name"
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
        <Controller
          name="enabled"
          control={control}
          render={({ field }) => (
            <FormSwitch
              label="Enabled"
              helperText="Clients that are disabled cannot initiate authentication"
              checked={field.value}
              onChange={field.onChange}
            />
          )}
        />
      </FormSection>

      <FormSection
        title="Authentication"
        description="Client type and consent settings"
        sectionId="client-auth"
        configuredCount={authConfigured}
        totalCount={authTotal}
      >
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
        {!watched.public_client && (
          <>
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
            {watched.client_authenticator_type === 'client-jwt' && (
              <div className="flex flex-col gap-3 rounded-lg border border-border-custom p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
                    JWKS Source
                  </span>
                  <div className="flex gap-1">
                    {(['inline', 'url'] as const).map((source) => (
                      <button
                        key={source}
                        type="button"
                        aria-pressed={watched.jwks_source === source}
                        onClick={() => setValue('jwks_source', source)}
                        className={cn(
                          'px-3 py-1.5 rounded-md text-xs border transition-all',
                          watched.jwks_source === source
                            ? 'bg-cyan-neon/10 border-cyan-neon/30 text-cyan-neon'
                            : 'border-border-custom text-text-secondary hover:bg-white/[0.03]'
                        )}
                      >
                        {source === 'inline' ? 'Inline' : 'URL'}
                      </button>
                    ))}
                  </div>
                </div>
                {watched.jwks_source === 'url' ? (
                  <Input
                    label="JWKS URL"
                    placeholder="https://app.example.com/jwks"
                    {...register('jwks_url')}
                    helperText="The client's JWKS is fetched from this URL (cached briefly); used to verify private_key_jwt client assertions"
                  />
                ) : (
                  <FormTextarea
                    label="JWKS (JSON)"
                    rows={5}
                    monospace
                    placeholder='{"keys":[...]}'
                    {...register('jwks_string')}
                    helperText="Inline JWKS document (public keys) used to verify private_key_jwt client assertions"
                  />
                )}
              </div>
            )}
          </>
        )}
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
        <Controller
          name="service_accounts_enabled"
          control={control}
          render={({ field }) => (
            <FormSwitch
              label="Service Accounts Enabled"
              helperText="Dedicated service account for the client-credentials grant"
              checked={field.value}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          name="token_exchange_enabled"
          control={control}
          render={({ field }) => (
            <FormSwitch
              label="Token Exchange Enabled"
              helperText="Allow other clients to exchange their tokens for tokens scoped to this client (RFC 8693 audience)"
              checked={field.value}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          name="subject_type"
          control={control}
          render={({ field }) => (
            <div className="flex flex-col gap-1.5">
              <FormSelect
                label="Subject Type"
                options={subjectTypeOptions}
                value={field.value}
                onChange={field.onChange}
                placeholder={infoLoading ? 'Loading...' : 'Select subject type'}
              />
              <FormContextLine text={subjectTypeDesc?.description} />
            </div>
          )}
        />
        {watched.subject_type === 'pairwise' && (
          <Input
            label="Sector Identifier URI"
            placeholder="https://app.example.com/sector.json"
            {...register('sector_identifier_uri')}
            helperText="Optional URL serving a JSON array of this client's redirect URIs (OIDC Core §8.1); the document must list every redirect URI and its host becomes the sector identifier"
          />
        )}
      </FormSection>

      <FormSection
        title="Advanced"
        description="URIs, origins, and scopes"
        sectionId="client-advanced"
        configuredCount={advConfigured}
        totalCount={advTotal}
      >
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
              onChange={(e) => field.onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
              rows={3}
              helperText="Scopes automatically granted to this client"
            />
          )}
        />
        <Controller
          name="optional_scopes"
          control={control}
          render={({ field }) => (
            <FormTextarea
              label="Optional Scopes (one per line)"
              value={field.value.join('\n')}
              onChange={(e) => field.onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
              rows={2}
              helperText="Scopes that can be requested but are not granted by default"
            />
          )}
        />
      </FormSection>

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
