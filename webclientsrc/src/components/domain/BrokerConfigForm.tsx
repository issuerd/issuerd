// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormSwitch from '../ui/FormSwitch'
import FormContextLine from '../ui/FormContextLine'
import FormSection from '../ui/FormSection'
import FormLabelWithTooltip from '../ui/FormLabelWithTooltip'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { cn } from '@/lib/utils'

interface BrokerConfigFormProps {
  value: Record<string, string>
  onChange: (value: Record<string, string>) => void
  className?: string
}

/**
 * Settings for external (broker) OIDC/social identity providers. Binds
 * directly to the IdP's free-form `config` map; keys follow the backend's
 * `BrokerIdpSettings` conventions (clientId, issuer, authorizationUrl, …).
 */
export default function BrokerConfigForm({ value, onChange, className }: BrokerConfigFormProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const syncModes = useMemo(
    () =>
      serverInfo?.broker_sync_modes.map((m) => ({
        value: m.id,
        label: m.name ?? m.id,
        description: m.description,
      })) ?? [],
    [serverInfo?.broker_sync_modes]
  )

  const clientAuthMethods = useMemo(
    () =>
      serverInfo?.broker_client_auth_methods.map((m) => ({
        value: m.id,
        label: m.name ?? m.id,
        description: m.description,
      })) ?? [],
    [serverInfo?.broker_client_auth_methods]
  )

  const setField = (key: string, val: string) => {
    onChange({ ...value, [key]: val })
  }

  const setCheckbox = (key: string, checked: boolean) => {
    onChange({ ...value, [key]: checked ? 'true' : 'false' })
  }

  // Discovery defaults on once an issuer is configured, until the admin
  // explicitly toggles it (mirrors BrokerIdpSettings::use_discovery).
  const useDiscovery =
    value.useDiscovery !== undefined ? value.useDiscovery === 'true' : Boolean(value.issuer)

  return (
    <div className={cn('flex flex-col gap-4', className)}>
      <FormSection
        title="Client"
        description="OAuth2 client credentials registered at the external provider"
        sectionId="broker-client"
        configuredCount={[value.clientId, value.clientSecret].filter(Boolean).length}
        totalCount={2}
      >
        <Input
          label="Client ID"
          placeholder="my-app-client-id"
          value={value.clientId ?? ''}
          onChange={(e) => setField('clientId', e.target.value)}
          required
        />
        <div className="flex flex-col gap-1.5">
          <FormLabelWithTooltip
            label="Client Secret"
            htmlFor="broker-client-secret"
            tooltipText="Secret issued by the external provider. Stored in the IdP configuration."
          />
          <Input
            id="broker-client-secret"
            type="password"
            placeholder="Client secret"
            value={value.clientSecret ?? ''}
            onChange={(e) => setField('clientSecret', e.target.value)}
          />
        </div>
      </FormSection>

      <FormSection
        title="Endpoints"
        description="How Issuerd discovers or reaches the provider's OIDC endpoints"
        sectionId="broker-endpoints"
        configuredCount={[value.issuer, value.authorizationUrl, value.tokenUrl].filter(Boolean).length}
        totalCount={3}
      >
        <div className="flex flex-col gap-1.5">
          <FormLabelWithTooltip
            label="Issuer"
            htmlFor="broker-issuer"
            tooltipText="OIDC issuer URL (e.g. https://accounts.google.com). With discovery enabled, endpoints are resolved from {issuer}/.well-known/openid-configuration."
          />
          <Input
            id="broker-issuer"
            placeholder="https://idp.example.com"
            value={value.issuer ?? ''}
            onChange={(e) => setField('issuer', e.target.value)}
          />
        </div>

        <FormSwitch
          label="Use Discovery"
          helperText="Resolve endpoints from the issuer's discovery document. Disable to enter endpoint URLs manually."
          checked={useDiscovery}
          onChange={(v) => setCheckbox('useDiscovery', v)}
        />

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Input
            label="Authorization URL"
            placeholder="https://idp.example.com/authorize"
            value={value.authorizationUrl ?? ''}
            onChange={(e) => setField('authorizationUrl', e.target.value)}
          />
          <Input
            label="Token URL"
            placeholder="https://idp.example.com/token"
            value={value.tokenUrl ?? ''}
            onChange={(e) => setField('tokenUrl', e.target.value)}
          />
          <Input
            label="UserInfo URL"
            placeholder="https://idp.example.com/userinfo"
            value={value.userInfoUrl ?? ''}
            onChange={(e) => setField('userInfoUrl', e.target.value)}
          />
          <Input
            label="JWKS URL"
            placeholder="https://idp.example.com/jwks"
            value={value.jwksUrl ?? ''}
            onChange={(e) => setField('jwksUrl', e.target.value)}
          />
        </div>
        <FormContextLine text="Endpoint URLs are resolved from the discovery document when enabled; they are required only for providers without discovery." />
      </FormSection>

      <FormSection
        title="Login Behaviour"
        description="Scope, trust, and synchronization options for brokered logins"
        sectionId="broker-behaviour"
      >
        <Input
          label="Default Scope"
          placeholder="openid profile email"
          value={value.defaultScope ?? ''}
          onChange={(e) => setField('defaultScope', e.target.value)}
        />

        <FormSelect
          label="Sync Mode"
          options={syncModes}
          value={value.syncMode ?? ''}
          onChange={(v) => setField('syncMode', v)}
          placeholder={infoLoading ? 'Loading...' : 'Select sync mode'}
        />

        <FormSelect
          label="Client Auth Method"
          options={clientAuthMethods}
          value={value.clientAuthMethod ?? ''}
          onChange={(v) => setField('clientAuthMethod', v)}
          placeholder={infoLoading ? 'Loading...' : 'Select client auth method'}
        />

        <FormSwitch
          label="Trust Email"
          helperText="Treat email addresses asserted by this provider as verified; enables automatic account linking by email."
          checked={value.trustEmail === 'true'}
          onChange={(v) => setCheckbox('trustEmail', v)}
        />

        <FormSwitch
          label="PKCE"
          helperText="Send a PKCE code challenge on the brokered authorization request (S256)."
          checked={value.pkceEnabled !== 'false'}
          onChange={(v) => setCheckbox('pkceEnabled', v)}
        />

        <FormSwitch
          label="Store Tokens"
          helperText="Persist the external provider's tokens on the user session for later inspection."
          checked={value.storeTokens === 'true'}
          onChange={(v) => setCheckbox('storeTokens', v)}
        />
      </FormSection>
    </div>
  )
}
