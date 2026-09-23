// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useEffect } from 'react'
import { useForm, Controller } from 'react-hook-form'
import type { IdentityProviderRepresentation, ProviderId } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormContextLine from '../ui/FormContextLine'
import LdapConfigForm from './LdapConfigForm'
import KerberosConfigForm from './KerberosConfigForm'
import BrokerConfigForm from './BrokerConfigForm'
import { cn } from '@/lib/utils'

interface IdPFormProps {
  defaultValues?: Partial<IdentityProviderRepresentation>
  onSubmit: (data: IdentityProviderRepresentation) => void
  onCancel: () => void
  loading?: boolean
}

type TabId = 'general' | 'connection' | 'mapping' | 'realm' | 'options' | 'broker'

function providerIdToString(pid: ProviderId | null | undefined): string {
  if (!pid) return ''
  if (typeof pid === 'string') return pid
  return pid.Custom
}

export default function IdPForm({ defaultValues, onSubmit, onCancel, loading }: IdPFormProps) {
  const { register, handleSubmit, control, watch, setValue } = useForm<IdentityProviderRepresentation>({
    defaultValues: {
      alias: '',
      display_name: '',
      provider_id: 'ldap',
      enabled: true,
      config: {},
      ...defaultValues,
    },
  })

  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const providerIdValue = watch('provider_id')
  const providerIdStr = providerIdToString(providerIdValue)
  const providerDesc = useEnumDescription(serverInfo?.provider_ids, providerIdStr || null)

  // Broker (OIDC/social) providers are recognized dynamically: the backend
  // ships a config preset for each of them via serverinfo.
  const brokerPreset = serverInfo?.identity_provider_presets.find(
    (p) => p.provider_id === providerIdStr
  )
  const isBroker = !!brokerPreset

  const [config, setConfig] = useState<Record<string, string>>(
    () => {
      const initial = defaultValues?.config
      if (initial && typeof initial === 'object' && !Array.isArray(initial)) {
        return Object.fromEntries(
          Object.entries(initial).filter(([, v]) => v !== null && v !== undefined)
        ) as Record<string, string>
      }
      return {}
    }
  )

  const [activeTab, setActiveTab] = useState<TabId>('general')

  // Reset config when provider type changes (create mode only); broker
  // providers prefill from their serverinfo preset — everything stays editable.
  const [lastProvider, setLastProvider] = useState(providerIdValue)
  useEffect(() => {
    if (providerIdValue !== lastProvider) {
      setLastProvider(providerIdValue)
      if (!defaultValues?.provider_id) {
        setConfig(brokerPreset ? { ...brokerPreset.config } : {})
        if (brokerPreset) setValue('display_name', brokerPreset.display_name)
      }
      setActiveTab('general')
    }
  }, [providerIdValue, lastProvider, defaultValues?.provider_id, brokerPreset, setValue])

  const submit = handleSubmit((data) => {
    onSubmit({ ...data, config })
  })

  const isLdap = providerIdValue === 'ldap'
  const isKerberos = providerIdValue === 'kerberos'

  const tabs: { id: TabId; label: string }[] = [
    { id: 'general', label: 'General' },
    ...(isBroker ? [{ id: 'broker' as TabId, label: 'Broker (OIDC/social)' }] : []),
    ...(isLdap
      ? [
          { id: 'connection' as TabId, label: 'Connection' },
          { id: 'mapping' as TabId, label: 'Mapping' },
        ]
      : []),
    ...(isKerberos
      ? [
          { id: 'realm' as TabId, label: 'Realm' },
          { id: 'options' as TabId, label: 'Options' },
        ]
      : []),
  ]

  return (
    <form onSubmit={submit} className="flex flex-col">
      {/* Tab bar */}
      <div className="flex border-b border-border-custom mb-4 shrink-0">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setActiveTab(t.id)}
            className={cn(
              'px-4 py-2.5 text-sm font-medium transition-colors relative',
              activeTab === t.id
                ? 'text-cyan-neon'
                : 'text-text-secondary hover:text-text-primary'
            )}
          >
            {t.label}
            {activeTab === t.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-neon rounded-full" />
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex flex-col gap-4">
        {activeTab === 'general' && (
          <>
            <Input label="Alias" {...register('alias', { required: true })} />
            <Input label="Display Name" {...register('display_name')} />
            <Controller
              name="provider_id"
              control={control}
              render={({ field }) => (
                <div className="flex flex-col gap-1.5">
                  <FormSelect
                    label="Provider"
                    options={
                      serverInfo?.provider_ids.map((p) => ({
                        value: p.id,
                        label: p.name ?? p.id,
                        description: p.description,
                      })) ?? []
                    }
                    value={typeof field.value === 'string' ? field.value : ''}
                    onChange={field.onChange}
                    placeholder={infoLoading ? 'Loading...' : 'Select provider'}
                  />
                  <FormContextLine text={providerDesc?.description} />
                </div>
              )}
            />
            <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
              <input
                type="checkbox"
                {...register('enabled')}
                className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
              />
              Enabled
            </label>
          </>
        )}

        {activeTab === 'broker' && isBroker && (
          <BrokerConfigForm value={config} onChange={setConfig} />
        )}

        {activeTab === 'connection' && isLdap && (
          <LdapConfigForm section="connection" value={config} onChange={setConfig} />
        )}

        {activeTab === 'mapping' && isLdap && (
          <LdapConfigForm section="mapping" value={config} onChange={setConfig} />
        )}

        {activeTab === 'realm' && isKerberos && (
          <KerberosConfigForm section="realm" value={config} onChange={setConfig} />
        )}

        {activeTab === 'options' && isKerberos && (
          <KerberosConfigForm section="options" value={config} onChange={setConfig} />
        )}
      </div>

      {/* Footer */}
      <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-border-custom shrink-0">
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
