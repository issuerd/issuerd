// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { useFlows } from '../../api/hooks/useAuthFlows'
import FormSection from '@/components/ui/FormSection'
import FormSelect from '@/components/ui/FormSelect'
import type { RealmRepresentation } from '@generated'

interface FlowBindingsSectionProps {
  /** Realm name (URL segment) used to list the realm's flows. */
  realm: string
  /** Merged realm values from the settings page (server data + local edits). */
  values: Partial<RealmRepresentation>
  /** Patches a field into the settings page's pending-change state. */
  onPatch: <K extends keyof RealmRepresentation>(key: K, value: RealmRepresentation[K]) => void
}

/** The five realm flow bindings, with their built-in default aliases. */
const BINDINGS: Array<{
  key: 'browserFlow' | 'directGrantFlow' | 'resetCredentialsFlow' | 'firstBrokerLoginFlow' | 'registrationFlow'
  label: string
  builtIn: string
  helper: string
}> = [
  {
    key: 'browserFlow',
    label: 'Browser Flow',
    builtIn: 'browser',
    helper: 'Flow used for interactive browser logins',
  },
  {
    key: 'directGrantFlow',
    label: 'Direct Grant Flow',
    builtIn: 'direct grant',
    helper: 'Flow used for the resource-owner password grant',
  },
  {
    key: 'resetCredentialsFlow',
    label: 'Reset Credentials Flow',
    builtIn: 'reset credentials',
    helper: 'Flow used when a user resets their credentials',
  },
  {
    key: 'firstBrokerLoginFlow',
    label: 'First Broker Login Flow',
    builtIn: 'first broker login',
    helper: 'Flow run the first time a user logs in through an identity provider',
  },
  {
    key: 'registrationFlow',
    label: 'Registration Flow',
    builtIn: 'registration',
    helper: 'Flow used for self-registration',
  },
]

/**
 * Realm flow bindings: binds the realm's authentication entry
 * points to top-level flow aliases. An empty selection means the built-in
 * system default flow. Changes ride the settings page's realm PUT.
 */
export default function FlowBindingsSection({ realm, values, onPatch }: FlowBindingsSectionProps) {
  const { data: flows, isLoading: flowsLoading } = useFlows(realm)

  const topLevelAliases = useMemo(
    () => (flows ?? []).filter((f) => f.top_level).map((f) => f.alias),
    [flows]
  )

  const configuredCount = BINDINGS.filter((b) => values[b.key]).length

  return (
    <FormSection
      title="Flow Bindings"
      description="Which authentication flows handle each login entry point"
      sectionId="realm-general-flow-bindings"
      configuredCount={configuredCount}
      totalCount={BINDINGS.length}
    >
      {BINDINGS.map((binding) => {
        const current = values[binding.key] ?? ''
        const options = [
          {
            value: '',
            label: 'System default',
            description: `Uses the built-in "${binding.builtIn}" flow`,
          },
          // Keep a stored alias selectable even when it no longer resolves to
          // a top-level flow, so it can be inspected and cleared.
          ...(current && !topLevelAliases.includes(current)
            ? [{ value: current, label: `${current} (missing)` }]
            : []),
          ...topLevelAliases.map((alias) => ({ value: alias, label: alias })),
        ]
        return (
          <FormSelect
            key={binding.key}
            label={binding.label}
            options={options}
            value={current}
            onChange={(v) => onPatch(binding.key, v || null)}
            placeholder={flowsLoading ? 'Loading...' : 'Select flow'}
            disabled={flowsLoading}
            helperText={binding.helper}
          />
        )
      })}
    </FormSection>
  )
}
