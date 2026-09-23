// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Info } from 'lucide-react'
import type { RoleRepresentation } from '@generated'
import { useClients } from '../../api/hooks/useClients'
import FormSelect from '../ui/FormSelect'
import TwoColumnPicker from './TwoColumnPicker'

interface QueryLike<T> {
  data?: T
  isLoading: boolean
}

interface MutationLike<V> {
  mutateAsync: (vars: V) => Promise<unknown>
  isPending: boolean
}

type RealmRoleVars = { realm: string; id: string; roles: RoleRepresentation[] }
type ClientRoleVars = { realm: string; id: string; clientId: string; roles: RoleRepresentation[] }

/**
 * Hook set adapter — the user, group, and client scope-mapping endpoints all
 * expose the same shape, so the pages inject their domain hooks here.
 */
export interface RoleMappingsHooks {
  useAssignedRealmRoles: (realm: string, id: string) => QueryLike<RoleRepresentation[]>
  useAvailableRealmRoles: (realm: string, id: string) => QueryLike<RoleRepresentation[]>
  useAssignedClientRoles: (realm: string, id: string, clientId: string) => QueryLike<RoleRepresentation[]>
  useAvailableClientRoles: (realm: string, id: string, clientId: string) => QueryLike<RoleRepresentation[]>
  useAddRealmRoles: () => MutationLike<RealmRoleVars>
  useRemoveRealmRoles: () => MutationLike<RealmRoleVars>
  useAddClientRoles: () => MutationLike<ClientRoleVars>
  useRemoveClientRoles: () => MutationLike<ClientRoleVars>
}

interface RoleMappingsSectionProps {
  realm: string
  entityId: string
  hooks: RoleMappingsHooks
  /** Informational banner shown above the pickers (e.g. full_scope_allowed note). */
  note?: string
}

function toPickerItems(roles: RoleRepresentation[] | undefined) {
  return (roles ?? [])
    .filter((r) => r.id)
    .map((r) => ({ id: r.id!, label: r.name, description: r.description }))
}

export default function RoleMappingsSection({ realm, entityId, hooks, note }: RoleMappingsSectionProps) {
  const [selectedClientId, setSelectedClientId] = useState('')

  const { data: clients } = useClients(realm)

  const assignedRealm = hooks.useAssignedRealmRoles(realm, entityId)
  const availableRealm = hooks.useAvailableRealmRoles(realm, entityId)
  const addRealmRoles = hooks.useAddRealmRoles()
  const removeRealmRoles = hooks.useRemoveRealmRoles()

  const assignedClient = hooks.useAssignedClientRoles(realm, entityId, selectedClientId)
  const availableClient = hooks.useAvailableClientRoles(realm, entityId, selectedClientId)
  const addClientRoles = hooks.useAddClientRoles()
  const removeClientRoles = hooks.useRemoveClientRoles()

  const clientOptions = (clients ?? [])
    .filter((c) => c.id)
    .map((c) => ({ value: c.id!, label: c.client_id }))

  async function addRealmRole(roleId: string) {
    const role = availableRealm.data?.find((r) => r.id === roleId)
    if (role) await addRealmRoles.mutateAsync({ realm, id: entityId, roles: [role] })
  }

  async function removeRealmRole(roleId: string) {
    const role = assignedRealm.data?.find((r) => r.id === roleId)
    if (role) await removeRealmRoles.mutateAsync({ realm, id: entityId, roles: [role] })
  }

  async function addClientRole(roleId: string) {
    const role = availableClient.data?.find((r) => r.id === roleId)
    if (role) await addClientRoles.mutateAsync({ realm, id: entityId, clientId: selectedClientId, roles: [role] })
  }

  async function removeClientRole(roleId: string) {
    const role = assignedClient.data?.find((r) => r.id === roleId)
    if (role) await removeClientRoles.mutateAsync({ realm, id: entityId, clientId: selectedClientId, roles: [role] })
  }

  return (
    <div className="flex flex-col gap-6">
      {note && (
        <div className="flex items-start gap-3 rounded-xl border border-cyan-neon/20 bg-cyan-neon/5 px-4 py-3">
          <Info className="w-4 h-4 text-cyan-neon mt-0.5 shrink-0" />
          <p className="text-sm text-text-secondary">{note}</p>
        </div>
      )}

      <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
        <h3 className="font-display text-base text-white mb-4">Realm Roles</h3>
        <TwoColumnPicker
          leftTitle="Available Roles"
          rightTitle="Assigned Roles"
          leftItems={toPickerItems(availableRealm.data)}
          rightItems={toPickerItems(assignedRealm.data)}
          onAdd={addRealmRole}
          onRemove={removeRealmRole}
        />
      </div>

      <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
        <h3 className="font-display text-base text-white mb-4">Client Roles</h3>
        <div className="max-w-sm mb-4">
          <FormSelect
            label="Client"
            options={clientOptions}
            value={selectedClientId}
            onChange={setSelectedClientId}
            placeholder="Select a client"
            searchable
          />
        </div>
        {selectedClientId ? (
          <TwoColumnPicker
            leftTitle="Available Roles"
            rightTitle="Assigned Roles"
            leftItems={toPickerItems(availableClient.data)}
            rightItems={toPickerItems(assignedClient.data)}
            onAdd={addClientRole}
            onRemove={removeClientRole}
          />
        ) : (
          <p className="text-sm text-text-tertiary">Select a client to manage its role mappings.</p>
        )}
      </div>
    </div>
  )
}
