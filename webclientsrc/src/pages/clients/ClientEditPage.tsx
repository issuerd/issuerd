// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { AppWindow, Trash2, KeyRound, RefreshCw, Plus, Download } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useClient,
  useUpdateClient,
  useDeleteClient,
  useRotateClientSecret,
  useGetClientSecret,
  useClientRoles,
  useCreateClientRole,
  useDeleteClientRole,
  useClientMappers,
  useCreateClientMapper,
  useUpdateClientMapper,
  useDeleteClientMapper,
  useDefaultClientScopes,
  useOptionalClientScopes,
  useAssignDefaultClientScope,
  useUnassignDefaultClientScope,
  useAssignOptionalClientScope,
  useUnassignOptionalClientScope,
  useScopeMappingRealmRoles,
  useAvailableScopeMappingRealmRoles,
  useAddScopeMappingRealmRoles,
  useRemoveScopeMappingRealmRoles,
  useScopeMappingClientRoles,
  useAvailableScopeMappingClientRoles,
  useAddScopeMappingClientRoles,
  useRemoveScopeMappingClientRoles,
} from '../../api/hooks/useClients'
import { useClientScopes } from '../../api/hooks/useClientScopes'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs'
import Spinner from '../../components/ui/Spinner'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import FormSelect from '../../components/ui/FormSelect'
import Badge from '../../components/ui/Badge'
import { Table, Thead, Tbody, Tr, Th, Td } from '../../components/ui/Table'
import ClientForm from '../../components/domain/ClientForm'
import RoleForm from '../../components/domain/RoleForm'
import ProtocolMapperEditor from '../../components/domain/ProtocolMapperEditor'
import RoleMappingsSection, { type RoleMappingsHooks } from '../../components/domain/RoleMappingsSection'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import SecretRevealModal from '../../components/domain/SecretRevealModal'
import DownloadClientConfigDialog from '../../components/domain/DownloadClientConfigDialog'
import PageHeader from '@/components/layout/PageHeader'

import type { ClientRepresentation, ClientScopeRepresentation, RoleRepresentation } from '@generated'

const scopeMappingHooks: RoleMappingsHooks = {
  useAssignedRealmRoles: useScopeMappingRealmRoles,
  useAvailableRealmRoles: useAvailableScopeMappingRealmRoles,
  useAssignedClientRoles: useScopeMappingClientRoles,
  useAvailableClientRoles: useAvailableScopeMappingClientRoles,
  useAddRealmRoles: useAddScopeMappingRealmRoles,
  useRemoveRealmRoles: useRemoveScopeMappingRealmRoles,
  useAddClientRoles: useAddScopeMappingClientRoles,
  useRemoveClientRoles: useRemoveScopeMappingClientRoles,
}

export default function ClientEditPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: client, isLoading, error } = useClient(realm, id!)
  const update = useUpdateClient()
  const remove = useDeleteClient()
  const rotate = useRotateClientSecret()
  const getSecret = useGetClientSecret()
  const [secretValue, setSecretValue] = useState('')

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [downloadOpen, setDownloadOpen] = useState(false)

  async function handleUpdate(data: ClientRepresentation) {
    await update.mutateAsync({ realm, id: id!, body: data })
    navigate('/clients')
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, id: id! })
    navigate('/clients')
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!client) return <ErrorMessage message="Client not found" />

  return (
    <div>
      <PageHeader
        title="Edit Client"
        icon={AppWindow}
        breadcrumbs={[
          { label: 'Clients', to: '/clients' },
          { label: client.client_id },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <button
              onClick={() => setDownloadOpen(true)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download Config
            </button>
            <button
              onClick={() => setDeleteOpen(true)}
              className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        }
      />

      <Tabs defaultValue="settings">
        <TabsList variant="line" className="mb-6">
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="roles">Roles</TabsTrigger>
          <TabsTrigger value="mappers">Mappers</TabsTrigger>
          <TabsTrigger value="client-scopes">Client Scopes</TabsTrigger>
          <TabsTrigger value="scope-mappings">Scope Mappings</TabsTrigger>
        </TabsList>

        <TabsContent value="settings">
          {!client.public_client && (
            <div className="bg-surface-dark border border-border-custom rounded-xl p-4 mb-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <KeyRound className="w-5 h-5 text-cyan-neon" />
                <div>
                  <div className="text-sm font-medium text-white">Client Secret</div>
                  <div className="text-xs text-text-secondary">Manage the client credentials</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={async () => {
                    const res = await getSecret.mutateAsync({ realm, id: id! })
                    setSecretValue(res?.value ?? '')
                    setShowSecret(true)
                  }}
                  className="px-4 py-2 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
                >
                  View Secret
                </button>
                <button
                  onClick={() => rotate.mutate({ realm, id: id! })}
                  className="px-4 py-2 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
                >
                  <RefreshCw className="w-4 h-4" />
                  Rotate
                </button>
              </div>
            </div>
          )}

          <div className="bg-surface-dark border border-border-custom rounded-xl p-6 max-w-2xl">
            <ClientForm
              defaultValues={client}
              onSubmit={handleUpdate}
              onCancel={() => navigate('/clients')}
              loading={update.isPending}
            />
          </div>
        </TabsContent>

        <TabsContent value="roles">
          <ClientRolesTab realm={realm} clientId={id!} />
        </TabsContent>

        <TabsContent value="mappers">
          <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
            <ClientMappersTab realm={realm} clientId={id!} />
          </div>
        </TabsContent>

        <TabsContent value="client-scopes">
          <ClientScopesTab realm={realm} clientId={id!} />
        </TabsContent>

        <TabsContent value="scope-mappings">
          <RoleMappingsSection
            realm={realm}
            entityId={id!}
            hooks={scopeMappingHooks}
            note={
              client.full_scope_allowed
                ? 'Full scope is allowed for this client — tokens include all realm and client roles, so the mappings below have no effect. You can still edit them; they apply as soon as full scope is turned off.'
                : undefined
            }
          />
        </TabsContent>
      </Tabs>

      <DeleteConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />

      <SecretRevealModal
        open={showSecret}
        onClose={() => setShowSecret(false)}
        secret={secretValue}
      />

      <DownloadClientConfigDialog
        open={downloadOpen}
        onClose={() => setDownloadOpen(false)}
        realm={realm}
        clientId={id!}
        protocol={client.protocol ?? 'openid-connect'}
      />
    </div>
  )
}

function ClientRolesTab({ realm, clientId }: { realm: string; clientId: string }) {
  const { data: roles, isLoading, error } = useClientRoles(realm, clientId)
  const create = useCreateClientRole()
  const remove = useDeleteClientRole()
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<RoleRepresentation | null>(null)

  async function handleCreate(data: RoleRepresentation) {
    await create.mutateAsync({ realm, clientId, body: data })
    setShowCreate(false)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await remove.mutateAsync({ realm, clientId, roleName: deleteTarget.name })
    setDeleteTarget(null)
  }

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-text-tertiary">
          Roles owned by this client. They appear under <code>resource_access.{`<client>`}</code> in tokens.
        </p>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Create Role
        </button>
      </div>

      {isLoading ? (
        <Spinner />
      ) : error ? (
        <ErrorMessage message={error.message} />
      ) : !roles || roles.length === 0 ? (
        <p className="text-sm text-text-tertiary py-4 text-center">No roles defined for this client.</p>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Description</Th>
              <Th>Composite</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {roles.map((role) => (
              <Tr key={role.id ?? role.name}>
                <Td className="font-medium text-foreground">{role.name}</Td>
                <Td className="text-text-secondary">{role.description || '—'}</Td>
                <Td>{role.composite ? <Badge variant="info">Composite</Badge> : <span className="text-text-tertiary">—</span>}</Td>
                <Td align="right">
                  <button
                    onClick={() => setDeleteTarget(role)}
                    className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors"
                    aria-label={`Delete role ${role.name}`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Client Role">
        <RoleForm onSubmit={handleCreate} onCancel={() => setShowCreate(false)} loading={create.isPending} />
      </Modal>

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}

function ClientMappersTab({ realm, clientId }: { realm: string; clientId: string }) {
  const { data: mappers, isLoading, error } = useClientMappers(realm, clientId)
  const create = useCreateClientMapper()
  const update = useUpdateClientMapper()
  const remove = useDeleteClientMapper()

  return (
    <ProtocolMapperEditor
      mappers={mappers}
      isLoading={isLoading}
      error={error}
      onCreate={async (body) => { await create.mutateAsync({ realm, clientId, body }) }}
      onUpdate={async (mapperId, body) => { await update.mutateAsync({ realm, clientId, mapperId, body }) }}
      onDelete={async (mapperId) => { await remove.mutateAsync({ realm, clientId, mapperId }) }}
      saving={create.isPending || update.isPending}
      deleting={remove.isPending}
    />
  )
}

function ClientScopesTab({ realm, clientId }: { realm: string; clientId: string }) {
  const { data: allScopes } = useClientScopes(realm)
  const { data: defaultScopes, isLoading: defaultLoading } = useDefaultClientScopes(realm, clientId)
  const { data: optionalScopes, isLoading: optionalLoading } = useOptionalClientScopes(realm, clientId)
  const assignDefault = useAssignDefaultClientScope()
  const unassignDefault = useUnassignDefaultClientScope()
  const assignOptional = useAssignOptionalClientScope()
  const unassignOptional = useUnassignOptionalClientScope()

  const assignedIds = new Set([
    ...(defaultScopes ?? []).map((s) => s.id),
    ...(optionalScopes ?? []).map((s) => s.id),
  ])
  const assignable = (allScopes ?? []).filter((s) => s.id && !assignedIds.has(s.id))

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <ScopeAssignmentList
        title="Default Client Scopes"
        description="Always granted to tokens issued for this client."
        scopes={defaultScopes}
        isLoading={defaultLoading}
        assignable={assignable}
        onAssign={async (scopeId) => { await assignDefault.mutateAsync({ realm, clientId, scopeId }) }}
        onRemove={async (scopeId) => { await unassignDefault.mutateAsync({ realm, clientId, scopeId }) }}
      />
      <ScopeAssignmentList
        title="Optional Client Scopes"
        description="Granted only when requested via the scope parameter."
        scopes={optionalScopes}
        isLoading={optionalLoading}
        assignable={assignable}
        onAssign={async (scopeId) => { await assignOptional.mutateAsync({ realm, clientId, scopeId }) }}
        onRemove={async (scopeId) => { await unassignOptional.mutateAsync({ realm, clientId, scopeId }) }}
      />
    </div>
  )
}

function ScopeAssignmentList({
  title,
  description,
  scopes,
  isLoading,
  assignable,
  onAssign,
  onRemove,
}: {
  title: string
  description: string
  scopes: ClientScopeRepresentation[] | undefined
  isLoading: boolean
  assignable: ClientScopeRepresentation[]
  onAssign: (scopeId: string) => Promise<void>
  onRemove: (scopeId: string) => Promise<void>
}) {
  const [selected, setSelected] = useState('')

  async function handleAdd() {
    if (!selected) return
    await onAssign(selected)
    setSelected('')
  }

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
      <h3 className="font-display text-base text-white">{title}</h3>
      <p className="text-xs text-text-tertiary mt-0.5 mb-4">{description}</p>

      <div className="flex items-end gap-2 mb-4">
        <div className="flex-1">
          <FormSelect
            options={assignable.map((s) => ({ value: s.id!, label: s.name, description: s.description }))}
            value={selected}
            onChange={setSelected}
            placeholder="Select a scope to add"
          />
        </div>
        <button
          onClick={handleAdd}
          disabled={!selected}
          className="h-11 px-4 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Add
        </button>
      </div>

      {isLoading ? (
        <Spinner />
      ) : !scopes || scopes.length === 0 ? (
        <p className="text-sm text-text-tertiary py-2">No scopes assigned.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {scopes.map((scope) => (
            <div
              key={scope.id ?? scope.name}
              className="flex items-center justify-between px-3 py-2 bg-surface-card border border-border-custom rounded-lg"
            >
              <div className="min-w-0">
                <div className="text-sm text-text-primary truncate">{scope.name}</div>
                {scope.description && (
                  <div className="text-[11px] text-text-tertiary truncate">{scope.description}</div>
                )}
              </div>
              <button
                onClick={() => onRemove(scope.id!)}
                className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors shrink-0"
                aria-label={`Remove scope ${scope.name}`}
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
