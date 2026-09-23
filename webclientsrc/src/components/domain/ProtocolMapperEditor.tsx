// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { MapperType, ProtocolMapperRepresentation } from '@generated'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormSwitch from '../ui/FormSwitch'
import FormContextLine from '../ui/FormContextLine'
import Modal from '../ui/Modal'
import Spinner from '../ui/Spinner'
import ErrorMessage from '../ui/ErrorMessage'
import DeleteConfirmModal from './DeleteConfirmModal'
import EnumBadge from '../ui/EnumBadge'
import { Table, Thead, Tbody, Tr, Th, Td } from '../ui/Table'

/**
 * Config values for `jsonType.label` — a Keycloak mapper-config value domain,
 * not a backend enum (mapper config values are not exposed via serverinfo).
 */
const JSON_TYPES = ['String', 'long', 'double', 'boolean', 'JSON']

type MapperField =
  | { kind: 'text'; key: string; label: string; placeholder?: string }
  | { kind: 'switch'; key: string; label: string; defaultValue?: boolean }
  | { kind: 'jsonType' }

const TARGET_SWITCHES: MapperField[] = [
  { kind: 'switch', key: 'access.token.claim', label: 'Add to Access Token', defaultValue: true },
  { kind: 'switch', key: 'id.token.claim', label: 'Add to ID Token', defaultValue: true },
  { kind: 'switch', key: 'userinfo.token.claim', label: 'Add to UserInfo', defaultValue: true },
]

/** Config keys relevant to each protocol mapper type (backend contract). */
const MAPPER_FIELDS: Record<MapperType, MapperField[]> = {
  'oidc-usermodel-attribute-mapper': [
    { kind: 'text', key: 'user.attribute', label: 'User Attribute', placeholder: 'department' },
    { kind: 'text', key: 'claim.name', label: 'Claim Name', placeholder: 'department' },
    { kind: 'jsonType' },
    { kind: 'switch', key: 'multivalued', label: 'Multivalued' },
    ...TARGET_SWITCHES,
  ],
  'oidc-usermodel-property-mapper': [
    { kind: 'text', key: 'user.property', label: 'User Property', placeholder: 'email' },
    { kind: 'text', key: 'claim.name', label: 'Claim Name', placeholder: 'email' },
    { kind: 'jsonType' },
    ...TARGET_SWITCHES,
  ],
  'oidc-full-name-mapper': [...TARGET_SWITCHES],
  'oidc-address-mapper': [...TARGET_SWITCHES],
  'oidc-group-membership-mapper': [
    { kind: 'text', key: 'claim.name', label: 'Claim Name', placeholder: 'groups' },
    { kind: 'switch', key: 'full.path', label: 'Full Group Path' },
    ...TARGET_SWITCHES,
  ],
  'oidc-usermodel-realm-role-mapper': [
    { kind: 'text', key: 'claim.name', label: 'Claim Name', placeholder: 'realm_access.roles' },
    { kind: 'switch', key: 'multivalued', label: 'Multivalued', defaultValue: true },
    ...TARGET_SWITCHES,
  ],
  'oidc-usermodel-client-role-mapper': [
    { kind: 'text', key: 'usermodel.clientRoleMapping.clientId', label: 'Client ID', placeholder: 'my-client' },
    { kind: 'text', key: 'claim.name', label: 'Claim Name', placeholder: 'resource_access.${client_id}.roles' },
    { kind: 'switch', key: 'multivalued', label: 'Multivalued', defaultValue: true },
    ...TARGET_SWITCHES,
  ],
  'oidc-audience-mapper': [
    { kind: 'text', key: 'included.client.audience', label: 'Included Client Audience', placeholder: 'my-client' },
    { kind: 'text', key: 'included.custom.audience', label: 'Included Custom Audience', placeholder: 'https://api.example.com' },
    { kind: 'switch', key: 'access.token.claim', label: 'Add to Access Token', defaultValue: true },
    { kind: 'switch', key: 'id.token.claim', label: 'Add to ID Token', defaultValue: true },
  ],
  'oidc-allowed-origins-mapper': [],
}

function switchValue(config: Record<string, string>, key: string, defaultValue: boolean): boolean {
  const raw = config[key]
  if (raw === undefined) return defaultValue
  return raw === 'true'
}

export interface ProtocolMapperEditorProps {
  mappers: ProtocolMapperRepresentation[] | undefined
  isLoading: boolean
  error?: Error | null
  onCreate: (body: ProtocolMapperRepresentation) => Promise<unknown>
  onUpdate: (mapperId: string, body: ProtocolMapperRepresentation) => Promise<unknown>
  onDelete: (mapperId: string) => Promise<unknown>
  saving?: boolean
  deleting?: boolean
}

/**
 * Shared protocol-mapper list + editor. Used for client-local mappers and
 * client-scope mappers — the parent wires the domain hooks to the callbacks.
 */
export default function ProtocolMapperEditor({
  mappers,
  isLoading,
  error,
  onCreate,
  onUpdate,
  onDelete,
  saving = false,
  deleting = false,
}: ProtocolMapperEditorProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<ProtocolMapperRepresentation | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ProtocolMapperRepresentation | null>(null)
  const [formName, setFormName] = useState('')
  const [formType, setFormType] = useState('')
  const [formConfig, setFormConfig] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState('')

  function openAdd() {
    setEditing(null)
    setFormName('')
    setFormType('')
    setFormConfig({})
    setFormError('')
    setDialogOpen(true)
  }

  function openEdit(mapper: ProtocolMapperRepresentation) {
    setEditing(mapper)
    setFormName(mapper.name)
    setFormType(mapper.protocol_mapper)
    setFormConfig({ ...(mapper.config ?? {}) })
    setFormError('')
    setDialogOpen(true)
  }

  function changeType(type: string) {
    setFormType(type)
    setFormConfig({})
  }

  const fields = (MAPPER_FIELDS as Record<string, MapperField[]>)[formType] ?? []

  async function handleSave() {
    setFormError('')
    const config: Record<string, string> = {}
    for (const field of fields) {
      if (field.kind === 'text') {
        const value = (formConfig[field.key] ?? '').trim()
        if (value) config[field.key] = value
      } else if (field.kind === 'switch') {
        config[field.key] = switchValue(formConfig, field.key, field.defaultValue ?? false) ? 'true' : 'false'
      } else {
        const value = (formConfig['jsonType.label'] ?? '').trim()
        if (value) config['jsonType.label'] = value
      }
    }
    const body: ProtocolMapperRepresentation = {
      name: formName.trim(),
      protocol: 'openid-connect',
      protocol_mapper: formType as MapperType,
      config,
    }
    try {
      if (editing?.id) {
        await onUpdate(editing.id, body)
      } else {
        await onCreate(body)
      }
      setDialogOpen(false)
    } catch (err) {
      setFormError((err as Error).message)
    }
  }

  async function handleDelete() {
    if (!deleteTarget?.id) return
    await onDelete(deleteTarget.id)
    setDeleteTarget(null)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-text-tertiary">
          Claim mappings applied to tokens issued within this context.
        </p>
        <button
          onClick={openAdd}
          className="px-4 py-2 bg-cyan-neon/10 border border-cyan-neon/30 rounded-lg text-sm text-cyan-neon hover:bg-cyan-neon/20 transition-all flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Add Mapper
        </button>
      </div>

      {isLoading ? (
        <Spinner />
      ) : error ? (
        <ErrorMessage message={error.message} />
      ) : !mappers || mappers.length === 0 ? (
        <p className="text-sm text-text-tertiary py-4 text-center">No mappers configured.</p>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Type</Th>
              <Th>Claim Name</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {mappers.map((mapper) => (
              <Tr key={mapper.id ?? mapper.name}>
                <Td className="font-medium text-foreground">{mapper.name}</Td>
                <Td>
                  <EnumBadge enumList={serverInfo?.mapper_types} value={mapper.protocol_mapper} />
                </Td>
                <Td className="text-text-secondary">{mapper.config?.['claim.name'] || '—'}</Td>
                <Td align="right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => openEdit(mapper)}
                      className="p-1.5 text-text-secondary hover:text-cyan-neon hover:bg-cyan-neon/10 rounded-lg transition-colors"
                      aria-label={`Edit mapper ${mapper.name}`}
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setDeleteTarget(mapper)}
                      className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors"
                      aria-label={`Delete mapper ${mapper.name}`}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}

      <Modal
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        title={editing ? 'Edit Mapper' : 'Add Mapper'}
      >
        <div className="flex flex-col gap-4">
          {formError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {formError}
            </div>
          )}

          <Input
            label="Name"
            placeholder="department-attribute"
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
            required
          />

          <FormSelect
            label="Mapper Type"
            options={
              serverInfo?.mapper_types.map((t) => ({
                value: t.id,
                label: t.name ?? t.id,
                description: t.description,
              })) ?? []
            }
            value={formType}
            onChange={changeType}
            placeholder={infoLoading ? 'Loading...' : 'Select mapper type'}
            disabled={!!editing}
          />
          {formType && (
            <FormContextLine
              text={serverInfo?.mapper_types.find((t) => t.id === formType)?.description}
            />
          )}

          {fields.map((field) => {
            if (field.kind === 'text') {
              return (
                <Input
                  key={field.key}
                  label={field.label}
                  placeholder={field.placeholder}
                  value={formConfig[field.key] ?? ''}
                  onChange={(e) => setFormConfig({ ...formConfig, [field.key]: e.target.value })}
                />
              )
            }
            if (field.kind === 'switch') {
              return (
                <FormSwitch
                  key={field.key}
                  label={field.label}
                  checked={switchValue(formConfig, field.key, field.defaultValue ?? false)}
                  onChange={(checked) =>
                    setFormConfig({ ...formConfig, [field.key]: checked ? 'true' : 'false' })
                  }
                />
              )
            }
            return (
              <FormSelect
                key="jsonType.label"
                label="Claim JSON Type"
                options={JSON_TYPES.map((t) => ({ value: t, label: t }))}
                value={formConfig['jsonType.label'] ?? ''}
                onChange={(v) => setFormConfig({ ...formConfig, 'jsonType.label': v })}
                placeholder="Select JSON type"
              />
            )
          })}

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setDialogOpen(false)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving || !formName.trim() || !formType}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </Modal>

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        loading={deleting}
      />
    </div>
  )
}
