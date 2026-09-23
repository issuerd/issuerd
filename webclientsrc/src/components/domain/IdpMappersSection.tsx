// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { IdpMapper, IdpMapperType } from '@generated'
import {
  useIdpMappers,
  useCreateIdpMapper,
  useUpdateIdpMapper,
  useDeleteIdpMapper,
} from '../../api/hooks/useIdentityProviders'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormContextLine from '../ui/FormContextLine'
import Modal from '../ui/Modal'
import Spinner from '../ui/Spinner'
import ErrorMessage from '../ui/ErrorMessage'
import { Table, Thead, Tbody, Tr, Th, Td } from '../ui/Table'
import EnumBadge from '../ui/EnumBadge'

interface IdpMappersSectionProps {
  realm: string
  alias: string
}

/** Config keys relevant to each mapper type (backend contract). */
const MAPPER_CONFIG_KEYS: Record<IdpMapperType, { key: string; label: string; placeholder: string }[]> = {
  attribute: [
    { key: 'claim', label: 'Claim', placeholder: 'email' },
    { key: 'attribute', label: 'User Attribute', placeholder: 'external_email' },
  ],
  role: [
    { key: 'claim', label: 'Claim', placeholder: 'groups' },
    { key: 'claim_value', label: 'Claim Value', placeholder: 'admins' },
    { key: 'role', label: 'Role', placeholder: 'realm-admin' },
  ],
  username_template: [
    { key: 'template', label: 'Template', placeholder: '${ALIAS}.${CLAIM.email}' },
  ],
}

export default function IdpMappersSection({ realm, alias }: IdpMappersSectionProps) {
  const { data: mappers, isLoading, error } = useIdpMappers(realm, alias)
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const create = useCreateIdpMapper()
  const update = useUpdateIdpMapper()
  const remove = useDeleteIdpMapper()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<IdpMapper | null>(null)
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

  function openEdit(mapper: IdpMapper) {
    setEditing(mapper)
    setFormName(mapper.name)
    setFormType(mapper.mapper_type)
    setFormConfig({ ...(mapper.config ?? {}) })
    setFormError('')
    setDialogOpen(true)
  }

  function changeType(type: string) {
    setFormType(type)
    setFormConfig({})
  }

  async function handleSave() {
    setFormError('')
    const body: IdpMapper = {
      name: formName.trim(),
      mapper_type: formType as IdpMapperType,
      config: Object.fromEntries(Object.entries(formConfig).filter(([, v]) => v !== '')),
    }
    try {
      if (editing) {
        await update.mutateAsync({ realm, alias, name: editing.name, body })
      } else {
        await create.mutateAsync({ realm, alias, body })
      }
      setDialogOpen(false)
    } catch (err: any) {
      setFormError(err.message)
    }
  }

  async function handleDelete(mapper: IdpMapper) {
    if (!window.confirm(`Delete mapper "${mapper.name}"?`)) return
    await remove.mutateAsync({ realm, alias, name: mapper.name })
  }

  const configKeys = (MAPPER_CONFIG_KEYS as Record<string, typeof MAPPER_CONFIG_KEYS[IdpMapperType]>)[formType] ?? []
  const saving = create.isPending || update.isPending

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl p-6 max-w-2xl mt-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-display text-lg text-white">Mappers</h2>
          <p className="text-xs text-text-tertiary mt-0.5">
            Claim-mapping rules applied to identities from this provider.
          </p>
        </div>
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
        <p className="text-sm text-text-tertiary py-4 text-center">
          No mappers configured for this provider.
        </p>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Type</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {mappers.map((mapper) => (
              <Tr key={mapper.name}>
                <Td className="font-medium text-foreground">{mapper.name}</Td>
                <Td>
                  <EnumBadge enumList={serverInfo?.idp_mapper_types} value={mapper.mapper_type} />
                </Td>
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
                      onClick={() => handleDelete(mapper)}
                      disabled={remove.isPending}
                      className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors disabled:opacity-50"
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
            placeholder="email-attribute"
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
            disabled={!!editing}
            required
          />

          <FormSelect
            label="Mapper Type"
            options={
              serverInfo?.idp_mapper_types.map((t) => ({
                value: t.id,
                label: t.name ?? t.id,
                description: t.description,
              })) ?? []
            }
            value={formType}
            onChange={changeType}
            placeholder={infoLoading ? 'Loading...' : 'Select mapper type'}
          />

          {configKeys.map((field) => (
            <div key={field.key} className="flex flex-col gap-1.5">
              <Input
                label={field.label}
                placeholder={field.placeholder}
                value={formConfig[field.key] ?? ''}
                onChange={(e) => setFormConfig({ ...formConfig, [field.key]: e.target.value })}
              />
              {field.key === 'template' && (
                <FormContextLine text="Template placeholders: ${ALIAS} expands to the provider alias, ${CLAIM.<name>} to a claim value (e.g. ${ALIAS}.${CLAIM.email})." />
              )}
            </div>
          ))}

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
    </div>
  )
}
