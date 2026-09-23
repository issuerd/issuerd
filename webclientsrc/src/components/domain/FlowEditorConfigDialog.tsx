// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import type { AuthenticatorConfigRepresentation, AuthenticatorConfigRequest, FlowStageRepresentation } from '@generated'
import Input from '../ui/Input'
import Modal from '../ui/Modal'
import Spinner from '../ui/Spinner'

interface ConfigRow {
  key: string
  value: string
}

export interface FlowEditorConfigDialogProps {
  open: boolean
  onClose: () => void
  stage: FlowStageRepresentation | null
  /** `undefined` while loading, `null` when the stage has no config yet. */
  config: AuthenticatorConfigRepresentation | null | undefined
  configLoading: boolean
  /** Built-in flows reject all mutations server-side — the dialog is view-only. */
  readOnly?: boolean
  onCreate: (body: AuthenticatorConfigRequest) => Promise<unknown>
  onUpdate: (body: AuthenticatorConfigRequest) => Promise<unknown>
  onDelete: () => Promise<unknown>
  saving?: boolean
}

/**
 * Per-execution authenticator-config editor: alias plus free-form key/value
 * rows. Creates (POST) when the stage has no config, updates (PUT) when it
 * does, and can delete the config entirely.
 */
export default function FlowEditorConfigDialog({
  open,
  onClose,
  stage,
  config,
  configLoading,
  readOnly = false,
  onCreate,
  onUpdate,
  onDelete,
  saving = false,
}: FlowEditorConfigDialogProps) {
  const [alias, setAlias] = useState('')
  const [rows, setRows] = useState<ConfigRow[]>([])
  const [formError, setFormError] = useState('')

  useEffect(() => {
    if (!open || configLoading) return
    setFormError('')
    setAlias(config?.alias ?? '')
    setRows(
      Object.entries(config?.config ?? {}).map(([key, value]) => ({
        key,
        value: value == null ? '' : String(value),
      })),
    )
  }, [open, config, configLoading])

  const hasConfig = config != null

  function setRow(index: number, patch: Partial<ConfigRow>) {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  function removeRow(index: number) {
    setRows((prev) => prev.filter((_, i) => i !== index))
  }

  async function handleSave() {
    setFormError('')
    const body: AuthenticatorConfigRequest = {
      alias: alias.trim(),
      config: Object.fromEntries(
        rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value]),
      ),
    }
    try {
      if (hasConfig) {
        await onUpdate(body)
      } else {
        await onCreate(body)
      }
      onClose()
    } catch (err) {
      setFormError((err as Error).message)
    }
  }

  async function handleDelete() {
    setFormError('')
    try {
      await onDelete()
      onClose()
    } catch (err) {
      setFormError((err as Error).message)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={stage ? `Config: ${stage.authenticator}` : 'Authenticator Config'}
    >
      {configLoading ? (
        <Spinner />
      ) : (
        <div className="flex flex-col gap-4">
          {formError && (
            <div className="rounded-lg border border-alert-red/20 bg-alert-red/10 px-4 py-3 text-sm text-alert-red">
              {formError}
            </div>
          )}

          <Input
            label="Alias"
            placeholder="my-config"
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            disabled={readOnly}
            required
          />

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
                Config Entries
              </span>
              {!readOnly && (
                <button
                  type="button"
                  onClick={() => setRows((prev) => [...prev, { key: '', value: '' }])}
                  className="px-2 py-1 text-xs text-cyan-neon hover:bg-cyan-neon/10 rounded-lg transition-colors flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" /> Add Row
                </button>
              )}
            </div>

            {rows.length === 0 && (
              <p className="text-xs text-text-tertiary">No config entries.</p>
            )}

            {rows.map((row, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="key"
                  value={row.key}
                  onChange={(e) => setRow(i, { key: e.target.value })}
                  disabled={readOnly}
                  aria-label={`Config key ${i + 1}`}
                  className="h-9 flex-1 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none transition-all disabled:opacity-50"
                />
                <input
                  type="text"
                  placeholder="value"
                  value={row.value}
                  onChange={(e) => setRow(i, { value: e.target.value })}
                  disabled={readOnly}
                  aria-label={`Config value ${i + 1}`}
                  className="h-9 flex-1 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none transition-all disabled:opacity-50"
                />
                {!readOnly && (
                  <button
                    type="button"
                    onClick={() => removeRow(i)}
                    aria-label={`Remove config row ${i + 1}`}
                    className="p-1.5 text-text-secondary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
          </div>

          <div className="flex justify-between gap-3 pt-2">
            <div>
              {hasConfig && !readOnly && (
                <button
                  type="button"
                  onClick={handleDelete}
                  disabled={saving}
                  className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all disabled:opacity-50"
                >
                  Delete Config
                </button>
              )}
            </div>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
              >
                {readOnly ? 'Close' : 'Cancel'}
              </button>
              {!readOnly && (
                <button
                  type="button"
                  onClick={handleSave}
                  disabled={saving || !alias.trim()}
                  className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {saving ? 'Saving...' : 'Save'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </Modal>
  )
}
