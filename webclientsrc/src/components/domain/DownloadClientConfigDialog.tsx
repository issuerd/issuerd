// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import Modal from '../ui/Modal'
import FormSelect from '../ui/FormSelect'
import FormTextarea from '../ui/FormTextarea'
import Spinner from '../ui/Spinner'
import ErrorMessage from '../ui/ErrorMessage'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useClientInstallation } from '../../api/hooks/useClients'

interface DownloadClientConfigDialogProps {
  open: boolean
  onClose: () => void
  realm: string
  /** Internal client UUID. */
  clientId: string
  /** Client protocol; available formats are filtered by it. */
  protocol?: string
}

/**
 * Keycloak's "Download adapter config" dialog: pick an installation format
 * (from serverinfo `client_installations`), preview the rendered client
 * configuration, and download it as a file.
 */
export default function DownloadClientConfigDialog({
  open,
  onClose,
  realm,
  clientId,
  protocol = 'openid-connect',
}: DownloadClientConfigDialogProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const providers = useMemo(
    () => (serverInfo?.client_installations ?? []).filter((p) => p.protocol === protocol),
    [serverInfo, protocol]
  )
  const [selected, setSelected] = useState('')
  const selectedProvider = providers.find((p) => p.id === selected) ?? providers[0]

  const {
    data: config,
    isLoading,
    error,
  } = useClientInstallation(realm, clientId, selectedProvider?.id ?? '', open && !!selectedProvider)

  const snippet = config ? JSON.stringify(config, null, 2) : ''

  function handleDownload() {
    if (!snippet || !selectedProvider) return
    const blob = new Blob([snippet], { type: selectedProvider.media_type })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = selectedProvider.filename
    anchor.click()
    URL.revokeObjectURL(url)
    onClose()
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Download Adapter Config"
      footer={
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
          >
            Cancel
          </button>
          <button
            onClick={handleDownload}
            disabled={!snippet}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Download
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        <FormSelect
          label="Format"
          options={providers.map((p) => ({
            value: p.id,
            label: p.display_type,
            description: p.help_text,
          }))}
          value={selectedProvider?.id}
          onChange={setSelected}
          disabled={infoLoading || providers.length === 0}
        />
        {isLoading && <Spinner />}
        {error && <ErrorMessage message={error.message} />}
        {!isLoading && !error && selectedProvider && (
          <FormTextarea label="Details" monospace readOnly rows={14} value={snippet} />
        )}
      </div>
    </Modal>
  )
}
