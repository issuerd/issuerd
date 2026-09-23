// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Download, Copy, Check, ShieldAlert } from 'lucide-react'
import { useExportRealm, usePushRevocation } from '../../api/hooks/useRealmAdminActions'
import { toast } from '../../stores/toastStore'
import FormSection from '@/components/ui/FormSection'
import Button from '@/components/ui/Button'
import Modal from '@/components/ui/Modal'
import ErrorMessage from '@/components/ui/ErrorMessage'
import ConfirmActionModal from './ConfirmActionModal'

interface RealmActionsSectionProps {
  /** Realm name (URL segment). */
  realm: string
}

/**
 * Realm maintenance actions: full realm export rendered as
 * pretty-printed JSON in a modal (copyable / downloadable), and the revocation
 * push that notifies clients of the realm's not-before cutoff.
 */
export default function RealmActionsSection({ realm }: RealmActionsSectionProps) {
  const exportRealm = useExportRealm()
  const pushRevocation = usePushRevocation()

  const [exportJson, setExportJson] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [pushConfirmOpen, setPushConfirmOpen] = useState(false)

  async function handleExport() {
    setExportError(null)
    try {
      const data = await exportRealm.mutateAsync(realm)
      setExportJson(JSON.stringify(data, null, 2))
    } catch (err) {
      setExportError((err as Error).message)
    }
  }

  async function handleCopy() {
    if (!exportJson) return
    try {
      await navigator.clipboard.writeText(exportJson)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast({ title: 'Copy failed', message: 'Clipboard access denied', type: 'error' })
    }
  }

  async function handlePushConfirm() {
    try {
      await pushRevocation.mutateAsync(realm)
      setPushConfirmOpen(false)
    } catch {
      // Failure is surfaced by the mutation's error toast; keep the modal open.
    }
  }

  const downloadHref = exportJson
    ? `data:application/json,${encodeURIComponent(exportJson)}`
    : undefined

  return (
    <>
      <FormSection
        title="Export"
        description="Download a full JSON snapshot of the realm (no secret material)"
        sectionId="realm-actions-export"
      >
        <div className="flex items-center gap-3">
          <Button type="button" size="sm" loading={exportRealm.isPending} onClick={handleExport}>
            <Download className="w-4 h-4 mr-1" />
            Export realm
          </Button>
          {exportError && <ErrorMessage message={exportError} />}
        </div>
      </FormSection>

      <FormSection
        title="Push Revocation"
        description="Notify clients of the realm's revocation cutoff (not-before)"
        sectionId="realm-actions-push-revocation"
      >
        <div>
          <Button
            type="button"
            variant="danger"
            size="sm"
            onClick={() => setPushConfirmOpen(true)}
          >
            <ShieldAlert className="w-4 h-4 mr-1" />
            Push revocation
          </Button>
        </div>
      </FormSection>

      <Modal
        open={exportJson !== null}
        onClose={() => setExportJson(null)}
        title={`Realm export — ${realm}`}
        className="max-w-3xl"
        footer={
          <div className="flex justify-end gap-3">
            <Button type="button" variant="ghost" size="sm" onClick={handleCopy}>
              {copied ? (
                <Check className="w-4 h-4 mr-1" />
              ) : (
                <Copy className="w-4 h-4 mr-1" />
              )}
              {copied ? 'Copied' : 'Copy to clipboard'}
            </Button>
            {downloadHref && (
              <a href={downloadHref} download={`${realm}-export.json`}>
                <Button type="button" variant="secondary" size="sm">
                  <Download className="w-4 h-4 mr-1" />
                  Download JSON
                </Button>
              </a>
            )}
          </div>
        }
      >
        <pre className="text-xs font-mono text-text-primary bg-surface-card border border-border-custom rounded-lg p-3 overflow-auto max-h-96 whitespace-pre">
          {exportJson}
        </pre>
      </Modal>

      <ConfirmActionModal
        open={pushConfirmOpen}
        onClose={() => setPushConfirmOpen(false)}
        onConfirm={handlePushConfirm}
        loading={pushRevocation.isPending}
        title="Push revocation"
        description="Push the realm's revocation cutoff (not-before) to all clients with a revocation channel. Tokens issued before the cutoff are rejected. Continue?"
        confirmLabel="Push"
      />
    </>
  )
}
