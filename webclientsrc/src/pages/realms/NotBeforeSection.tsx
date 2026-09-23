// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { useUpdateRealm } from '../../api/hooks/useRealms'
import FormSection from '@/components/ui/FormSection'
import Button from '@/components/ui/Button'
import ConfirmActionModal from './ConfirmActionModal'
import type { RealmRepresentation } from '@generated'

interface NotBeforeSectionProps {
  /** Realm name (URL segment) — the PUT path parameter. */
  realmName: string
  /** Currently loaded realm, used as the base of the update payload. */
  realm: RealmRepresentation
}

/**
 * Revocation cutoff: displays the realm's `notBefore` timestamp and
 * offers "Set to now", which instantly invalidates every token issued before
 * the current second. Persists through the regular realm PUT.
 */
export default function NotBeforeSection({ realmName, realm }: NotBeforeSectionProps) {
  const update = useUpdateRealm()
  const [confirmOpen, setConfirmOpen] = useState(false)

  const notBefore = realm.notBefore ?? 0
  const display =
    notBefore > 0 ? new Date(notBefore * 1000).toLocaleString() : 'Not set — all tokens valid'

  async function handleSetToNow() {
    try {
      await update.mutateAsync({
        realm: realmName,
        body: { ...realm, notBefore: Math.floor(Date.now() / 1000) },
      })
      setConfirmOpen(false)
    } catch {
      // Failure is surfaced by the mutation's error toast; keep the modal open.
    }
  }

  return (
    <FormSection
      title="Revocation"
      description="Invalidate all tokens issued before a point in time"
      sectionId="realm-security-revocation"
      configuredCount={notBefore > 0 ? 1 : 0}
      totalCount={1}
    >
      <div className="flex flex-col gap-1.5">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Not Before
        </span>
        <span className="text-sm text-text-primary" data-testid="not-before-value">
          {display}
        </span>
        <span className="text-xs text-text-tertiary">
          Tokens and refresh requests issued before this time are rejected
        </span>
      </div>
      <div>
        <Button type="button" variant="danger" size="sm" onClick={() => setConfirmOpen(true)}>
          <ShieldAlert className="w-4 h-4 mr-1" />
          Set to now
        </Button>
      </div>

      <ConfirmActionModal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleSetToNow}
        loading={update.isPending}
        title="Set revocation cutoff to now"
        description="All tokens issued before this moment will stop working for every user of the realm. Active sessions are effectively revoked. Continue?"
        confirmLabel="Set to now"
      />
    </FormSection>
  )
}
