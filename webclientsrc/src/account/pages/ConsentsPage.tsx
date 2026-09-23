// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useState } from 'react'
import { Link2 } from 'lucide-react'
import { accountDeleteConsent, accountListConsents } from '@generated'
import type { AccountConsentResponse } from '@generated'
import { unwrap } from '../api/errors'
import { getAccountRealm } from '../../config'
import Spinner from '../../components/ui/Spinner'
import { Table, Thead, Tbody, Tr, Th, Td } from '../../components/ui/Table'

export default function ConsentsPage() {
  const [consents, setConsents] = useState<AccountConsentResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revoking, setRevoking] = useState<string | null>(null)

  function loadConsents() {
    setLoading(true)
    accountListConsents({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((data) => {
        setConsents(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }

  useEffect(() => {
    loadConsents()
  }, [])

  async function handleRevoke(clientId: string) {
    setRevoking(clientId)
    setError('')
    try {
      await accountDeleteConsent({
        path: { realm: getAccountRealm(), client_id: clientId },
      }).then(unwrap)
      loadConsents()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setRevoking(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner />
      </div>
    )
  }

  return (
    <div className="max-w-3xl">
      <h1 className="font-display text-2xl text-foreground font-bold mb-6">Consents</h1>

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {consents.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-8 text-center">
          <Link2 className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">
            You have not granted access to any applications yet.
          </p>
        </div>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Application</Th>
              <Th>Granted scopes</Th>
              <Th>Last updated</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {consents.map((consent) => (
              <Tr key={consent.client_id}>
                <Td className="font-medium text-foreground">{consent.client_id}</Td>
                <Td>
                  <div className="flex flex-wrap gap-1.5">
                    {consent.granted_scopes.map((scope) => (
                      <span
                        key={scope}
                        className="px-2 py-0.5 rounded text-[11px] bg-muted text-muted-foreground border border-border"
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                </Td>
                <Td className="whitespace-nowrap text-muted-foreground">
                  {new Date(consent.last_updated_at).toLocaleString()}
                </Td>
                <Td align="right">
                  <button
                    onClick={() => handleRevoke(consent.client_id)}
                    disabled={revoking === consent.client_id}
                    className="px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors border border-destructive/20 hover:border-destructive/40 disabled:opacity-50"
                  >
                    {revoking === consent.client_id ? 'Revoking...' : 'Revoke'}
                  </button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </div>
  )
}
