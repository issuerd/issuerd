// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useState } from 'react'
import { Link2 } from 'lucide-react'
import {
  accountLinkIdentity,
  accountListLinkedAccounts,
  accountUnlinkIdentity,
  loginContext,
} from '@generated'
import type { LinkedAccountResponse, LoginContextIdp } from '@generated'
import { unwrap } from '../api/errors'
import { getAccountRealm } from '../../config'
import Spinner from '../../components/ui/Spinner'
import { Table, Thead, Tbody, Tr, Th, Td } from '../../components/ui/Table'

const LINK_ERROR_MESSAGES: Record<string, string> = {
  'already-linked': 'This provider account is already linked to another user',
  'link-session-mismatch': 'Sign-in session mismatch — please try again',
  'link-failed': 'Linking failed — please try again',
}

export default function LinkedAccountsPage() {
  const [linked, setLinked] = useState<LinkedAccountResponse[]>([])
  const [available, setAvailable] = useState<LoginContextIdp[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [unlinking, setUnlinking] = useState<string | null>(null)
  const [linking, setLinking] = useState<string | null>(null)

  function loadLinked() {
    setLoading(true)
    accountListLinkedAccounts({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((data) => {
        setLinked(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }

  useEffect(() => {
    loadLinked()
    // The login context also drives the "available to link" list; a failure
    // there simply hides the section (the linked table still works).
    loginContext({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((ctx) => setAvailable(ctx.identity_providers ?? []))
      .catch(() => setAvailable([]))
  }, [])

  // The browser lands here after the external link ceremony with a
  // `linked` / `error` query param — show the outcome once, then strip it.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const linkedAlias = params.get('linked')
    const linkError = params.get('error')
    if (linkedAlias) {
      setNotice('Account linked')
    } else if (linkError) {
      setError(LINK_ERROR_MESSAGES[linkError] ?? LINK_ERROR_MESSAGES['link-failed'])
    }
    if (linkedAlias || linkError) {
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  const linkedAliases = new Set(linked.map((l) => l.alias))
  const linkable = available.filter((p) => !linkedAliases.has(p.alias))

  async function handleLink(alias: string) {
    setLinking(alias)
    setError('')
    try {
      const res = await accountLinkIdentity({ path: { realm: getAccountRealm(), alias } }).then(unwrap)
      window.location.href = res.redirect_url
    } catch (err: any) {
      setError(err.message)
      setLinking(null)
    }
  }

  async function handleUnlink(account: LinkedAccountResponse) {
    if (!window.confirm(`Unlink ${account.display_name || account.alias}?`)) return
    setUnlinking(account.alias)
    setError('')
    try {
      await accountUnlinkIdentity({
        path: { realm: getAccountRealm(), alias: account.alias },
      }).then(unwrap)
      loadLinked()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setUnlinking(null)
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
      <h1 className="font-display text-2xl text-foreground font-bold mb-6">Linked Accounts</h1>

      {notice && (
        <div className="mb-4 rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-3 text-sm text-green-500">
          {notice}
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {linked.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-8 text-center">
          <Link2 className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">
            You have not linked any external accounts yet.
          </p>
        </div>
      ) : (
        <Table>
          <Thead>
            <Tr>
              <Th>Provider</Th>
              <Th>External account</Th>
              <Th>Linked</Th>
              <Th align="right"> </Th>
            </Tr>
          </Thead>
          <Tbody>
            {linked.map((account) => (
              <Tr key={account.alias}>
                <Td className="font-medium text-foreground">
                  {account.display_name || account.alias}
                </Td>
                <Td className="text-muted-foreground">{account.external_username}</Td>
                <Td className="whitespace-nowrap text-muted-foreground">
                  {new Date(account.created_at).toLocaleString()}
                </Td>
                <Td align="right">
                  <button
                    onClick={() => handleUnlink(account)}
                    disabled={unlinking === account.alias}
                    className="px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors border border-destructive/20 hover:border-destructive/40 disabled:opacity-50"
                  >
                    {unlinking === account.alias ? 'Unlinking...' : 'Unlink'}
                  </button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}

      {linkable.length > 0 && (
        <div className="mt-8">
          <h2 className="font-display text-lg text-foreground font-semibold mb-4">
            Available to link
          </h2>
          <div className="bg-card border border-border rounded-xl divide-y divide-border">
            {linkable.map((provider) => (
              <div key={provider.alias} className="flex items-center justify-between px-4 py-3">
                <span className="text-sm font-medium text-foreground">
                  {provider.display_name || provider.alias}
                </span>
                <button
                  onClick={() => handleLink(provider.alias)}
                  disabled={linking === provider.alias}
                  className="px-3 py-1.5 text-xs font-medium text-foreground hover:bg-muted rounded-lg transition-colors border border-border disabled:opacity-50"
                >
                  {linking === provider.alias ? 'Redirecting...' : 'Link'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
