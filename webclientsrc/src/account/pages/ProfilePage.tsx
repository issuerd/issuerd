// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { FormEvent, useEffect, useState } from 'react'
import {
  accountGetMe,
  accountUpdateMe,
  loginContext as fetchLoginContext,
} from '@generated'
import type { AccountMeResponse, LoginContextResponse, UpdateMeRequest } from '@generated'
import { unwrap } from '../api/errors'
import { getAccountRealm } from '../../config'
import Spinner from '../../components/ui/Spinner'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'

export default function ProfilePage() {
  const [user, setUser] = useState<AccountMeResponse | null>(null)
  const [loginCtx, setLoginCtx] = useState<LoginContextResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [username, setUsername] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')

  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [saved, setSaved] = useState(false)
  const [verificationSent, setVerificationSent] = useState(false)

  useEffect(() => {
    // The login-context endpoint is public and may be missing on older
    // servers — degrade to a read-only username instead of failing the page.
    Promise.all([
      accountGetMe({ path: { realm: getAccountRealm() } }).then(unwrap),
      fetchLoginContext({ path: { realm: getAccountRealm() } })
        .then(unwrap)
        .catch(() => null),
    ])
      .then(([me, ctx]) => {
        setUser(me)
        setLoginCtx(ctx)
        setUsername(me.username)
        setFirstName(me.first_name ?? '')
        setLastName(me.last_name ?? '')
        setEmail(me.email ?? '')
        setLoading(false)
      })
      .catch((err) => {
        setLoadError(err.message)
        setLoading(false)
      })
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!user) return
    setSaving(true)
    setSaveError('')
    setSaved(false)
    setVerificationSent(false)

    const body: UpdateMeRequest = {
      first_name: firstName.trim() || null,
      last_name: lastName.trim() || null,
      email: email.trim() || null,
    }
    // Only send a username when it actually changed — realms that disallow
    // username edits reject any change attempt.
    if (username.trim() !== user.username) {
      body.username = username.trim()
    }

    try {
      const updated = await accountUpdateMe({ path: { realm: getAccountRealm() }, body }).then(unwrap)
      const emailChanged = (updated.email ?? null) !== (user.email ?? null)
      setUser(updated)
      setUsername(updated.username)
      setFirstName(updated.first_name ?? '')
      setLastName(updated.last_name ?? '')
      setEmail(updated.email ?? '')
      setSaved(true)
      // Changing the email clears email_verified server-side; the realm sends
      // a verification email when verify_email is enabled.
      setVerificationSent(
        emailChanged && !updated.email_verified && (loginCtx?.verify_email_enabled ?? false)
      )
    } catch (err: any) {
      setSaveError(err.message || 'Failed to update profile')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner />
      </div>
    )
  }

  if (loadError) {
    return (
      <div className="bg-card border border-destructive/30 rounded-xl p-6 text-destructive">
        {loadError}
      </div>
    )
  }

  if (!user) return null

  const editUsernameAllowed = loginCtx?.edit_username_allowed ?? false

  return (
    <div className="max-w-2xl">
      <h1 className="font-display text-2xl text-foreground font-bold mb-6">Personal Info</h1>

      <div className="bg-card border border-border rounded-xl p-6 space-y-6">
        {saved && (
          <div className="rounded-lg border border-em-500/20 bg-em-500/10 px-4 py-3 text-sm text-em-600 dark:text-em-400">
            Profile updated.
          </div>
        )}
        {verificationSent && (
          <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-600 dark:text-blue-400">
            Your email address changed. A verification email has been sent to the new address —
            please confirm it to restore the verified status.
          </div>
        )}
        {saveError && (
          <div className="rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {saveError}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Username"
            name="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            readOnly={!editUsernameAllowed}
            required
            autoComplete="username"
            helperText={
              editUsernameAllowed ? undefined : 'Username changes are not allowed in this realm'
            }
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="First name"
              name="first_name"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              autoComplete="given-name"
            />
            <Input
              label="Last name"
              name="last_name"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              autoComplete="family-name"
            />
          </div>
          <Input
            label="Email"
            name="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            helperText={
              user.email && !user.email_verified ? 'Email address is not verified' : undefined
            }
          />
          <div className="pt-2">
            <Button type="submit" loading={saving}>
              Save
            </Button>
          </div>
        </form>

        {user.roles.length > 0 && (
          <div className="pt-4 border-t border-border">
            <h3 className="text-sm font-medium text-muted-foreground mb-3">Roles</h3>
            <div className="flex flex-wrap gap-2">
              {user.roles.map((role) => (
                <span
                  key={role}
                  className="px-3 py-1 rounded-full text-xs font-medium bg-primary/10 text-primary border border-primary/20"
                >
                  {role}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
