// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { FormEvent, useEffect, useState } from 'react'
import { KeyRound, ShieldCheck, Fingerprint, CheckCircle2, CircleDashed } from 'lucide-react'
import {
  accountChangePassword,
  accountGetCredentials,
  accountTotpDelete,
  accountTotpStart,
  accountTotpVerify,
  accountWebauthnDeleteCredential,
  accountWebauthnListCredentials,
  accountWebauthnRegisterFinish,
  accountWebauthnRegisterStart,
} from '@generated'
import type {
  AccountCredentialsResponse,
  AccountPasskeyResponse,
  TotpStartResponse,
} from '@generated'
import { AccountApiError, unwrap } from '../api/errors'
import { getAccountRealm } from '../../config'
import type { WebAuthnCreationOptionsJSON } from '../webauthn'
import { attestationToJSON, creationOptionsFromJSON } from '../webauthn'
import Spinner from '../../components/ui/Spinner'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'

const CREDENTIAL_TYPES = [
  { key: 'password', label: 'Password', icon: KeyRound },
  { key: 'totp', label: 'TOTP', icon: ShieldCheck },
  { key: 'webauthn', label: 'WebAuthn', icon: Fingerprint },
] as const

/** Group a base32 secret into chunks of 4 for manual entry. */
function groupSecret(secret: string): string {
  return secret.match(/.{1,4}/g)?.join(' ') ?? secret
}

export default function PasswordPage() {
  const [credentials, setCredentials] = useState<AccountCredentialsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const [saving, setSaving] = useState(false)
  const [confirmError, setConfirmError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [policyViolations, setPolicyViolations] = useState<string[]>([])
  const [saved, setSaved] = useState(false)

  // TOTP enrollment state
  const [totpEnrollment, setTotpEnrollment] = useState<TotpStartResponse | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [totpBusy, setTotpBusy] = useState(false)
  const [totpError, setTotpError] = useState('')
  const [totpConfirmingRemove, setTotpConfirmingRemove] = useState(false)

  // Passkey (WebAuthn) state
  const [passkeys, setPasskeys] = useState<AccountPasskeyResponse[]>([])
  const [passkeysError, setPasskeysError] = useState('')
  const [passkeyLabel, setPasskeyLabel] = useState('')
  const [registering, setRegistering] = useState(false)
  const [deletingPasskey, setDeletingPasskey] = useState<string | null>(null)

  const webauthnSupported =
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    !!navigator.credentials

  async function refreshCredentials() {
    const data = unwrap(await accountGetCredentials({ path: { realm: getAccountRealm() } }))
    setCredentials(data)
  }

  function loadPasskeys() {
    return accountWebauthnListCredentials({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((data) => setPasskeys(data))
      .catch((err) => setPasskeysError(err.message))
  }

  useEffect(() => {
    accountGetCredentials({ path: { realm: getAccountRealm() } })
      .then(unwrap)
      .then((data) => {
        setCredentials(data)
        setLoading(false)
      })
      .catch((err) => {
        setLoadError(err.message)
        setLoading(false)
      })
    loadPasskeys()
  }, [])

  async function handleTotpStart() {
    setTotpError('')
    setTotpBusy(true)
    try {
      const data = await accountTotpStart({ path: { realm: getAccountRealm() } }).then(unwrap)
      setTotpEnrollment(data)
      setTotpCode('')
    } catch (err: any) {
      setTotpError(err.message || 'Failed to start authenticator setup')
    } finally {
      setTotpBusy(false)
    }
  }

  async function handleTotpVerify(e: FormEvent) {
    e.preventDefault()
    setTotpError('')
    setTotpBusy(true)
    try {
      await accountTotpVerify({
        path: { realm: getAccountRealm() },
        body: { code: totpCode.trim() },
      }).then(unwrap)
      setTotpEnrollment(null)
      setTotpCode('')
      await refreshCredentials()
    } catch (err: any) {
      setTotpError(err.message || 'Failed to verify the code')
    } finally {
      setTotpBusy(false)
    }
  }

  async function handleTotpRemove() {
    setTotpError('')
    setTotpBusy(true)
    try {
      await accountTotpDelete({ path: { realm: getAccountRealm() } }).then(unwrap)
      setTotpConfirmingRemove(false)
      await refreshCredentials()
    } catch (err: any) {
      setTotpError(err.message || 'Failed to remove the authenticator')
    } finally {
      setTotpBusy(false)
    }
  }

  async function handleRegisterPasskey() {
    setPasskeysError('')
    setRegistering(true)
    try {
      const label = passkeyLabel.trim()
      const options = unwrap(
        await accountWebauthnRegisterStart({ path: { realm: getAccountRealm() } }),
      ) as WebAuthnCreationOptionsJSON
      const publicKey = creationOptionsFromJSON(options)
      const credential = (await navigator.credentials.create({
        publicKey,
      })) as PublicKeyCredential | null
      if (!credential) throw new Error('Passkey registration was cancelled')
      await accountWebauthnRegisterFinish({
        path: { realm: getAccountRealm() },
        body: { label, credential: attestationToJSON(credential) },
      }).then(unwrap)
      setPasskeyLabel('')
      await loadPasskeys()
    } catch (err: any) {
      setPasskeysError(err.message || 'Failed to register the passkey')
    } finally {
      setRegistering(false)
    }
  }

  async function handleDeletePasskey(id: string) {
    setPasskeysError('')
    setDeletingPasskey(id)
    try {
      await accountWebauthnDeleteCredential({ path: { realm: getAccountRealm(), id } }).then(unwrap)
      await loadPasskeys()
    } catch (err: any) {
      setPasskeysError(err.message || 'Failed to delete the passkey')
    } finally {
      setDeletingPasskey(null)
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSaveError('')
    setPolicyViolations([])
    setSaved(false)

    if (newPassword !== confirmPassword) {
      setConfirmError('Passwords do not match')
      return
    }
    setConfirmError('')
    setSaving(true)

    try {
      await accountChangePassword({
        path: { realm: getAccountRealm() },
        body: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      }).then(unwrap)
      setSaved(true)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      // A password now exists even if it was not enrolled before.
      setCredentials((prev) => (prev ? { ...prev, password: true } : prev))
    } catch (err: any) {
      const violations = (err as AccountApiError).policyViolations
      if (violations && violations.length > 0) {
        setPolicyViolations(violations.map((v) => v.message))
      } else {
        setSaveError(err.message || 'Failed to change password')
      }
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

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="font-display text-2xl text-foreground font-bold">Security</h1>

      <div className="bg-card border border-border rounded-xl p-6">
        <h2 className="text-sm font-medium text-muted-foreground mb-4">Credentials</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {CREDENTIAL_TYPES.map(({ key, label, icon: Icon }) => {
            const present = credentials?.[key] ?? false
            return (
              <div
                key={key}
                className="flex items-center gap-3 rounded-lg border border-border px-4 py-3"
              >
                <Icon className="w-5 h-5 text-muted-foreground shrink-0" />
                <span className="flex-1 text-sm text-foreground">{label}</span>
                {present ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-em-600 dark:text-em-400">
                    <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                    Set up
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                    <CircleDashed className="w-3.5 h-3.5" aria-hidden="true" />
                    Not set up
                  </span>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl p-6">
        <h2 className="text-sm font-medium text-muted-foreground mb-4">Change Password</h2>

        {saved && (
          <div className="mb-4 rounded-lg border border-em-500/20 bg-em-500/10 px-4 py-3 text-sm text-em-600 dark:text-em-400">
            Password changed.
          </div>
        )}
        {policyViolations.length > 0 && (
          <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            <p className="mb-1">The new password does not meet the password policy:</p>
            <ul className="list-disc pl-5 space-y-0.5">
              {policyViolations.map((message) => (
                <li key={message}>{message}</li>
              ))}
            </ul>
          </div>
        )}
        {saveError && (
          <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {saveError}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Current password"
            name="current_password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
          <Input
            label="New password"
            name="new_password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            autoComplete="new-password"
          />
          <Input
            label="Confirm new password"
            name="confirm_password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            autoComplete="new-password"
            error={confirmError}
          />
          <div className="pt-2">
            <Button type="submit" loading={saving}>
              Change Password
            </Button>
          </div>
        </form>
      </div>

      <div className="bg-card border border-border rounded-xl p-6">
        <h2 className="text-sm font-medium text-muted-foreground mb-4">Authenticator app</h2>

        {totpError && (
          <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {totpError}
          </div>
        )}

        {credentials?.totp ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              An authenticator app is configured for your account.
            </p>
            {totpConfirmingRemove ? (
              <div className="rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 space-y-3">
                <p className="text-sm text-destructive">
                  Remove the authenticator app? You will no longer be able to sign in with it.
                </p>
                <div className="flex gap-2">
                  <Button variant="danger" size="sm" onClick={handleTotpRemove} loading={totpBusy}>
                    Confirm remove
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setTotpConfirmingRemove(false)}
                    disabled={totpBusy}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => {
                    setTotpError('')
                    setTotpConfirmingRemove(true)
                  }}
                >
                  Remove
                </Button>
              </div>
            )}
          </div>
        ) : totpEnrollment ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Scan this QR code with your authenticator app, then enter the 6-digit code it
              shows.
            </p>
            {/* The SVG is generated by our own server (no user input), so a
                scoped innerHTML wrapper is safe here. */}
            <div
              data-testid="totp-qr"
              className="bg-white rounded-lg p-4 w-fit"
              dangerouslySetInnerHTML={{ __html: totpEnrollment.qrSvg }}
            />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                Can't scan? Enter this setup key manually
              </p>
              <code className="block font-mono text-sm text-foreground bg-muted rounded-md px-3 py-2 break-all">
                {groupSecret(totpEnrollment.secret)}
              </code>
              <a
                href={totpEnrollment.otpauthUrl}
                className="mt-1.5 inline-block text-xs text-primary hover:underline break-all"
              >
                Open in authenticator app
              </a>
            </div>
            <form onSubmit={handleTotpVerify} className="space-y-4">
              <Input
                label="6-digit code"
                name="totp_code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                required
              />
              <div className="flex gap-2 pt-1">
                <Button type="submit" loading={totpBusy}>
                  Verify
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setTotpEnrollment(null)
                    setTotpCode('')
                    setTotpError('')
                  }}
                  disabled={totpBusy}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Use an authenticator app to generate one-time codes for signing in.
            </p>
            <div>
              <Button variant="outline" size="sm" onClick={handleTotpStart} loading={totpBusy}>
                Set up authenticator app
              </Button>
            </div>
          </div>
        )}
      </div>

      <div className="bg-card border border-border rounded-xl p-6">
        <h2 className="text-sm font-medium text-muted-foreground mb-4">Passkeys</h2>

        {passkeysError && (
          <div className="mb-4 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {passkeysError}
          </div>
        )}

        {passkeys.length === 0 ? (
          <p className="text-sm text-muted-foreground mb-4">No passkeys registered yet.</p>
        ) : (
          <ul className="mb-4 divide-y divide-border rounded-lg border border-border">
            {passkeys.map((passkey) => (
              <li key={passkey.id} className="flex items-center gap-3 px-4 py-3">
                <Fingerprint className="w-4 h-4 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground truncate">{passkey.label || 'Passkey'}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {new Date(passkey.createdAt).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => handleDeletePasskey(passkey.id)}
                  disabled={deletingPasskey === passkey.id}
                  className="px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors border border-destructive/20 hover:border-destructive/40 disabled:opacity-50"
                >
                  {deletingPasskey === passkey.id ? 'Deleting...' : 'Delete'}
                </button>
              </li>
            ))}
          </ul>
        )}

        {webauthnSupported ? (
          <div className="space-y-3">
            <Input
              label="Passkey label (optional)"
              name="passkey_label"
              value={passkeyLabel}
              onChange={(e) => setPasskeyLabel(e.target.value)}
              placeholder="e.g. MacBook Touch ID"
            />
            <div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleRegisterPasskey}
                loading={registering}
              >
                Register passkey
              </Button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Passkeys are not supported in this browser.
          </p>
        )}
      </div>
    </div>
  )
}
