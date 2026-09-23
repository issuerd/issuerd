// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Globe, Save, ArrowLeft } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import { useRealm, useUpdateRealm, useTestSmtpConnection } from '../../api/hooks/useRealms'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import PageHeader from '@/components/layout/PageHeader'
import PageLoader from '@/components/ui/PageLoader'
import ErrorMessage from '@/components/ui/ErrorMessage'
import Button from '@/components/ui/Button'
import Input from '@/components/ui/Input'
import FormSwitch from '@/components/ui/FormSwitch'
import FormSelect from '@/components/ui/FormSelect'
import FormDuration from '@/components/ui/FormDuration'
import FormSection from '@/components/ui/FormSection'
import FormContextLine from '@/components/ui/FormContextLine'
import FormLabelWithTooltip from '@/components/ui/FormLabelWithTooltip'
import FlowBindingsSection from './FlowBindingsSection'
import EventsConfigSection from './EventsConfigSection'
import NotBeforeSection from './NotBeforeSection'
import DefaultGroupsSection from './DefaultGroupsSection'
import PartialImportSection from './PartialImportSection'
import RealmActionsSection from './RealmActionsSection'
import type { RealmRepresentation } from '@generated'

const TABS = [
  { id: 'general', label: 'General' },
  { id: 'localization', label: 'Localization' },
  { id: 'login', label: 'Login' },
  { id: 'email', label: 'Email' },
  { id: 'tokens', label: 'Tokens' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'security', label: 'Security' },
  { id: 'events', label: 'Events' },
  { id: 'actions', label: 'Actions' },
] as const

type TabId = (typeof TABS)[number]['id']

export default function RealmSettingsPage() {
  const navigate = useNavigate()
  const { realm: realmName } = useParams<{ realm: string }>()
  const currentRealm = useAuthStore((s) => s.currentRealm)
  const setRealm = useAuthStore((s) => s.setRealm)
  const [activeTab, setActiveTab] = useState<TabId>('general')

  const { data: realm, isLoading, error } = useRealm(realmName!)
  const update = useUpdateRealm()
  const testSmtp = useTestSmtpConnection()
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const [form, setForm] = useState<Partial<RealmRepresentation>>({})
  const [smtpTestEmail, setSmtpTestEmail] = useState('')
  const [smtpTestResult, setSmtpTestResult] = useState<{ ok: boolean; message: string } | null>(
    null
  )

  // Merge server data with local overrides
  const values: Partial<RealmRepresentation> = {
    ...realm,
    ...form,
  }

  const sslDesc = useEnumDescription(serverInfo?.ssl_required, values.ssl_required ?? 'external')
  const otpAlgDesc = useEnumDescription(
    serverInfo?.otp_algorithms,
    values.otpPolicyAlgorithm ?? 'HmacSHA1'
  )
  const defaultLocaleDesc = useEnumDescription(
    serverInfo?.locales,
    values.defaultLocale ?? null
  )

  function patch<K extends keyof RealmRepresentation>(key: K, value: RealmRepresentation[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  /** SMTP settings live in realm attributes under `smtpServer.*` (Keycloak model). */
  function smtpAttr(key: string): string {
    return values.attributes?.[`smtpServer.${key}`] ?? ''
  }

  function patchSmtp(key: string, value: string) {
    patch('attributes', { ...(values.attributes ?? {}), [`smtpServer.${key}`]: value })
  }

  function patchNumber(
    key:
      | 'maxLoginFailures'
      | 'waitIncrementSecs'
      | 'maxFailureWaitSecs'
      | 'lockoutDurationSecs'
      | 'otpPolicyDigits'
      | 'otpPolicyPeriod'
      | 'otpPolicyLookAheadWindow',
    raw: string
  ) {
    patch(key, raw === '' ? null : Number(raw))
  }

  async function handleTestSmtp() {
    setSmtpTestResult(null)
    try {
      await testSmtp.mutateAsync({ realm: realmName!, email: smtpTestEmail })
      setSmtpTestResult({ ok: true, message: `Test email sent to ${smtpTestEmail}.` })
    } catch (err) {
      setSmtpTestResult({ ok: false, message: (err as Error).message })
    }
  }

  async function handleSave() {
    if (!realm) return
    const payload: RealmRepresentation = {
      ...realm,
      ...form,
    }
    await update.mutateAsync({ realm: realmName!, body: payload })
    // If realm name changed, update current realm reference
    if (form.realm && form.realm !== realmName && form.realm === currentRealm) {
      setRealm(form.realm)
    }
  }

  const hasChanges = Object.keys(form).length > 0
  const bruteForceOn = values.bruteForceProtected ?? false
  const i18nOn = values.internationalizationEnabled ?? false

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!realm) return <ErrorMessage message="Realm not found" />

  const sslOptions =
    serverInfo?.ssl_required.map((s) => ({
      value: s.id,
      label: s.name ?? s.id,
      description: s.description,
    })) ?? []

  const otpAlgorithmOptions =
    serverInfo?.otp_algorithms.map((a) => ({
      value: a.id,
      label: a.name ?? a.id,
      description: a.description,
    })) ?? []

  // Dynamic enum rule: theme options come from `serverInfo.themes` (built-in
  // `issuerd` plus the server's themes directory scan). The leading empty
  // option maps to `null`, which the server resolves to the built-in theme.
  const themeOptions = [
    { value: '', label: 'Default', description: 'Built-in theme used when none is selected' },
    ...(serverInfo?.themes.map((t) => ({
      value: t.id,
      label: t.name ?? t.id,
      description: t.description,
    })) ?? []),
  ]

  const localeOptions =
    serverInfo?.locales.map((l) => ({
      value: l.id,
      label: l.name ?? l.id,
      description: l.description,
    })) ?? []

  // Default locale is offered only among the explicitly supported locales
  // (an empty supported list means unrestricted). A stored value outside the
  // supported set is still shown so it can be cleared.
  const supportedLocales = values.supportedLocales ?? []
  const defaultLocalePool =
    supportedLocales.length > 0
      ? localeOptions.filter((o) => supportedLocales.includes(o.value))
      : localeOptions
  const currentDefaultLocale = values.defaultLocale ?? ''
  const defaultLocaleOptions = [
    { value: '', label: 'Server default', description: 'Falls back to English when unset' },
    ...(currentDefaultLocale &&
    !defaultLocalePool.some((o) => o.value === currentDefaultLocale)
      ? [{ value: currentDefaultLocale, label: currentDefaultLocale }]
      : []),
    ...defaultLocalePool,
  ]

  function toggleSupportedLocale(id: string) {
    const current = values.supportedLocales ?? []
    patch(
      'supportedLocales',
      current.includes(id) ? current.filter((v) => v !== id) : [...current, id]
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Realm Settings"
        icon={Globe}
        breadcrumbs={[
          { label: 'Realms', to: '/realms' },
          { label: realmName! },
          { label: 'Settings' },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => navigate('/realms')}
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back
            </Button>
            <Button
              type="button"
              size="sm"
              loading={update.isPending}
              disabled={!hasChanges}
              onClick={handleSave}
            >
              <Save className="w-4 h-4 mr-1" />
              Save Changes
            </Button>
          </div>
        }
      />

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border-custom">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm font-medium transition-all relative ${
              activeTab === tab.id
                ? 'text-cyan-neon'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-neon rounded-full" />
            )}
          </button>
        ))}
      </div>

      {/* General Tab */}
      {activeTab === 'general' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="Basic Information"
            description="Realm identity and display"
            sectionId="realm-general-basic"
            configuredCount={
              [values.realm, values.display_name].filter(Boolean).length
            }
            totalCount={2}
          >
            <Input
              label="Realm Name"
              value={values.realm ?? ''}
              onChange={(e) => patch('realm', e.target.value)}
              helperText="Unique identifier used in URLs and API calls"
              copyable
            />
            <Input
              label="Display Name"
              value={values.display_name ?? ''}
              onChange={(e) => patch('display_name', e.target.value)}
              helperText="Human-readable name shown on login pages"
            />
          </FormSection>

          <FormSection
            title="Security"
            description="SSL and availability"
            sectionId="realm-general-security"
            configuredCount={[values.ssl_required].filter(Boolean).length}
            totalCount={1}
          >
            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="SSL Required"
                tooltipText="Controls whether HTTPS is required for all endpoints, only external requests, or not at all"
              />
              <FormSelect
                options={sslOptions}
                value={values.ssl_required ?? 'external'}
                onChange={(v) => patch('ssl_required', v as RealmRepresentation['ssl_required'])}
                placeholder={infoLoading ? 'Loading...' : 'Select SSL mode'}
                disabled={infoLoading}
              />
              <FormContextLine text={sslDesc?.description} />
            </div>
            <FormSwitch
              label="Enabled"
              helperText="Disabled realms cannot be accessed"
              checked={values.enabled ?? true}
              onChange={(v) => patch('enabled', v)}
            />
          </FormSection>

          <FormSection
            title="Themes"
            description="Visual appearance for realm-facing pages"
            sectionId="realm-general-themes"
            configuredCount={
              [values.login_theme, values.email_theme, values.admin_theme].filter(Boolean).length
            }
            totalCount={3}
          >
            <FormSelect
              label="Login Theme"
              options={themeOptions}
              value={values.login_theme ?? ''}
              onChange={(v) => patch('login_theme', v || null)}
              placeholder={infoLoading ? 'Loading...' : 'Select theme'}
              disabled={infoLoading}
              helperText="Theme used for the login UI"
            />
            <FormSelect
              label="Email Theme"
              options={themeOptions}
              value={values.email_theme ?? ''}
              onChange={(v) => patch('email_theme', v || null)}
              placeholder={infoLoading ? 'Loading...' : 'Select theme'}
              disabled={infoLoading}
              helperText="Theme used for email templates"
            />
            <FormSelect
              label="Admin Theme"
              options={themeOptions}
              value={values.admin_theme ?? ''}
              onChange={(v) => patch('admin_theme', v || null)}
              placeholder={infoLoading ? 'Loading...' : 'Select theme'}
              disabled={infoLoading}
              helperText="Theme used for the admin console"
            />
          </FormSection>

          <FlowBindingsSection realm={realmName!} values={values} onPatch={patch} />
        </div>
      )}

      {/* Localization Tab */}
      {activeTab === 'localization' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="Internationalization"
            description="Localized login pages and emails for this realm"
            sectionId="realm-localization-i18n"
            configuredCount={i18nOn ? 1 : 0}
            totalCount={1}
          >
            <FormSwitch
              label="Internationalization"
              helperText="Localize login pages and emails based on the negotiated user locale"
              checked={i18nOn}
              onChange={(v) => patch('internationalizationEnabled', v)}
            />

            <div className="flex flex-col gap-1.5">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Supported Locales
              </span>
              <div
                className={`flex flex-col gap-2 rounded-md border border-border-custom p-3 ${i18nOn ? '' : 'opacity-50'}`}
              >
                {infoLoading && <span className="text-xs text-text-tertiary">Loading...</span>}
                {!infoLoading && (serverInfo?.locales.length ?? 0) === 0 && (
                  <span className="text-xs text-text-tertiary">No locales available</span>
                )}
                {serverInfo?.locales.map((locale) => {
                  const checked = (values.supportedLocales ?? []).includes(locale.id)
                  return (
                    <label
                      key={locale.id}
                      className={`flex items-start gap-2 ${i18nOn ? 'cursor-pointer' : 'cursor-not-allowed'}`}
                      title={locale.description ?? undefined}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={!i18nOn}
                        onChange={() => toggleSupportedLocale(locale.id)}
                        className="mt-0.5 w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                      />
                      <span className="flex flex-col">
                        <span className="text-sm text-text-primary">
                          {locale.name ?? locale.id}
                        </span>
                        {locale.description && (
                          <span className="text-[11px] text-text-tertiary leading-tight">
                            {locale.description}
                          </span>
                        )}
                      </span>
                    </label>
                  )
                })}
              </div>
              <span className="text-xs text-text-tertiary">
                Locales this realm can render — no selection means every locale is allowed
              </span>
            </div>

            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="Default Locale"
                tooltipText="Locale used when the client does not negotiate one"
              />
              <FormSelect
                options={defaultLocaleOptions}
                value={currentDefaultLocale}
                onChange={(v) => patch('defaultLocale', v || null)}
                placeholder={infoLoading ? 'Loading...' : 'Select default locale'}
                disabled={infoLoading || !i18nOn}
              />
              <FormContextLine text={defaultLocaleDesc?.description} />
            </div>
          </FormSection>
        </div>
      )}

      {/* Login Tab */}
      {activeTab === 'login' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="Login Options"
            description="Realm-wide login and registration behavior"
            sectionId="realm-login-options"
            configuredCount={
              [
                values.registrationEnabled,
                values.resetPasswordAllowed,
                values.rememberMeEnabled,
                values.verifyEmailEnabled,
                values.loginWithEmailAllowed ?? true,
                values.duplicateEmailsAllowed,
                values.editUsernameAllowed ?? true,
              ].filter(Boolean).length
            }
            totalCount={7}
          >
            <FormSwitch
              label="User registration"
              helperText="Allow users to create accounts from the login page"
              checked={values.registrationEnabled ?? false}
              onChange={(v) => patch('registrationEnabled', v)}
            />
            <FormSwitch
              label="Forgot password"
              helperText="Show a password-reset link on the login page"
              checked={values.resetPasswordAllowed ?? false}
              onChange={(v) => patch('resetPasswordAllowed', v)}
            />
            <FormSwitch
              label="Remember me"
              helperText="Offer a remember-me checkbox that extends the SSO session"
              checked={values.rememberMeEnabled ?? false}
              onChange={(v) => patch('rememberMeEnabled', v)}
            />
            <FormSwitch
              label="Verify email"
              helperText="Require users to verify their email address after registration"
              checked={values.verifyEmailEnabled ?? false}
              onChange={(v) => patch('verifyEmailEnabled', v)}
            />
            <FormSwitch
              label="Login with email"
              helperText="Allow users to log in with their email address instead of username"
              checked={values.loginWithEmailAllowed ?? true}
              onChange={(v) => patch('loginWithEmailAllowed', v)}
            />
            <FormSwitch
              label="Duplicate emails"
              helperText="Allow multiple accounts to share the same email address"
              checked={values.duplicateEmailsAllowed ?? false}
              onChange={(v) => patch('duplicateEmailsAllowed', v)}
            />
            <FormSwitch
              label="Edit username"
              helperText="Allow users to change their own username"
              checked={values.editUsernameAllowed ?? true}
              onChange={(v) => patch('editUsernameAllowed', v)}
            />
          </FormSection>
        </div>
      )}

      {/* Email Tab */}
      {activeTab === 'email' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="SMTP Server"
            description="Outgoing mail server used for realm emails (stored as smtpServer.* attributes)"
            sectionId="realm-email-smtp"
            configuredCount={[smtpAttr('host'), smtpAttr('port')].filter(Boolean).length}
            totalCount={2}
          >
            <Input
              label="Host"
              value={smtpAttr('host')}
              onChange={(e) => patchSmtp('host', e.target.value)}
              helperText="SMTP server hostname"
              placeholder="smtp.example.com"
            />
            <Input
              label="Port"
              type="number"
              min={0}
              value={smtpAttr('port')}
              onChange={(e) => patchSmtp('port', e.target.value)}
              helperText="SMTP server port (usually 25, 465, or 587)"
              placeholder="587"
            />
            <FormSwitch
              label="Enable SSL"
              helperText="Connect over implicit TLS (typically port 465)"
              checked={smtpAttr('ssl') === 'true'}
              onChange={(v) => patchSmtp('ssl', v ? 'true' : 'false')}
            />
            <FormSwitch
              label="Enable StartTLS"
              helperText="Upgrade the connection with STARTTLS (typically port 587)"
              checked={smtpAttr('starttls') === 'true'}
              onChange={(v) => patchSmtp('starttls', v ? 'true' : 'false')}
            />
          </FormSection>

          <FormSection
            title="Sender & Authentication"
            description="Envelope sender and optional SMTP credentials"
            sectionId="realm-email-sender"
            configuredCount={
              [smtpAttr('from'), smtpAttr('fromDisplayName'), smtpAttr('replyTo'), smtpAttr('user'), smtpAttr('password')].filter(
                Boolean
              ).length
            }
            totalCount={5}
          >
            <Input
              label="From"
              type="email"
              value={smtpAttr('from')}
              onChange={(e) => patchSmtp('from', e.target.value)}
              helperText="Sender address for outgoing emails"
              placeholder="noreply@example.com"
            />
            <Input
              label="From Display Name"
              value={smtpAttr('fromDisplayName')}
              onChange={(e) => patchSmtp('fromDisplayName', e.target.value)}
              helperText="Friendly sender name shown to recipients"
            />
            <Input
              label="Reply To"
              type="email"
              value={smtpAttr('replyTo')}
              onChange={(e) => patchSmtp('replyTo', e.target.value)}
              helperText="Optional Reply-To address"
            />
            <Input
              label="Username"
              value={smtpAttr('user')}
              onChange={(e) => patchSmtp('user', e.target.value)}
              helperText="SMTP authentication username"
            />
            <Input
              label="Password"
              type="password"
              value={smtpAttr('password')}
              onChange={(e) => patchSmtp('password', e.target.value)}
              helperText="SMTP authentication password"
            />
          </FormSection>

          <FormSection
            title="Test Connection"
            description="Send a test email using the stored SMTP settings"
            sectionId="realm-email-test"
          >
            <Input
              label="Recipient Email"
              type="email"
              value={smtpTestEmail}
              onChange={(e) => setSmtpTestEmail(e.target.value)}
              helperText="Save changes before testing — the test uses the settings stored on the server"
              placeholder="admin@example.com"
            />
            <div className="flex items-center gap-3">
              <Button
                type="button"
                size="sm"
                loading={testSmtp.isPending}
                disabled={!smtpTestEmail}
                onClick={handleTestSmtp}
              >
                Send Test Email
              </Button>
              {smtpTestResult && (
                <span
                  className={`text-sm ${smtpTestResult.ok ? 'text-matrix-green' : 'text-alert-red'}`}
                  role={smtpTestResult.ok ? 'status' : 'alert'}
                >
                  {smtpTestResult.message}
                </span>
              )}
            </div>
          </FormSection>
        </div>
      )}

      {/* Tokens Tab */}
      {activeTab === 'tokens' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="Token Lifespans"
            description="Control how long issued tokens remain valid"
            sectionId="realm-tokens-lifespans"
            configuredCount={
              [
                values.access_token_lifespan !== undefined && values.access_token_lifespan !== null,
                values.refresh_token_lifespan !== undefined && values.refresh_token_lifespan !== null,
              ].filter(Boolean).length
            }
            totalCount={2}
          >
            <FormDuration
              label="Access Token Lifespan"
              value={values.access_token_lifespan ?? 300}
              onChange={(v) => patch('access_token_lifespan', v)}
              helperText="Time until access tokens expire"
            />
            <FormDuration
              label="Refresh Token Lifespan"
              value={values.refresh_token_lifespan ?? 1800}
              onChange={(v) => patch('refresh_token_lifespan', v)}
              helperText="Time until refresh tokens expire"
            />
          </FormSection>
        </div>
      )}

      {/* Sessions Tab */}
      {activeTab === 'sessions' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="SSO Session"
            description="Single sign-on session timeouts"
            sectionId="realm-sessions-sso"
            configuredCount={
              [
                values.sso_session_idle_timeout !== undefined && values.sso_session_idle_timeout !== null,
                values.sso_session_max_lifespan !== undefined && values.sso_session_max_lifespan !== null,
              ].filter(Boolean).length
            }
            totalCount={2}
          >
            <FormDuration
              label="SSO Session Idle Timeout"
              value={values.sso_session_idle_timeout ?? 1800}
              onChange={(v) => patch('sso_session_idle_timeout', v)}
              helperText="Time before an idle session expires"
            />
            <FormDuration
              label="SSO Session Max Lifespan"
              value={values.sso_session_max_lifespan ?? 36000}
              onChange={(v) => patch('sso_session_max_lifespan', v)}
              helperText="Maximum time a session can remain active regardless of activity"
            />
          </FormSection>

          <FormSection
            title="Offline Sessions"
            description="Offline access token session policy"
            sectionId="realm-sessions-offline"
            configuredCount={
              [values.offline_session_idle_timeout !== undefined && values.offline_session_idle_timeout !== null].filter(
                Boolean
              ).length
            }
            totalCount={1}
          >
            <FormDuration
              label="Offline Session Idle Timeout"
              value={values.offline_session_idle_timeout ?? 2592000}
              onChange={(v) => patch('offline_session_idle_timeout', v)}
              helperText="Time before an idle offline session expires"
            />
          </FormSection>
        </div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <div className="space-y-4 max-w-3xl">
          <FormSection
            title="Brute Force Detection"
            description="Track consecutive login failures and temporarily lock out targeted accounts"
            sectionId="realm-security-brute-force"
            configuredCount={values.bruteForceProtected ? 1 : 0}
            totalCount={1}
          >
            <FormSwitch
              label="Enabled"
              helperText="Count failed logins per user and lock the account after too many failures"
              checked={values.bruteForceProtected ?? false}
              onChange={(v) => patch('bruteForceProtected', v)}
            />
            <Input
              label="Max Login Failures"
              type="number"
              min={1}
              disabled={!bruteForceOn}
              value={values.maxLoginFailures ?? 5}
              onChange={(e) => patchNumber('maxLoginFailures', e.target.value)}
              helperText="Consecutive failures before the account is locked"
            />
            <Input
              label="Wait Increment (seconds)"
              type="number"
              min={0}
              disabled={!bruteForceOn}
              value={values.waitIncrementSecs ?? 60}
              onChange={(e) => patchNumber('waitIncrementSecs', e.target.value)}
              helperText="Base lockout time added after each failure beyond the threshold"
            />
            <Input
              label="Max Failure Wait (seconds)"
              type="number"
              min={0}
              disabled={!bruteForceOn}
              value={values.maxFailureWaitSecs ?? 900}
              onChange={(e) => patchNumber('maxFailureWaitSecs', e.target.value)}
              helperText="Upper bound for the escalating wait time"
            />
            <Input
              label="Lockout Duration (seconds)"
              type="number"
              min={0}
              disabled={!bruteForceOn}
              value={values.lockoutDurationSecs ?? 900}
              onChange={(e) => patchNumber('lockoutDurationSecs', e.target.value)}
              helperText="How long the account stays locked once the threshold is hit"
            />
          </FormSection>

          <FormSection
            title="OTP Policy"
            description="Time-based one-time password (TOTP) settings for authenticator apps"
            sectionId="realm-security-otp-policy"
            configuredCount={
              [
                values.otpPolicyAlgorithm !== undefined && values.otpPolicyAlgorithm !== null,
                values.otpPolicyDigits !== undefined && values.otpPolicyDigits !== null,
                values.otpPolicyPeriod !== undefined && values.otpPolicyPeriod !== null,
                values.otpPolicyLookAheadWindow !== undefined &&
                  values.otpPolicyLookAheadWindow !== null,
              ].filter(Boolean).length
            }
            totalCount={4}
          >
            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="Algorithm"
                tooltipText="HMAC hash algorithm used to generate and verify TOTP codes"
              />
              <FormSelect
                options={otpAlgorithmOptions}
                value={values.otpPolicyAlgorithm ?? 'HmacSHA1'}
                onChange={(v) => patch('otpPolicyAlgorithm', v)}
                placeholder={infoLoading ? 'Loading...' : 'Select algorithm'}
                disabled={infoLoading}
              />
              <FormContextLine text={otpAlgDesc?.description} />
            </div>
            <Input
              label="Digits"
              type="number"
              min={6}
              max={8}
              step={2}
              value={values.otpPolicyDigits ?? 6}
              onChange={(e) => patchNumber('otpPolicyDigits', e.target.value)}
              helperText="Length of the generated code — 6 or 8 digits"
            />
            <Input
              label="Period (seconds)"
              type="number"
              min={1}
              value={values.otpPolicyPeriod ?? 30}
              onChange={(e) => patchNumber('otpPolicyPeriod', e.target.value)}
              helperText="How long each generated code stays valid"
            />
            <Input
              label="Look-ahead Window"
              type="number"
              min={0}
              max={5}
              value={values.otpPolicyLookAheadWindow ?? 0}
              onChange={(e) => patchNumber('otpPolicyLookAheadWindow', e.target.value)}
              helperText="Future time steps accepted when verifying a code (0–5), to tolerate client clock drift"
            />
          </FormSection>

          <NotBeforeSection realmName={realmName!} realm={realm} />

          <DefaultGroupsSection values={values} onPatch={patch} />
        </div>
      )}

      {/* Events Tab */}
      {activeTab === 'events' && (
        <div className="space-y-4 max-w-3xl">
          <EventsConfigSection realm={realmName!} />
        </div>
      )}

      {/* Actions Tab */}
      {activeTab === 'actions' && (
        <div className="space-y-4 max-w-3xl">
          <PartialImportSection realm={realmName!} />
          <RealmActionsSection realm={realmName!} />
        </div>
      )}
    </div>
  )
}
