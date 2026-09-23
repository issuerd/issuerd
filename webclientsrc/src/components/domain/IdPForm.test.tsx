// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import IdPForm from './IdPForm'
import type { IdentityProviderRepresentation } from '@generated'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      provider_ids: [
        { id: 'ldap', name: 'LDAP', description: 'User federation via LDAP' },
        { id: 'oidc', name: 'OpenID Connect', description: 'Generic OIDC broker' },
        { id: 'google', name: 'Google', description: 'Google social login' },
      ],
      identity_provider_presets: [
        {
          provider_id: 'oidc',
          display_name: 'OpenID Connect',
          config: { defaultScope: 'openid profile email' },
        },
        {
          provider_id: 'google',
          display_name: 'Google',
          config: {
            issuer: 'https://accounts.google.com',
            defaultScope: 'openid profile email',
            trustEmail: 'true',
          },
        },
      ],
      broker_sync_modes: [
        { id: 'import', name: 'Import', description: 'Map data only on first login' },
        { id: 'force', name: 'Force', description: 'Re-apply mappers on every login' },
      ],
      broker_client_auth_methods: [
        { id: 'client_secret_basic', name: 'Client Secret Basic', description: 'HTTP Basic Authorization header' },
        { id: 'client_secret_post', name: 'Client Secret Post', description: 'Credentials in the POST body' },
      ],
    },
    isLoading: false,
  }),
}))

function renderForm(
  defaultValues?: Partial<IdentityProviderRepresentation>,
  onSubmit = vi.fn()
) {
  render(<IdPForm defaultValues={defaultValues} onSubmit={onSubmit} onCancel={vi.fn()} />)
  return onSubmit
}

function pickProvider(name: RegExp) {
  fireEvent.click(screen.getByLabelText('Provider'))
  fireEvent.click(screen.getByRole('option', { name }))
}

describe('IdPForm broker section', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('does not show the broker tab for non-broker providers', () => {
    renderForm()
    expect(screen.queryByRole('button', { name: /Broker/ })).not.toBeInTheDocument()
  })

  it('shows the broker tab and prefills config + display name from the preset in create mode', () => {
    renderForm()
    pickProvider(/Google/)

    // Display Name is prefilled on the General tab
    expect(screen.getByLabelText('Display Name')).toHaveValue('Google')

    fireEvent.click(screen.getByRole('button', { name: 'Broker (OIDC/social)' }))
    expect(screen.getByLabelText('Issuer')).toHaveValue('https://accounts.google.com')
    expect(screen.getByLabelText('Default Scope')).toHaveValue('openid profile email')
  })

  it('shows the broker tab for any provider with a preset (dynamic check)', () => {
    renderForm()
    pickProvider(/OpenID Connect/)

    expect(screen.getByLabelText('Display Name')).toHaveValue('OpenID Connect')

    fireEvent.click(screen.getByRole('button', { name: 'Broker (OIDC/social)' }))
    expect(screen.getByLabelText('Default Scope')).toHaveValue('openid profile email')
  })

  it('does not prefill over existing values in edit mode', () => {
    renderForm({
      alias: 'google',
      provider_id: 'google',
      display_name: 'Corporate Google',
      config: { clientId: 'existing-id', issuer: 'https://accounts.google.com' },
    })

    expect(screen.getByLabelText('Display Name')).toHaveValue('Corporate Google')

    fireEvent.click(screen.getByRole('button', { name: 'Broker (OIDC/social)' }))
    expect(screen.getByLabelText('Client ID')).toHaveValue('existing-id')
  })

  it('submits broker config bound to the config map', async () => {
    const onSubmit = renderForm()
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'google' } })
    pickProvider(/Google/)

    fireEvent.click(screen.getByRole('button', { name: 'Broker (OIDC/social)' }))
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'cid-123' } })
    fireEvent.change(screen.getByLabelText('Client Secret'), { target: { value: 's3cret' } })

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalled())
    const submitted = onSubmit.mock.calls[0][0] as IdentityProviderRepresentation
    expect(submitted.alias).toBe('google')
    expect(submitted.display_name).toBe('Google')
    expect(submitted.config).toMatchObject({
      issuer: 'https://accounts.google.com',
      clientId: 'cid-123',
      clientSecret: 's3cret',
    })
  })

  it('sources sync mode and client auth method options from serverinfo with descriptions', () => {
    renderForm()
    pickProvider(/Google/)
    fireEvent.click(screen.getByRole('button', { name: 'Broker (OIDC/social)' }))

    fireEvent.click(screen.getByLabelText('Sync Mode'))
    expect(screen.getByRole('option', { name: /Import/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /Force/ })).toBeInTheDocument()
    // Description visibility rule: descriptions render as option subtitles
    expect(screen.getByText('Map data only on first login')).toBeInTheDocument()
    expect(screen.getByText('Re-apply mappers on every login')).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Client Auth Method'))
    expect(screen.getByRole('option', { name: /Client Secret Basic/ })).toBeInTheDocument()
    expect(screen.getByText('Credentials in the POST body')).toBeInTheDocument()
  })
})
