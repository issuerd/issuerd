// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import BrokerConfigForm from './BrokerConfigForm'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      broker_sync_modes: [
        { id: 'import', name: 'Import', description: 'Import on first login' },
        { id: 'force', name: 'Force', description: 'Update on every login' },
      ],
      broker_client_auth_methods: [
        { id: 'client_secret_basic', name: 'Client Secret Basic', description: 'Basic auth' },
        { id: 'client_secret_post', name: 'Client Secret Post', description: 'POST auth' },
      ],
    },
    isLoading: false,
  }),
}))

describe('BrokerConfigForm', () => {
  it('emits endpoint, credential, and login behaviour changes', () => {
    const onChange = vi.fn()
    const value = { issuer: 'https://idp.example.com' }
    render(<BrokerConfigForm value={value} onChange={onChange} />)

    const fields = [
      ['Client ID', 'clientId', 'my-client'],
      ['Client Secret', 'clientSecret', 'secret'],
      ['Issuer', 'issuer', 'https://login.example.com'],
      ['Authorization URL', 'authorizationUrl', 'https://login.example.com/authorize'],
      ['Token URL', 'tokenUrl', 'https://login.example.com/token'],
      ['UserInfo URL', 'userInfoUrl', 'https://login.example.com/userinfo'],
      ['JWKS URL', 'jwksUrl', 'https://login.example.com/jwks'],
      ['Default Scope', 'defaultScope', 'openid email'],
    ] as const
    for (const [label, key, nextValue] of fields) {
      fireEvent.change(screen.getByLabelText(label), { target: { value: nextValue } })
      expect(onChange).toHaveBeenLastCalledWith({ ...value, [key]: nextValue })
    }

    fireEvent.click(screen.getByLabelText('Sync Mode'))
    fireEvent.click(screen.getByRole('option', { name: /Force/ }))
    expect(onChange).toHaveBeenLastCalledWith({ ...value, syncMode: 'force' })

    fireEvent.click(screen.getByLabelText('Client Auth Method'))
    fireEvent.click(screen.getByRole('option', { name: /Client Secret Post/ }))
    expect(onChange).toHaveBeenLastCalledWith({ ...value, clientAuthMethod: 'client_secret_post' })

    const switches = [
      ['Use Discovery', 'useDiscovery', 'false'],
      ['Trust Email', 'trustEmail', 'true'],
      ['PKCE', 'pkceEnabled', 'false'],
      ['Store Tokens', 'storeTokens', 'true'],
    ] as const
    for (const [label, key, nextValue] of switches) {
      fireEvent.click(screen.getByRole('switch', { name: label }))
      expect(onChange).toHaveBeenLastCalledWith({ ...value, [key]: nextValue })
    }
  })
})
