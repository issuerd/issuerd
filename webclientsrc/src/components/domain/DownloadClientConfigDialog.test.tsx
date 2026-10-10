// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { serializeClientConfig } from './DownloadClientConfigDialog'
import type { GenericOidcClientConfigRepresentation } from '@generated'

const oidcConfig: GenericOidcClientConfigRepresentation = {
  issuer: 'https://idp.example.com/realms/test',
  authorization_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/auth',
  token_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/token',
  userinfo_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/userinfo',
  jwks_uri: 'https://idp.example.com/realms/test/protocol/openid-connect/certs',
  end_session_endpoint: 'https://idp.example.com/realms/test/protocol/openid-connect/logout',
  introspection_endpoint:
    'https://idp.example.com/realms/test/protocol/openid-connect/token/introspect',
  client_id: 'my-app',
  client_secret: 'old-secret',
  redirect_uris: ['https://app.example.com/cb'],
}

describe('serializeClientConfig', () => {
  it('renders JSON providers as pretty-printed JSON', () => {
    expect(serializeClientConfig(oidcConfig)).toBe(JSON.stringify(oidcConfig, null, 2))
  })

  it('passes the server-rendered dotenv body through verbatim', () => {
    const dotenv = [
      'ISSUERD_CLIENT_ID="my-app"',
      'ISSUERD_ISSUER="https://idp.example.com/realms/test"',
      'ISSUERD_REDIRECT_URI="https://app.example.com/cb?param=value&other=123#section"',
      '',
    ].join('\n')
    expect(serializeClientConfig(dotenv)).toBe(dotenv)
  })
})
