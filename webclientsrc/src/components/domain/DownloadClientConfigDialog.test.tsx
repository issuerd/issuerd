// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { serializeClientConfig } from './DownloadClientConfigDialog'
import type { DotenvClientConfigRepresentation } from '@generated'

const dotenvConfig: DotenvClientConfigRepresentation = {
  ISSUERD_CLIENT_ID: 'my-app',
  ISSUERD_ISSUER: 'https://idp.example.com/realms/test',
  ISSUERD_REDIRECT_URI: 'https://app.example.com/cb',
}

describe('serializeClientConfig', () => {
  it('renders JSON providers as pretty-printed JSON', () => {
    expect(serializeClientConfig(dotenvConfig, 'application/json')).toBe(
      JSON.stringify(dotenvConfig, null, 2),
    )
  })

  it('renders text/plain providers as quoted KEY=VALUE lines', () => {
    expect(serializeClientConfig(dotenvConfig, 'text/plain')).toBe(
      [
        'ISSUERD_CLIENT_ID="my-app"',
        'ISSUERD_ISSUER="https://idp.example.com/realms/test"',
        'ISSUERD_REDIRECT_URI="https://app.example.com/cb"',
      ].join('\n'),
    )
  })

  it('keeps URL special characters intact inside quotes', () => {
    const cfg = {
      ...dotenvConfig,
      ISSUERD_REDIRECT_URI: 'https://app.example.com/cb?param=value&other=123#section',
    }
    expect(serializeClientConfig(cfg, 'text/plain')).toContain(
      'ISSUERD_REDIRECT_URI="https://app.example.com/cb?param=value&other=123#section"',
    )
  })

  it('escapes backslashes and double quotes in dotenv values', () => {
    const cfg = { ...dotenvConfig, ISSUERD_REDIRECT_URI: 'C:\\apps\\"my app"\\cb' }
    expect(serializeClientConfig(cfg, 'text/plain')).toContain(
      'ISSUERD_REDIRECT_URI="C:\\\\apps\\\\\\"my app\\"\\\\cb"',
    )
  })
})
