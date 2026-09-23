// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { generateCodeVerifier, generateCodeChallenge, generateState } from './pkce'

describe('PKCE utilities', () => {
  it('generateCodeVerifier returns 128 chars', () => {
    const verifier = generateCodeVerifier()
    expect(verifier).toHaveLength(128)
    expect(typeof verifier).toBe('string')
  })

  it('generateCodeChallenge returns base64url string', async () => {
    const challenge = await generateCodeChallenge('test-verifier')
    expect(typeof challenge).toBe('string')
    expect(challenge).not.toContain('+')
    expect(challenge).not.toContain('/')
    expect(challenge).not.toContain('=')
  })

  it('generateState returns 32 chars', () => {
    const state = generateState()
    expect(state).toHaveLength(32)
    expect(typeof state).toBe('string')
  })
})
