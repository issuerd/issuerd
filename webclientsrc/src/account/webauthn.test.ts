// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import {
  attestationToJSON,
  base64urlToBuffer,
  bufferToBase64url,
  creationOptionsFromJSON,
} from './webauthn'

describe('base64url codec', () => {
  it('round-trips arbitrary bytes', () => {
    const samples = [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([1, 2]),
      // Exercises the +/ alphabet characters that become - and _.
      new Uint8Array([251, 255, 190]),
      new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 3 + 1) % 256)),
    ]
    for (const sample of samples) {
      const encoded = bufferToBase64url(sample.buffer)
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/)
      expect(encoded).not.toContain('=')
      expect(Array.from(new Uint8Array(base64urlToBuffer(encoded)))).toEqual(
        Array.from(sample)
      )
    }
  })

  it('decodes padded and unpadded input identically', () => {
    expect(Array.from(new Uint8Array(base64urlToBuffer('AQID')))).toEqual([1, 2, 3])
    expect(Array.from(new Uint8Array(base64urlToBuffer('AQIDBA==')))).toEqual([1, 2, 3, 4])
    expect(Array.from(new Uint8Array(base64urlToBuffer('AQIDBA')))).toEqual([1, 2, 3, 4])
  })
})

describe('creationOptionsFromJSON', () => {
  it('converts base64url fields into ArrayBuffers', () => {
    const options = creationOptionsFromJSON({
      rp: { name: 'Issuerd' },
      user: { id: 'AQID', name: 'alice', displayName: 'Alice' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
      excludeCredentials: [{ type: 'public-key', id: 'BwgJ', transports: ['internal'] }],
    })

    expect(options.rp).toEqual({ name: 'Issuerd' })
    expect(Array.from(new Uint8Array(options.challenge as ArrayBuffer))).toEqual([4, 5, 6])
    expect(Array.from(new Uint8Array(options.user.id as ArrayBuffer))).toEqual([1, 2, 3])
    expect(options.user.name).toBe('alice')
    expect(options.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }])
    expect(options.timeout).toBe(60000)
    expect(options.attestation).toBe('none')
    expect(options.authenticatorSelection).toEqual({ userVerification: 'preferred' })
    expect(options.excludeCredentials).toHaveLength(1)
    expect(
      Array.from(new Uint8Array(options.excludeCredentials![0].id as ArrayBuffer))
    ).toEqual([7, 8, 9])
    expect(options.excludeCredentials![0].transports).toEqual(['internal'])
  })

  it('omits optional fields the server did not send', () => {
    const options = creationOptionsFromJSON({
      rp: { name: 'Issuerd' },
      user: { id: 'AQID', name: 'alice', displayName: 'Alice' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    })

    expect(options).not.toHaveProperty('timeout')
    expect(options).not.toHaveProperty('attestation')
    expect(options).not.toHaveProperty('authenticatorSelection')
    expect(options).not.toHaveProperty('excludeCredentials')
  })
})

describe('attestationToJSON', () => {
  it('serializes binary fields as base64url and keeps transports', () => {
    const cred = {
      id: 'AQID',
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      response: {
        attestationObject: new Uint8Array([251, 255, 190]).buffer,
        clientDataJSON: new Uint8Array([123, 125]).buffer, // "{}"
        getTransports: () => ['internal'],
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential

    const json = attestationToJSON(cred)
    expect(json).toEqual({
      id: 'AQID',
      rawId: 'AQID',
      type: 'public-key',
      response: {
        attestationObject: bufferToBase64url(new Uint8Array([251, 255, 190]).buffer),
        clientDataJSON: 'e30',
        transports: ['internal'],
      },
      clientExtensionResults: {},
    })
    // Every serialized binary field must be unpadded base64url.
    for (const value of [json.rawId, json.response.attestationObject, json.response.clientDataJSON]) {
      expect(value).toMatch(/^[A-Za-z0-9_-]*$/)
    }
  })

  it('omits transports when the browser does not expose getTransports()', () => {
    const cred = {
      id: 'AQID',
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      response: {
        attestationObject: new Uint8Array([9]).buffer,
        clientDataJSON: new Uint8Array([123, 125]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential

    const json = attestationToJSON(cred)
    expect(json.response).not.toHaveProperty('transports')
  })
})
