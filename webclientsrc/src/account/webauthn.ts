// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

/**
 * WebAuthn helpers for the account console: a base64url codec plus conversion between the server's JSON shapes (webauthn-rs, binary fields
 * as base64url strings) and the browser's `PublicKeyCredential` binary types.
 */

/**
 * JSON shape of the WebAuthn creation options returned by the register-start endpoint (webauthn-rs
 * `PublicKeyCredentialCreationOptions`; binary fields are base64url strings). The OpenAPI spec models this
 * body as free-form JSON, so this is the client-side structural view used by the conversion helpers.
 */
export interface WebAuthnCreationOptionsJSON {
  rp: { id?: string; name: string }
  user: { id: string; name: string; displayName: string }
  challenge: string
  pubKeyCredParams: Array<{ type: string; alg: number }>
  timeout?: number
  attestation?: string
  authenticatorSelection?: {
    authenticatorAttachment?: string
    residentKey?: string
    requireResidentKey?: boolean
    userVerification?: string
  }
  excludeCredentials?: Array<{ type: string; id: string; transports?: string[] }>
  extensions?: Record<string, unknown>
}

/**
 * Serialized `PublicKeyCredential` sent to the register-finish endpoint;
 * binary fields are base64url strings (what webauthn-rs deserializes).
 */
export interface WebAuthnCredentialJSON {
  id: string
  rawId: string
  type: string
  response: {
    attestationObject: string
    clientDataJSON: string
    transports?: string[]
  }
  clientExtensionResults: AuthenticationExtensionsClientOutputs
}

/** Decode a base64url string (padding optional) into an `ArrayBuffer`. */
export function base64urlToBuffer(s: string): ArrayBuffer {
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

/** Encode an `ArrayBuffer` as an unpadded base64url string. */
export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Convert the server's creation options (base64url JSON) into the binary
 * `PublicKeyCredentialCreationOptions` shape the browser expects.
 */
export function creationOptionsFromJSON(
  json: WebAuthnCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  const options: PublicKeyCredentialCreationOptions = {
    rp: json.rp,
    challenge: base64urlToBuffer(json.challenge),
    user: {
      id: base64urlToBuffer(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    pubKeyCredParams: json.pubKeyCredParams.map((p) => ({
      type: p.type as PublicKeyCredentialType,
      alg: p.alg,
    })),
  }
  if (json.timeout !== undefined) options.timeout = json.timeout
  if (json.attestation !== undefined) {
    options.attestation = json.attestation as AttestationConveyancePreference
  }
  if (json.authenticatorSelection !== undefined) {
    options.authenticatorSelection =
      json.authenticatorSelection as AuthenticatorSelectionCriteria
  }
  if (json.excludeCredentials !== undefined) {
    options.excludeCredentials = json.excludeCredentials.map((c) => ({
      type: c.type as PublicKeyCredentialType,
      id: base64urlToBuffer(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined,
    }))
  }
  if (json.extensions !== undefined) {
    options.extensions = json.extensions as unknown as AuthenticationExtensionsClientInputs
  }
  return options
}

/**
 * Serialize a browser attestation into the JSON shape webauthn-rs expects:
 * `id`/`rawId`/`response.attestationObject`/`response.clientDataJSON` as
 * base64url strings, plus `getTransports()` output when the browser exposes it.
 */
export function attestationToJSON(cred: PublicKeyCredential): WebAuthnCredentialJSON {
  const response = cred.response as AuthenticatorAttestationResponse
  const json: WebAuthnCredentialJSON = {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
  const transports =
    typeof response.getTransports === 'function' ? response.getTransports() : undefined
  if (transports !== undefined) json.response.transports = transports
  return json
}
