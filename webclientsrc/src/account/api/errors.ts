// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

/**
 * Error type + unwrapping helper for the account console's generated SDK
 * calls. Account endpoints report failures as `{"error": "..."}` (admin
 * endpoints use `errorMessage`); password-policy failures additionally
 * carry `policyViolations`.
 */

export interface PolicyViolation {
  code: string
  message: string
}

/** Account-API failure; carries password-policy violations when present. */
export class AccountApiError extends Error {
  status: number
  policyViolations: PolicyViolation[]

  constructor(message: string, status: number, policyViolations: PolicyViolation[] = []) {
    super(message)
    this.name = 'AccountApiError'
    this.status = status
    this.policyViolations = policyViolations
  }
}

function toError(error: unknown, status: number): AccountApiError {
  const body = (error ?? {}) as Record<string, unknown>
  const message =
    (typeof body.error === 'string' && body.error) ||
    (typeof body.errorMessage === 'string' && body.errorMessage) ||
    `Request failed (${status})`
  const violations = Array.isArray(body.policyViolations)
    ? (body.policyViolations as PolicyViolation[])
    : []
  return new AccountApiError(message, status, violations)
}

/**
 * Unwrap a generated-SDK result (`{data, error, response}`): return the parsed body or throw an `AccountApiError`.
 * Use as `sdkFn({...}).then(unwrap)` or `unwrap(await sdkFn(...))`.
 */
export function unwrap<T>(res: { data?: T; error?: unknown; response?: { status: number } }): T {
  if (res.error !== undefined && res.error !== null) {
    throw toError(res.error, res.response?.status ?? 0)
  }
  return res.data as T
}
