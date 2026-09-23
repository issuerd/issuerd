// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import PasswordPage from './PasswordPage'

const mockGetCredentials = vi.fn()
const mockChangePassword = vi.fn()
const mockTotpStart = vi.fn()
const mockTotpVerify = vi.fn()
const mockTotpDelete = vi.fn()
const mockWebauthnRegisterStart = vi.fn()
const mockWebauthnRegisterFinish = vi.fn()
const mockWebauthnList = vi.fn()
const mockWebauthnDelete = vi.fn()

vi.mock('@generated', () => ({
  accountGetCredentials: (...args: unknown[]) => mockGetCredentials(...args),
  accountChangePassword: (...args: unknown[]) => mockChangePassword(...args),
  accountTotpStart: (...args: unknown[]) => mockTotpStart(...args),
  accountTotpVerify: (...args: unknown[]) => mockTotpVerify(...args),
  accountTotpDelete: (...args: unknown[]) => mockTotpDelete(...args),
  accountWebauthnRegisterStart: (...args: unknown[]) => mockWebauthnRegisterStart(...args),
  accountWebauthnRegisterFinish: (...args: unknown[]) => mockWebauthnRegisterFinish(...args),
  accountWebauthnListCredentials: (...args: unknown[]) => mockWebauthnList(...args),
  accountWebauthnDeleteCredential: (...args: unknown[]) => mockWebauthnDelete(...args),
}))

/** Simulate a browser with (or without) WebAuthn platform support. */
function mockWebAuthnSupport(createImpl: unknown = vi.fn()) {
  Object.defineProperty(window, 'PublicKeyCredential', {
    value: class PublicKeyCredential {},
    configurable: true,
  })
  Object.defineProperty(window.navigator, 'credentials', {
    value: { create: createImpl },
    configurable: true,
  })
  return createImpl as ReturnType<typeof vi.fn>
}

function mockNoWebAuthnSupport() {
  delete (window as { PublicKeyCredential?: unknown }).PublicKeyCredential
  Object.defineProperty(window.navigator, 'credentials', {
    value: undefined,
    configurable: true,
  })
}

function resolved(data: unknown) {
  return { data, error: undefined, response: { status: 200 } }
}

describe('PasswordPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetCredentials.mockResolvedValue(resolved({ password: true, totp: false, webauthn: false }))
    mockWebauthnList.mockResolvedValue(resolved([]))
    mockNoWebAuthnSupport()
  })

  it('renders credential presence badges', async () => {
    render(<PasswordPage />)
    expect(await screen.findByText('Password')).toBeInTheDocument()
    expect(screen.getByText('TOTP')).toBeInTheDocument()
    expect(screen.getByText('WebAuthn')).toBeInTheDocument()
    expect(screen.getByText('Set up')).toBeInTheDocument()
    expect(screen.getAllByText('Not set up')).toHaveLength(2)
  })

  it('requires the confirmation to match before calling the API', async () => {
    render(<PasswordPage />)
    await screen.findByText('Password')
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'old-pass' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-pass-1' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), {
      target: { value: 'new-pass-2' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Change Password' }))

    expect(await screen.findByText('Passwords do not match')).toBeInTheDocument()
    expect(mockChangePassword).not.toHaveBeenCalled()
  })

  it('renders password-policy violations returned by the server', async () => {
    mockChangePassword.mockResolvedValue({
      error: {
        error: 'Password policy failed',
        policyViolations: [
          { code: 'min_length', message: 'Password must be at least 8 characters long' },
        ],
      },
      response: { status: 400 },
    })
    render(<PasswordPage />)
    await screen.findByText('Password')
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'old-pass' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'short' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'short' } })
    fireEvent.click(screen.getByRole('button', { name: 'Change Password' }))

    expect(
      await screen.findByText('Password must be at least 8 characters long')
    ).toBeInTheDocument()
    expect(mockChangePassword).toHaveBeenCalledWith({
      path: { realm: 'master' },
      body: { current_password: 'old-pass', new_password: 'short' },
    })
  })

  it('renders a generic server error when no policy violations are present', async () => {
    mockChangePassword.mockResolvedValue({
      error: { error: 'Current password is incorrect' },
      response: { status: 400 },
    })
    render(<PasswordPage />)
    await screen.findByText('Password')
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'wrong' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-pass' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), {
      target: { value: 'new-pass' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Change Password' }))

    expect(await screen.findByText('Current password is incorrect')).toBeInTheDocument()
  })

  it('changes the password and clears the form on success', async () => {
    mockChangePassword.mockResolvedValue(resolved(undefined))
    render(<PasswordPage />)
    await screen.findByText('Password')
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'old-pass' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-pass' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), {
      target: { value: 'new-pass' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Change Password' }))

    expect(await screen.findByText('Password changed.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('New password')).toHaveValue(''))
    expect(screen.getByLabelText('Current password')).toHaveValue('')
    expect(screen.getByLabelText('Confirm new password')).toHaveValue('')
  })

  describe('TOTP enrollment', () => {
    const startResponse = {
      secret: 'JBSWY3DPEHPK3PXP',
      otpauthUrl: 'otpauth://totp/Issuerd:alice?secret=JBSWY3DPEHPK3PXP',
      qrSvg:
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">' +
        '<rect width="100" height="100"/></svg>',
    }

    it('starts enrollment and renders the QR svg, grouped secret and fallback link', async () => {
      mockTotpStart.mockResolvedValue(resolved(startResponse))
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator app' }))

      expect(mockTotpStart).toHaveBeenCalled()
      const qr = await screen.findByTestId('totp-qr')
      expect(qr.querySelector('svg')).toBeInTheDocument()
      expect(screen.getByText('JBSW Y3DP EHPK 3PXP')).toBeInTheDocument()
      expect(
        screen.getByRole('link', { name: 'Open in authenticator app' })
      ).toHaveAttribute('href', startResponse.otpauthUrl)
      // The setup button is replaced by the enrollment form.
      expect(
        screen.queryByRole('button', { name: 'Set up authenticator app' })
      ).not.toBeInTheDocument()
    })

    it('verifies the code and flips the badge to "Set up"', async () => {
      mockTotpStart.mockResolvedValue(resolved(startResponse))
      mockTotpVerify.mockResolvedValue(resolved(undefined))
      mockGetCredentials
        .mockResolvedValueOnce(resolved({ password: true, totp: false, webauthn: false }))
        .mockResolvedValue(resolved({ password: true, totp: true, webauthn: false }))
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator app' }))
      fireEvent.change(await screen.findByLabelText('6-digit code'), {
        target: { value: '123456' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

      await waitFor(() =>
        expect(mockTotpVerify).toHaveBeenCalledWith({
          path: { realm: 'master' },
          body: { code: '123456' },
        })
      )
      // Password + TOTP badges are now "Set up".
      expect(await screen.findAllByText('Set up')).toHaveLength(2)
      // Enrollment UI collapsed back into the configured state.
      expect(screen.queryByTestId('totp-qr')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument()
    })

    it('shows the server error message when verification fails', async () => {
      mockTotpStart.mockResolvedValue(resolved(startResponse))
      mockTotpVerify.mockResolvedValue({
        error: { error: 'Invalid or expired code' },
        response: { status: 400 },
      })
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator app' }))
      fireEvent.change(await screen.findByLabelText('6-digit code'), {
        target: { value: '000000' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

      expect(await screen.findByText('Invalid or expired code')).toBeInTheDocument()
      // The enrollment stays open so the user can retry.
      expect(screen.getByTestId('totp-qr')).toBeInTheDocument()
    })

    it('removes the authenticator after confirmation and refetches', async () => {
      mockGetCredentials.mockResolvedValueOnce(resolved({ password: true, totp: true, webauthn: false }))
      // The refetch after removal falls back to the beforeEach default (totp: false).
      mockTotpDelete.mockResolvedValue(resolved(undefined))
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm remove' }))

      await waitFor(() => expect(mockTotpDelete).toHaveBeenCalled())
      expect(
        await screen.findByRole('button', { name: 'Set up authenticator app' })
      ).toBeInTheDocument()
      expect(screen.getAllByText('Not set up')).toHaveLength(2)
    })

    it('does not call the API when the removal is cancelled', async () => {
      mockGetCredentials.mockResolvedValue(resolved({ password: true, totp: true, webauthn: false }))
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

      expect(mockTotpDelete).not.toHaveBeenCalled()
      expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument()
    })
  })

  describe('Passkeys', () => {
    const creationOptions = {
      rp: { name: 'Issuerd' },
      user: { id: 'AQID', name: 'alice', displayName: 'Alice' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      attestation: 'none',
    }

    it('shows a not-supported note and no register button without WebAuthn', async () => {
      render(<PasswordPage />)
      await screen.findByText('Password')
      expect(screen.getByText(/not supported in this browser/)).toBeInTheDocument()
      expect(
        screen.queryByRole('button', { name: 'Register passkey' })
      ).not.toBeInTheDocument()
    })

    it('renders the registered passkeys with label and creation date', async () => {
      mockWebAuthnSupport()
      mockWebauthnList.mockResolvedValue(
        resolved([{ id: 'cred-1', label: 'MacBook Touch ID', createdAt: '2026-08-01T10:00:00Z' }])
      )
      render(<PasswordPage />)
      await screen.findByText('Password')
      expect(await screen.findByText('MacBook Touch ID')).toBeInTheDocument()
      expect(screen.getByText(/^Added /)).toBeInTheDocument()
    })

    it('registers a passkey through the browser ceremony and refreshes the list', async () => {
      const fakeCredential = {
        id: 'AQID',
        rawId: new Uint8Array([1, 2, 3]).buffer,
        type: 'public-key',
        response: {
          attestationObject: new Uint8Array([9, 9]).buffer,
          clientDataJSON: new Uint8Array([123, 125]).buffer,
          getTransports: () => ['internal'],
        },
        getClientExtensionResults: () => ({}),
      }
      const mockCreate = mockWebAuthnSupport()
      mockCreate.mockResolvedValue(fakeCredential)
      mockWebauthnRegisterStart.mockResolvedValue(resolved(creationOptions))
      mockWebauthnRegisterFinish.mockResolvedValue(resolved(undefined))
      mockWebauthnList
        .mockResolvedValueOnce(resolved([]))
        .mockResolvedValue(
          resolved([{ id: 'cred-1', label: 'Work laptop', createdAt: '2026-08-01T10:00:00Z' }])
        )

      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.change(screen.getByLabelText('Passkey label (optional)'), {
        target: { value: 'Work laptop' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Register passkey' }))

      await waitFor(() =>
        expect(mockWebauthnRegisterStart).toHaveBeenCalledWith({ path: { realm: 'master' } })
      )
      // The browser ceremony received binary creation options.
      expect(mockCreate).toHaveBeenCalledWith({
        publicKey: expect.objectContaining({
          rp: { name: 'Issuerd' },
          challenge: expect.any(ArrayBuffer),
          user: expect.objectContaining({ id: expect.any(ArrayBuffer) }),
        }),
      })
      // The attestation was serialized with base64url fields before finishing.
      await waitFor(() =>
        expect(mockWebauthnRegisterFinish).toHaveBeenCalledWith({
          path: { realm: 'master' },
          body: {
            label: 'Work laptop',
            credential: {
              id: 'AQID',
              rawId: 'AQID',
              type: 'public-key',
              response: {
                attestationObject: 'CQk',
                clientDataJSON: 'e30',
                transports: ['internal'],
              },
              clientExtensionResults: {},
            },
          },
        })
      )
      // The refreshed list shows the new passkey.
      expect((await screen.findAllByText('Work laptop')).length).toBeGreaterThan(0)
      expect(mockWebauthnList).toHaveBeenCalledTimes(2)
    })

    it('surfaces server errors from the register ceremony', async () => {
      mockWebAuthnSupport()
      mockWebauthnRegisterStart.mockResolvedValue({
        error: { error: 'WebAuthn is disabled' },
        response: { status: 400 },
      })
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(screen.getByRole('button', { name: 'Register passkey' }))

      expect(await screen.findByText('WebAuthn is disabled')).toBeInTheDocument()
    })

    it('deletes a passkey and refreshes the list', async () => {
      mockWebAuthnSupport()
      mockWebauthnDelete.mockResolvedValue(resolved(undefined))
      mockWebauthnList
        .mockResolvedValueOnce(
          resolved([{ id: 'cred-1', label: 'MacBook Touch ID', createdAt: '2026-08-01T10:00:00Z' }])
        )
        .mockResolvedValue(resolved([]))
      render(<PasswordPage />)
      await screen.findByText('Password')
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))

      await waitFor(() =>
        expect(mockWebauthnDelete).toHaveBeenCalledWith({
          path: { realm: 'master', id: 'cred-1' },
        })
      )
      await waitFor(() =>
        expect(screen.queryByText('MacBook Touch ID')).not.toBeInTheDocument()
      )
      expect(screen.getByText('No passkeys registered yet.')).toBeInTheDocument()
    })
  })
})
