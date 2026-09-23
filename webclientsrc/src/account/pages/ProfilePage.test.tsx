// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import ProfilePage from './ProfilePage'

const mockGetMe = vi.fn()
const mockLoginContext = vi.fn()
const mockUpdateMe = vi.fn()

vi.mock('@generated', () => ({
  accountGetMe: (...args: unknown[]) => mockGetMe(...args),
  loginContext: (...args: unknown[]) => mockLoginContext(...args),
  accountUpdateMe: (...args: unknown[]) => mockUpdateMe(...args),
}))

const me = {
  id: 'u1',
  username: 'alice',
  email: 'alice@example.com',
  first_name: 'Alice',
  last_name: 'Doe',
  email_verified: true,
  enabled: true,
  roles: ['user'],
}

const loginContext = {
  registration_enabled: true,
  reset_password_allowed: true,
  remember_me_enabled: false,
  login_with_email_allowed: true,
  duplicate_emails_allowed: false,
  edit_username_allowed: true,
  verify_email_enabled: true,
}

describe('ProfilePage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetMe.mockResolvedValue({ data: me, error: undefined, response: { status: 200 } })
    mockLoginContext.mockResolvedValue({ data: loginContext, error: undefined, response: { status: 200 } })
  })

  it('renders the form populated with the account data', async () => {
    render(<ProfilePage />)
    expect(await screen.findByLabelText('Username')).toHaveValue('alice')
    expect(screen.getByLabelText('First name')).toHaveValue('Alice')
    expect(screen.getByLabelText('Last name')).toHaveValue('Doe')
    expect(screen.getByLabelText('Email')).toHaveValue('alice@example.com')
    expect(screen.getByText('user')).toBeInTheDocument()
  })

  it('makes the username read-only when the realm disallows editing', async () => {
    mockLoginContext.mockResolvedValue({
      data: { ...loginContext, edit_username_allowed: false },
      error: undefined,
      response: { status: 200 },
    })
    render(<ProfilePage />)
    const username = await screen.findByLabelText('Username')
    expect(username).toHaveAttribute('readonly')
    expect(
      screen.getByText('Username changes are not allowed in this realm')
    ).toBeInTheDocument()
  })

  it('submits changes and shows a success note', async () => {
    mockUpdateMe.mockResolvedValue({ data: { ...me, first_name: 'Alicia' }, error: undefined, response: { status: 200 } })
    render(<ProfilePage />)
    const firstName = await screen.findByLabelText('First name')
    fireEvent.change(firstName, { target: { value: 'Alicia' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockUpdateMe).toHaveBeenCalledWith({
        path: { realm: 'master' },
        body: {
          first_name: 'Alicia',
          last_name: 'Doe',
          email: 'alice@example.com',
        },
      })
    )
    expect(await screen.findByText('Profile updated.')).toBeInTheDocument()
    expect(screen.getByLabelText('First name')).toHaveValue('Alicia')
  })

  it('shows verification guidance when the email changed and verify-email is enabled', async () => {
    mockUpdateMe.mockResolvedValue({
      data: { ...me, email: 'new@example.com', email_verified: false },
      error: undefined,
      response: { status: 200 },
    })
    render(<ProfilePage />)
    const email = await screen.findByLabelText('Email')
    fireEvent.change(email, { target: { value: 'new@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(
      await screen.findByText(/A verification email has been sent/)
    ).toBeInTheDocument()
  })

  it('shows the server error message when the update fails', async () => {
    mockUpdateMe.mockResolvedValue({
      error: { error: 'Email is already taken' },
      response: { status: 400 },
    })
    render(<ProfilePage />)
    await screen.findByLabelText('Username')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Email is already taken')).toBeInTheDocument()
  })
})
