// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import UserForm from './UserForm'
import type { UserRepresentation } from '@generated'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      required_actions: [
        {
          id: 'VERIFY_EMAIL',
          name: 'Verify Email',
          description: 'The user must verify their email address',
        },
        {
          id: 'UPDATE_PASSWORD',
          name: 'Update Password',
          description: 'The user must change their password',
        },
      ],
    },
    isLoading: false,
  }),
}))

function renderForm(defaultValues?: Partial<UserRepresentation>, onSubmit = vi.fn()) {
  render(
    <UserForm
      defaultValues={defaultValues}
      onSubmit={onSubmit}
      onCancel={vi.fn()}
    />
  )
  return onSubmit
}

describe('UserForm required actions', () => {
  it('renders required-action options from serverinfo with descriptions', () => {
    renderForm()
    expect(screen.getByText('Verify Email')).toBeInTheDocument()
    expect(screen.getByText('Update Password')).toBeInTheDocument()
    // Description visibility rule: shown as subtitle and label tooltip
    expect(screen.getByText('The user must verify their email address')).toBeInTheDocument()
    expect(screen.getByTitle('The user must change their password')).toBeInTheDocument()
  })

  it('submits checked required actions', async () => {
    const onSubmit = renderForm({ username: 'alice' })
    fireEvent.click(screen.getByLabelText(/Verify Email/))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalled())
    const submitted = onSubmit.mock.calls[0][0] as UserRepresentation
    expect(submitted.requiredActions).toEqual(['VERIFY_EMAIL'])
  })

  it('round-trips pre-selected actions and supports removal', async () => {
    const onSubmit = renderForm({
      username: 'alice',
      requiredActions: ['VERIFY_EMAIL', 'UPDATE_PASSWORD'],
    })
    const verifyEmail = screen.getByLabelText(/Verify Email/)
    expect(verifyEmail).toBeChecked()
    expect(screen.getByLabelText(/Update Password/)).toBeChecked()
    fireEvent.click(verifyEmail)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalled())
    const submitted = onSubmit.mock.calls[0][0] as UserRepresentation
    expect(submitted.requiredActions).toEqual(['UPDATE_PASSWORD'])
  })
})
