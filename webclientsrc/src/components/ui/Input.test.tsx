// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import Input from './Input'
import { Mail } from 'lucide-react'

describe('Input', () => {
  it('renders label when provided', () => {
    render(<Input label="Email" />)
    expect(screen.getByText('Email')).toBeInTheDocument()
  })

  it('renders error message and sets aria-invalid', () => {
    render(<Input label="Name" error="Name is required" />)
    expect(screen.getByText('Name is required')).toBeInTheDocument()
    expect(screen.getByRole('textbox')).toHaveAttribute('aria-invalid', 'true')
  })

  it('renders helper text', () => {
    render(<Input label="Name" helperText="Enter your full name" />)
    expect(screen.getByText('Enter your full name')).toBeInTheDocument()
  })

  it('shows character counter when maxLength is set', () => {
    render(<Input label="Bio" maxLength={100} value="Hello" onChange={() => {}} />)
    expect(screen.getByText('5/100')).toBeInTheDocument()
  })

  it('links aria-describedby to error and helper', () => {
    render(<Input label="Name" error="Error" helperText="Helper" />)
    const input = screen.getByRole('textbox')
    const describedBy = input.getAttribute('aria-describedby')
    expect(describedBy).toContain('error')
    expect(describedBy).toContain('helper')
  })

  it('shows success checkmark when success is true', () => {
    render(<Input label="Name" success />)
    expect(screen.getByRole('textbox')).toHaveClass('border-em-600')
  })

  it('renders left icon', () => {
    render(<Input label="Email" iconLeft={Mail} />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('renders right icon', () => {
    render(<Input label="Email" iconRight={Mail} />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('copy button writes to clipboard', async () => {
    const user = userEvent.setup()
    const mockWrite = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockWrite },
      writable: true,
      configurable: true,
    })
    render(<Input label="Secret" value="abc123" onChange={() => {}} copyable />)
    const copyBtn = screen.getByLabelText('Copy to clipboard')
    await user.click(copyBtn)
    expect(mockWrite).toHaveBeenCalledWith('abc123')
    expect(screen.getByLabelText('Copied')).toBeInTheDocument()
  })

  it('copy button uses defaultValue when value is empty', async () => {
    const user = userEvent.setup()
    const mockWrite = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockWrite },
      writable: true,
      configurable: true,
    })
    render(<Input label="Secret" defaultValue="fallback" onChange={() => {}} copyable />)
    const copyBtn = screen.getByLabelText('Copy to clipboard')
    await user.click(copyBtn)
    expect(mockWrite).toHaveBeenCalledWith('fallback')
  })

  it('does not show copy button when copyable is false', () => {
    render(<Input label="Name" />)
    expect(screen.queryByLabelText('Copy to clipboard')).not.toBeInTheDocument()
  })

  it('does not copy when text is empty', async () => {
    const user = userEvent.setup()
    const mockWrite = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockWrite },
      writable: true,
      configurable: true,
    })
    render(<Input label="Secret" value="" onChange={() => {}} copyable />)
    const copyBtn = screen.getByLabelText('Copy to clipboard')
    await user.click(copyBtn)
    expect(mockWrite).not.toHaveBeenCalled()
  })

  it('renders as password type', () => {
    render(<Input label="Password" type="password" value="secret" onChange={() => {}} />)
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
  })
})
