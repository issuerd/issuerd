// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import FormDuration from './FormDuration'

describe('FormDuration', () => {
  it('renders presets', () => {
    render(<FormDuration label="TTL" value={300} onChange={() => {}} />)
    expect(screen.getByText('5 minutes')).toBeInTheDocument()
    expect(screen.getByText('1 hour')).toBeInTheDocument()
    expect(screen.getByText('Never')).toBeInTheDocument()
  })

  it('highlights selected preset', () => {
    render(<FormDuration label="TTL" value={3600} onChange={() => {}} />)
    const selected = screen.getByText('1 hour').closest('button')
    expect(selected?.className).toContain('cyan-neon')
  })

  it('calls onChange when a preset is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormDuration label="TTL" value={300} onChange={onChange} />)
    await user.click(screen.getByText('30 minutes'))
    expect(onChange).toHaveBeenCalledWith(1800)
  })

  it('renders helper text and error', () => {
    const { rerender } = render(<FormDuration label="TTL" value={300} helperText="Pick a duration" onChange={() => {}} />)
    expect(screen.getByText('Pick a duration')).toBeInTheDocument()
    rerender(<FormDuration label="TTL" value={300} error="Required" onChange={() => {}} />)
    expect(screen.getByText('Required')).toBeInTheDocument()
  })
})
