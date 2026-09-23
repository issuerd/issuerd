// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import FormSwitch from './FormSwitch'

describe('FormSwitch', () => {
  it('renders label', () => {
    render(<FormSwitch checked={false} onChange={() => {}} label="Enabled" />)
    expect(screen.getByText('Enabled')).toBeInTheDocument()
  })

  it('renders helper text', () => {
    render(
      <FormSwitch
        checked={false}
        onChange={() => {}}
        label="Enabled"
        helperText="Toggle to enable"
      />
    )
    expect(screen.getByText('Toggle to enable')).toBeInTheDocument()
  })

  it('calls onChange when clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSwitch checked={false} onChange={onChange} label="Enabled" />)
    await user.click(screen.getByRole('switch'))
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('calls onChange when div is clicked', () => {
    const onChange = vi.fn()
    const { container } = render(<FormSwitch checked={false} onChange={onChange} label="Enabled" />)
    const div = container.querySelector('.cursor-pointer')
    if (div) fireEvent.click(div)
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('toggles with space key on div', () => {
    const onChange = vi.fn()
    const { container } = render(<FormSwitch checked={false} onChange={onChange} label="Enabled" />)
    const div = container.querySelector('[tabindex="0"]')
    if (div) fireEvent.keyDown(div, { key: ' ' })
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('toggles with Enter key on div', () => {
    const onChange = vi.fn()
    const { container } = render(<FormSwitch checked={false} onChange={onChange} label="Enabled" />)
    const div = container.querySelector('[tabindex="0"]')
    if (div) fireEvent.keyDown(div, { key: 'Enter' })
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('has correct aria-checked', () => {
    const { rerender } = render(
      <FormSwitch checked={false} onChange={() => {}} label="Enabled" />
    )
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
    rerender(<FormSwitch checked={true} onChange={() => {}} label="Enabled" />)
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  })

  it('does not toggle when disabled', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSwitch checked={false} onChange={onChange} label="Enabled" disabled />)
    await user.click(screen.getByRole('switch'))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not toggle div when disabled', () => {
    const onChange = vi.fn()
    const { container } = render(<FormSwitch checked={false} onChange={onChange} disabled />)
    const div = container.querySelector('.cursor-pointer')
    if (div) fireEvent.click(div)
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not toggle div keydown when disabled', () => {
    const onChange = vi.fn()
    const { container } = render(<FormSwitch checked={false} onChange={onChange} disabled />)
    const div = container.querySelector('[tabindex="-1"]')
    if (div) fireEvent.keyDown(div, { key: ' ' })
    expect(onChange).not.toHaveBeenCalled()
  })

  it('accepts ref', () => {
    const ref = { current: null as HTMLInputElement | null }
    render(<FormSwitch checked={false} onChange={() => {}} ref={(el) => { ref.current = el }} />)
    expect(ref.current).toBeInstanceOf(HTMLInputElement)
  })
})
