// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import FormTagInput from './FormTagInput'

describe('FormTagInput', () => {
  it('renders label and placeholder', () => {
    render(<FormTagInput tags={[]} onChange={() => {}} label="Tags" placeholder="Add tags" />)
    expect(screen.getByText('Tags')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Add tags')).toBeInTheDocument()
  })

  it('adds tag on Enter', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={[]} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'hello{Enter}')
    expect(onChange).toHaveBeenCalledWith(['hello'])
  })

  it('adds tag on comma', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={[]} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'world,')
    expect(onChange).toHaveBeenCalledWith(['world'])
  })

  it('adds tag on blur', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={[]} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'blurme')
    await user.click(document.body)
    expect(onChange).toHaveBeenCalledWith(['blurme'])
  })

  it('removes tag via button', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={['a', 'b']} onChange={onChange} />)
    const removeButtons = screen.getAllByLabelText(/Remove/)
    await user.click(removeButtons[0])
    expect(onChange).toHaveBeenCalledWith(['b'])
  })

  it('removes last tag on Backspace with empty input', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={['a']} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, '{Backspace}')
    expect(onChange).toHaveBeenCalledWith([])
  })

  it('shows max count', () => {
    render(<FormTagInput tags={['a']} onChange={() => {}} maxTags={5} />)
    expect(screen.getByText('1/5')).toBeInTheDocument()
  })

  it('does not add duplicate tags', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={['hello']} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'hello{Enter}')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not add empty tags', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={[]} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, '   {Enter}')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('adds tags on paste', () => {
    const onChange = vi.fn()
    render(<FormTagInput tags={[]} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    fireEvent.paste(input, {
      clipboardData: { getData: () => 'a,b' } as unknown as DataTransfer,
    })
    expect(onChange).toHaveBeenCalledWith(['a', 'b'])
  })

  it('respects maxTags on paste', () => {
    const onChange = vi.fn()
    render(<FormTagInput tags={['x']} onChange={onChange} maxTags={2} />)
    const input = screen.getByRole('textbox')
    fireEvent.paste(input, {
      clipboardData: { getData: () => 'a,b,c' } as unknown as DataTransfer,
    })
    expect(onChange).toHaveBeenCalledWith(['x', 'a'])
  })

  it('disables input when maxTags reached', () => {
    render(<FormTagInput tags={['a', 'b']} onChange={() => {}} maxTags={2} />)
    expect(screen.getByRole('textbox')).toBeDisabled()
  })

  it('hides remove buttons when disabled', () => {
    render(<FormTagInput tags={['a']} onChange={() => {}} disabled />)
    expect(screen.queryByLabelText('Remove a')).not.toBeInTheDocument()
  })

  it('does not add tag on blur when maxTags reached', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={['a', 'b']} onChange={onChange} maxTags={2} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'c')
    await user.click(document.body)
    expect(onChange).not.toHaveBeenCalled()
  })

  it('ignores backspace when input has text', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormTagInput tags={['a']} onChange={onChange} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'x{Backspace}')
    expect(onChange).not.toHaveBeenCalled()
  })
})
