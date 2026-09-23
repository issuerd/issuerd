// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SearchBar from './SearchBar'

describe('SearchBar', () => {
  it('renders placeholder', () => {
    render(<SearchBar placeholder="Find..." />)
    expect(screen.getByPlaceholderText('Find...')).toBeInTheDocument()
  })

  it('calls onChange when typing', () => {
    const onChange = vi.fn()
    render(<SearchBar onChange={onChange} />)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'hello' } })
    expect(onChange).toHaveBeenCalledWith('hello')
  })

  it('shows clear button when value is present', () => {
    const onChange = vi.fn()
    render(<SearchBar value="hello" onChange={onChange} />)
    fireEvent.click(screen.getByRole('button'))
    expect(onChange).toHaveBeenCalledWith('')
  })

  it('shows shortcut hint when empty', () => {
    render(<SearchBar />)
    expect(screen.getByText('Ctrl+K')).toBeInTheDocument()
  })
})
