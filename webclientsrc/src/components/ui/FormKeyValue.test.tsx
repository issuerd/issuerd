// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import FormKeyValue from './FormKeyValue'

describe('FormKeyValue', () => {
  it('renders entries and label', () => {
    render(<FormKeyValue label="Headers" value={{ a: '1', b: '2' }} onChange={() => {}} />)
    expect(screen.getByText('Headers')).toBeInTheDocument()
    expect(screen.getAllByDisplayValue('1')).toHaveLength(1)
    expect(screen.getAllByDisplayValue('2')).toHaveLength(1)
  })

  it('updates key', () => {
    const onChange = vi.fn()
    render(<FormKeyValue value={{ a: '1' }} onChange={onChange} />)
    const keyInput = screen.getAllByRole('textbox')[0]
    fireEvent.change(keyInput, { target: { value: 'b' } })
    expect(onChange).toHaveBeenCalledWith({ b: '1' })
  })

  it('updates value', () => {
    const onChange = vi.fn()
    render(<FormKeyValue value={{ a: '1' }} onChange={onChange} />)
    const valInput = screen.getAllByRole('textbox')[1]
    fireEvent.change(valInput, { target: { value: '2' } })
    expect(onChange).toHaveBeenCalledWith({ a: '2' })
  })

  it('removes entry', () => {
    const onChange = vi.fn()
    render(<FormKeyValue value={{ a: '1', b: '2' }} onChange={onChange} />)
    fireEvent.click(screen.getAllByLabelText('Remove row')[0])
    expect(onChange).toHaveBeenCalledWith({ b: '2' })
  })

  it('adds entry', () => {
    const onChange = vi.fn()
    render(<FormKeyValue value={{ a: '1' }} onChange={onChange} />)
    fireEvent.click(screen.getByText('Add row'))
    expect(onChange).toHaveBeenCalledWith({ a: '1', '': '' })
  })

  it('disables inputs and hides buttons when disabled', () => {
    render(<FormKeyValue value={{ a: '1' }} onChange={() => {}} disabled />)
    expect(screen.getAllByRole('textbox')[0]).toBeDisabled()
    expect(screen.queryByLabelText('Remove row')).not.toBeInTheDocument()
    expect(screen.queryByText('Add row')).not.toBeInTheDocument()
  })

  it('shows helper text', () => {
    render(<FormKeyValue value={{}} onChange={() => {}} helperText="Hint" />)
    expect(screen.getByText('Hint')).toBeInTheDocument()
  })
})
