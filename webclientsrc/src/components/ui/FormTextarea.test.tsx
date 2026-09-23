// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import FormTextarea from './FormTextarea'

describe('FormTextarea', () => {
  it('renders with label', () => {
    render(<FormTextarea label="Description" />)
    expect(screen.getByText('Description')).toBeInTheDocument()
  })

  it('shows error message', () => {
    render(<FormTextarea error="Required" />)
    expect(screen.getByText('Required')).toBeInTheDocument()
  })

  it('shows helper text when no error', () => {
    render(<FormTextarea helperText="Hint" />)
    expect(screen.getByText('Hint')).toBeInTheDocument()
  })

  it('applies monospace class', () => {
    render(<FormTextarea monospace data-testid="ta" />)
    expect(screen.getByTestId('ta')).toHaveClass('font-mono')
  })

  it('applies autoResize class', () => {
    render(<FormTextarea autoResize data-testid="ta" />)
    expect(screen.getByTestId('ta')).toHaveClass('resize-none')
  })

  it('handles function ref', () => {
    const refFn = vi.fn()
    render(<FormTextarea ref={refFn} data-testid="ta" />)
    expect(refFn).toHaveBeenCalled()
  })

  it('handles object ref', () => {
    const refObj = { current: null as HTMLTextAreaElement | null }
    render(<FormTextarea ref={refObj} data-testid="ta" />)
    expect(refObj.current).toBeInstanceOf(HTMLTextAreaElement)
  })

  it('shows error styling and message', () => {
    render(<FormTextarea error="Invalid input" data-testid="ta" />)
    expect(screen.getByText('Invalid input')).toBeInTheDocument()
    expect(screen.getByTestId('ta')).toHaveClass('border-alert-red')
  })
})
