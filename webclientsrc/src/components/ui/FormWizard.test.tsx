// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import FormWizard from './FormWizard'

describe('FormWizard', () => {
  const steps = [
    { id: 's1', title: 'Step 1', content: <div data-testid="step1">Content 1</div> },
    { id: 's2', title: 'Step 2', content: <div data-testid="step2">Content 2</div> },
    { id: 's3', title: 'Step 3', content: <div data-testid="step3">Content 3</div> },
  ]

  it('renders first step by default', () => {
    render(<FormWizard steps={steps} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.getByTestId('step1')).toBeInTheDocument()
  })

  it('advances to next step on Next', async () => {
    const user = userEvent.setup()
    render(<FormWizard steps={steps} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
  })

  it('goes back on Back', async () => {
    const user = userEvent.setup()
    render(<FormWizard steps={steps} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
    const backButtons = screen.getAllByRole('button', { name: /Back/i })
    await user.click(backButtons[0])
    await waitFor(() => expect(screen.getByTestId('step1')).toBeInTheDocument())
  })

  it('calls onSubmit on last step', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<FormWizard steps={steps} onSubmit={onSubmit} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step3')).toBeInTheDocument())
    const createButtons = screen.getAllByRole('button', { name: /Create/i })
    await user.click(createButtons[0])
    expect(onSubmit).toHaveBeenCalled()
  })

  it('calls onCancel on Cancel', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(<FormWizard steps={steps} onSubmit={() => {}} onCancel={onCancel} />)
    const cancelButtons = screen.getAllByRole('button', { name: /Cancel/i })
    await user.click(cancelButtons[0])
    expect(onCancel).toHaveBeenCalled()
  })

  it('blocks advance when validate returns false', async () => {
    const user = userEvent.setup()
    const stepsWithValidate = [
      { id: 's1', title: 'Step 1', content: <div data-testid="step1">Content 1</div>, validate: () => false },
      { id: 's2', title: 'Step 2', content: <div data-testid="step2">Content 2</div> },
    ]
    render(<FormWizard steps={stepsWithValidate} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.queryByTestId('step2')).not.toBeInTheDocument())
    expect(screen.getByTestId('step1')).toBeInTheDocument()
  })

  it('allows advance when validate returns true', async () => {
    const user = userEvent.setup()
    const stepsWithValidate = [
      { id: 's1', title: 'Step 1', content: <div data-testid="step1">Content 1</div>, validate: () => true },
      { id: 's2', title: 'Step 2', content: <div data-testid="step2">Content 2</div> },
    ]
    render(<FormWizard steps={stepsWithValidate} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
  })

  it('allows advance when validate returns resolved promise true', async () => {
    const user = userEvent.setup()
    const stepsWithValidate = [
      { id: 's1', title: 'Step 1', content: <div data-testid="step1">Content 1</div>, validate: async () => true },
      { id: 's2', title: 'Step 2', content: <div data-testid="step2">Content 2</div> },
    ]
    render(<FormWizard steps={stepsWithValidate} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
  })

  it('jumps back to done step when clicking step indicator', async () => {
    const user = userEvent.setup()
    render(<FormWizard steps={steps} onSubmit={() => {}} onCancel={() => {}} />)
    const nextButtons = screen.getAllByRole('button', { name: /Next/i })
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step2')).toBeInTheDocument())
    await user.click(nextButtons[0])
    await waitFor(() => expect(screen.getByTestId('step3')).toBeInTheDocument())
    // Click on step 1 indicator (done state — first button in step indicators row)
    const stepIndicators = screen.getAllByRole('button', { type: 'button' }).filter((b) =>
      b.className.includes('rounded-full')
    )
    await user.click(stepIndicators[0])
    await waitFor(() => expect(screen.getByTestId('step1')).toBeInTheDocument())
  })

  it('renders step description', () => {
    const stepsWithDesc = [
      { id: 's1', title: 'Step 1', description: 'Desc 1', content: <div>Content</div> },
    ]
    render(<FormWizard steps={stepsWithDesc} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.getByText('Desc 1')).toBeInTheDocument()
  })

  it('uses custom submitLabel', async () => {
    const user = userEvent.setup()
    const stepsSingle = [
      { id: 's1', title: 'Step 1', content: <div>Content</div> },
    ]
    render(<FormWizard steps={stepsSingle} onSubmit={() => {}} onCancel={() => {}} submitLabel="Save" />)
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument()
  })
})
