// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import FormSelect from './FormSelect'

const options = [
  { value: 'a', label: 'Option A' },
  { value: 'b', label: 'Option B' },
  { value: 'c', label: 'Option C' },
]

const groupedOptions = [
  { value: 'g1a', label: 'G1 A', group: 'Group 1' },
  { value: 'g1b', label: 'G1 B', group: 'Group 1' },
  { value: 'g2a', label: 'G2 A', group: 'Group 2' },
]

describe('FormSelect', () => {
  it('renders label and placeholder', () => {
    render(<FormSelect options={options} onChange={() => {}} label="Choose" placeholder="Pick one" />)
    expect(screen.getByText('Choose')).toBeInTheDocument()
    expect(screen.getByText('Pick one')).toBeInTheDocument()
  })

  it('opens dropdown on click', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    expect(screen.getByText('Option A')).toBeInTheDocument()
  })

  it('selects option and closes dropdown', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSelect options={options} onChange={onChange} />)
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByText('Option B'))
    expect(onChange).toHaveBeenCalledWith('b')
  })

  it('filters options when searchable', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} searchable />)
    await user.click(screen.getByRole('button'))
    const searchInput = screen.getByPlaceholderText('Search...')
    await user.type(searchInput, 'B')
    expect(screen.getByText('Option B')).toBeInTheDocument()
    expect(screen.queryByText('Option A')).not.toBeInTheDocument()
  })

  it('closes on Escape', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })

  it('renders grouped options', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={groupedOptions} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByText('Group 1')).toBeInTheDocument()
    expect(screen.getByText('Group 2')).toBeInTheDocument()
  })

  it('renders option descriptions', async () => {
    const user = userEvent.setup()
    const descOptions = [{ value: 'x', label: 'X', description: 'Desc for X' }]
    render(<FormSelect options={descOptions} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByText('Desc for X')).toBeInTheDocument()
  })

  it('shows helper text', () => {
    render(<FormSelect options={options} onChange={() => {}} helperText="Pick wisely" />)
    expect(screen.getByText('Pick wisely')).toBeInTheDocument()
  })

  it('shows error message', () => {
    render(<FormSelect options={options} onChange={() => {}} error="Required" />)
    expect(screen.getByText('Required')).toBeInTheDocument()
  })

  it('disables the trigger', () => {
    render(<FormSelect options={options} onChange={() => {}} disabled />)
    expect(screen.getByRole('button')).toBeDisabled()
  })

  it('navigates options with keyboard', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSelect options={options} onChange={onChange} />)
    const trigger = screen.getByRole('button')
    trigger.focus()
    await user.keyboard('{ArrowDown}')
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{Enter}')
    expect(onChange).toHaveBeenCalledWith('b')
  })

  it('shows no results when search matches nothing', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} searchable />)
    await user.click(screen.getByRole('button'))
    const searchInput = screen.getByPlaceholderText('Search...')
    await user.type(searchInput, 'zzz')
    expect(screen.getByText('No results')).toBeInTheDocument()
  })

  it('closes on Tab', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.keyboard('{Tab}')
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })

  it('highlights option on mouse enter', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={options} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    const option = screen.getByText('Option B')
    fireEvent.mouseEnter(option)
    expect(option.closest('[role="option"]')).toHaveClass('bg-white/5')
  })

  it('closes dropdown when clicking outside', async () => {
    const user = userEvent.setup()
    render(
      <div>
        <FormSelect options={options} onChange={() => {}} />
        <button>Outside</button>
      </div>
    )
    await user.click(screen.getByRole('button', { name: /Select/i }))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.click(screen.getByText('Outside'))
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })

  it('navigates up with ArrowUp', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSelect options={options} onChange={onChange} />)
    const trigger = screen.getByRole('button')
    trigger.focus()
    await user.keyboard('{ArrowDown}')
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{ArrowDown}')
    await user.keyboard('{ArrowUp}')
    await user.keyboard('{Enter}')
    expect(onChange).toHaveBeenCalledWith('b')
  })

  it('renders descriptions in grouped options', async () => {
    const user = userEvent.setup()
    const descGrouped = [
      { value: 'g1a', label: 'G1 A', group: 'Group 1', description: 'Desc A' },
      { value: 'g1b', label: 'G1 B', group: 'Group 1', description: 'Desc B' },
    ]
    render(<FormSelect options={descGrouped} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByText('Desc A')).toBeInTheDocument()
    expect(screen.getByText('Desc B')).toBeInTheDocument()
  })

  it('highlights grouped option on mouse enter', async () => {
    const user = userEvent.setup()
    render(<FormSelect options={groupedOptions} onChange={() => {}} />)
    await user.click(screen.getByRole('button'))
    const option = screen.getByText('G1 A')
    fireEvent.mouseEnter(option)
    expect(option.closest('[role="option"]')).toHaveClass('bg-white/5')
  })

  it('selects grouped option on click', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FormSelect options={groupedOptions} onChange={onChange} />)
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByText('G2 A'))
    expect(onChange).toHaveBeenCalledWith('g2a')
  })
})
