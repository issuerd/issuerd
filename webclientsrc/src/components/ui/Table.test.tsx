// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Table, Thead, Tbody, Tr, Th, Td } from './Table'

describe('Table components', () => {
  it('renders full table', () => {
    render(
      <Table>
        <Thead>
          <Tr>
            <Th>A</Th>
            <Th align="right">B</Th>
          </Tr>
        </Thead>
        <Tbody>
          <Tr onClick={() => {}}>
            <Td>1</Td>
            <Td align="right" className="extra">2</Td>
          </Tr>
        </Tbody>
      </Table>
    )
    expect(screen.getByText('A')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toHaveClass('extra')
  })

  it('applies Table className', () => {
    const { container } = render(<Table className="my-table">x</Table>)
    expect(container.firstChild).toHaveClass('my-table')
  })
})
