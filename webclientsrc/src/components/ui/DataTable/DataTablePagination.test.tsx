// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import DataTablePagination from './DataTablePagination'
import { DataTableContext } from './types'

const mockActions = {
  setPage: vi.fn(),
  setPerPage: vi.fn(),
  setSort: vi.fn(),
  setSearch: vi.fn(),
  setFilter: vi.fn(),
  toggleSelection: vi.fn(),
  toggleAll: vi.fn(),
  clearSelection: vi.fn(),
}

describe('DataTablePagination', () => {
  it('renders page info', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={1} perPage={10} total={25} startRow={1} endRow={10} />
      </DataTableContext.Provider>
    )
    expect(screen.getByText((_, el) => el?.textContent === 'Showing 1–10 of 25')).toBeInTheDocument()
  })

  it('changes page on button click', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={2} perPage={10} total={25} startRow={11} endRow={20} />
      </DataTableContext.Provider>
    )
    fireEvent.click(screen.getByLabelText('Previous page'))
    expect(mockActions.setPage).toHaveBeenCalledWith(1)
    fireEvent.click(screen.getByLabelText('Next page'))
    expect(mockActions.setPage).toHaveBeenCalledWith(3)
  })

  it('changes per page', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={1} perPage={10} total={100} startRow={1} endRow={10} />
      </DataTableContext.Provider>
    )
    fireEvent.change(screen.getByLabelText('Rows'), { target: { value: '50' } })
    expect(mockActions.setPerPage).toHaveBeenCalledWith(50)
  })

  it('disables previous on first page', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={1} perPage={10} total={100} startRow={1} endRow={10} />
      </DataTableContext.Provider>
    )
    expect(screen.getByLabelText('Previous page')).toBeDisabled()
  })

  it('disables next on last page', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={10} perPage={10} total={100} startRow={91} endRow={100} />
      </DataTableContext.Provider>
    )
    expect(screen.getByLabelText('Next page')).toBeDisabled()
  })

  it('renders ellipsis for many pages', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={5} perPage={10} total={200} startRow={41} endRow={50} />
      </DataTableContext.Provider>
    )
    expect(screen.getAllByText('…').length).toBeGreaterThan(0)
  })

  it('jumps to a specific page on button click', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={1} perPage={10} total={100} startRow={1} endRow={10} />
      </DataTableContext.Provider>
    )
    fireEvent.click(screen.getByText('5'))
    expect(mockActions.setPage).toHaveBeenCalledWith(5)
  })

  it('renders first page as active', () => {
    render(
      <DataTableContext.Provider value={{ state: {} as never, actions: mockActions }}>
        <DataTablePagination page={1} perPage={10} total={50} startRow={1} endRow={10} />
      </DataTableContext.Provider>
    )
    expect(screen.getByRole('button', { current: 'page' })).toHaveTextContent('1')
  })
})
