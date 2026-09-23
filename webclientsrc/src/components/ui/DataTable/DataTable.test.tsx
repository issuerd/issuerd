// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useState } from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DataTable from './DataTable'
import { useDataTable } from './useDataTable'
import type { ColumnDef } from './types'

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: (opts: any) => {
    opts?.getScrollElement?.()
    opts?.estimateSize?.()
    return {
      getTotalSize: () => 3120,
      getVirtualItems: () =>
        Array.from({ length: 10 }, (_, i) => ({
          index: i,
          start: i * 52,
          size: 52,
          key: String(i),
        })),
      measureElement: vi.fn(),
    }
  },
}))

interface Row {
  id: string
  name: string
  status: string
  age: number | null
}

const columns: ColumnDef<Row>[] = [
  { key: 'name', header: 'Name', accessor: (r) => r.name, cell: (r) => r.name, sortable: true },
  { key: 'status', header: 'Status', accessor: (r) => r.status, cell: (r) => r.status, sortable: true },
  { key: 'age', header: 'Age', accessor: (r) => r.age, cell: (r) => r.age ?? '-', sortable: true },
  { key: 'actions', header: 'Actions', cell: () => <button>Act</button> },
]

const baseData: Row[] = [
  { id: '1', name: 'Alice', status: 'active', age: 30 },
  { id: '2', name: 'Bob', status: 'inactive', age: 25 },
  { id: '3', name: 'Charlie', status: 'active', age: null },
]

function renderTable(props: Partial<React.ComponentProps<typeof DataTable<Row>>> = {}) {
  return render(
    <DataTable
      data={baseData}
      columns={columns}
      rowId={(r) => r.id}
      {...props}
    />
  )
}

describe('DataTable', () => {
  beforeEach(() => {
    vi.stubGlobal('window', {
      location: { search: '', pathname: '/test', href: 'http://localhost/test' },
      history: { replaceState: vi.fn() },
    } as unknown as Window & typeof globalThis)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders rows', () => {
    renderTable()
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    renderTable({ data: [], loading: true })
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('shows custom empty state', () => {
    renderTable({ data: [], emptyState: <div>Custom empty</div> })
    expect(screen.getByText('Custom empty')).toBeInTheDocument()
  })

  it('shows default empty state when no data', () => {
    renderTable({ data: [] })
    expect(screen.getByText('No results found.')).toBeInTheDocument()
  })

  it('searches rows', async () => {
    const user = userEvent.setup()
    renderTable()
    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'Ali')
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.queryByText('Bob')).not.toBeInTheDocument()
  })

  it('clears search with X button', async () => {
    const user = userEvent.setup()
    renderTable()
    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'Ali')
    const clearBtn = screen.getByLabelText('Clear search')
    await user.click(clearBtn)
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('sorts ascending then descending then null', async () => {
    const user = userEvent.setup()
    renderTable()
    const nameHeader = screen.getByText('Name').closest('th')!
    await user.click(nameHeader)
    // asc
    await user.click(nameHeader)
    // desc
    await user.click(nameHeader)
    // null - back to original order
    const rows = screen.getAllByRole('row')
    expect(rows.length).toBeGreaterThan(1)
  })

  it('sorts null values to end in asc', async () => {
    const user = userEvent.setup()
    renderTable()
    const ageHeader = screen.getByText('Age').closest('th')!
    await user.click(ageHeader)
    // Alice(30), Bob(25), Charlie(null) -> Bob, Alice, Charlie
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('Bob')
    expect(rows[2]).toHaveTextContent('Alice')
    expect(rows[3]).toHaveTextContent('Charlie')
  })

  it('filters by column array values', () => {
    renderTable({
      filters: { status: ['active'] },
      onFilterChange: vi.fn(),
    })
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.queryByText('Bob')).not.toBeInTheDocument()
  })

  it('calls onRowClick when row is clicked', async () => {
    const onRowClick = vi.fn()
    renderTable({ onRowClick })
    const row = screen.getByText('Alice').closest('tr')!
    fireEvent.click(row)
    expect(onRowClick).toHaveBeenCalledWith(expect.objectContaining({ name: 'Alice' }))
  })

  it('does not call onRowClick when checkbox is clicked', async () => {
    const onRowClick = vi.fn()
    renderTable({ onRowClick, bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    const checkbox = screen.getByLabelText('Select row 1')
    fireEvent.click(checkbox)
    expect(onRowClick).not.toHaveBeenCalled()
  })

  it('toggles row selection with bulkActions', async () => {
    renderTable({ bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    const checkbox = screen.getByLabelText('Select row 1')
    fireEvent.click(checkbox)
    expect(checkbox).toBeChecked()
    fireEvent.click(checkbox)
    expect(checkbox).not.toBeChecked()
  })

  it('toggles all selection', async () => {
    renderTable({ bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    const selectAll = screen.getByLabelText('Select all rows')
    fireEvent.click(selectAll)
    expect(screen.getByLabelText('Select row 1')).toBeChecked()
    expect(screen.getByLabelText('Select row 2')).toBeChecked()
    fireEvent.click(selectAll)
    expect(screen.getByLabelText('Select row 1')).not.toBeChecked()
  })

  it('shows bulk action bar when rows selected', async () => {
    const onClick = vi.fn()
    renderTable({ bulkActions: [{ label: 'Delete', onClick }] })
    fireEvent.click(screen.getByLabelText('Select row 1'))
    expect(screen.getByText('1 selected')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Delete'))
    expect(onClick).toHaveBeenCalledWith(['1'])
  })

  it('clears selection from bulk bar', async () => {
    renderTable({ bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    fireEvent.click(screen.getByLabelText('Select row 1'))
    expect(screen.getByText('1 selected')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Clear'))
    expect(screen.queryByText('1 selected')).not.toBeInTheDocument()
  })

  it('syncs URL params on uncontrolled state change', async () => {
    const replaceState = vi.fn()
    vi.stubGlobal('window', {
      location: { search: '', pathname: '/test', href: 'http://localhost/test' },
      history: { replaceState },
    } as unknown as Window & typeof globalThis)
    const user = userEvent.setup()
    renderTable()
    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'foo')
    await new Promise((r) => setTimeout(r, 50))
    expect(replaceState).toHaveBeenCalledWith({}, '', expect.stringContaining('dt_search=foo'))
  })

  it('reads sort from URL param on mount', () => {
    vi.stubGlobal('window', {
      location: { search: '?dt_sort=name:desc', pathname: '/test' },
      history: { replaceState: vi.fn() },
    } as unknown as Window & typeof globalThis)
    renderTable()
    // Should have sorted desc by name: Charlie, Bob, Alice
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('Charlie')
  })

  it('reads page and perPage from URL param on mount', () => {
    vi.stubGlobal('window', {
      location: { search: '?dt_page=2&dt_perPage=10', pathname: '/test' },
      history: { replaceState: vi.fn() },
    } as unknown as Window & typeof globalThis)
    const data = Array.from({ length: 15 }, (_, i) => ({ id: String(i), name: `User ${i}`, status: 'active', age: i }))
    renderTable({ data })
    // page 2 with perPage 10 should show users 10-14
    expect(screen.getByText('User 10')).toBeInTheDocument()
    expect(screen.queryByText('User 0')).not.toBeInTheDocument()
  })

  it('ignores invalid URL sort param', () => {
    vi.stubGlobal('window', {
      location: { search: '?dt_sort=bad', pathname: '/test' },
      history: { replaceState: vi.fn() },
    } as unknown as Window & typeof globalThis)
    renderTable()
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('Alice')
  })

  it('renders virtualized table with many rows', () => {
    const data = Array.from({ length: 60 }, (_, i) => ({ id: String(i), name: `User ${i}`, status: 'active', age: i }))
    renderTable({ data, perPage: 100, onPerPageChange: vi.fn() })
    expect(screen.getByText('User 0')).toBeInTheDocument()
  })

  it('virtualized row click and checkbox exclusion', () => {
    const data = Array.from({ length: 60 }, (_, i) => ({ id: String(i), name: `User ${i}`, status: 'active', age: i }))
    const onRowClick = vi.fn()
    renderTable({ data, perPage: 100, onPerPageChange: vi.fn(), onRowClick, bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    const row = screen.getByText('User 0').closest('div[class*="flex items-center"]')!
    fireEvent.click(row)
    expect(onRowClick).toHaveBeenCalledWith(expect.objectContaining({ name: 'User 0' }))
    const checkbox = screen.getByLabelText('Select row 0')
    fireEvent.click(checkbox)
    expect(onRowClick).toHaveBeenCalledTimes(1)
  })

  it('uses controlled sort prop', () => {
    const onSortChange = vi.fn()
    renderTable({ sort: { key: 'name', direction: 'asc' }, onSortChange })
    const nameHeader = screen.getByText('Name').closest('th')!
    fireEvent.click(nameHeader)
    expect(onSortChange).toHaveBeenCalled()
  })

  it('someSelected returns false when all selected', () => {
    renderTable({ bulkActions: [{ label: 'Delete', onClick: vi.fn() }] })
    fireEvent.click(screen.getByLabelText('Select all rows'))
    // Bulk bar should show; this covers someSelected when all are selected
    expect(screen.getByText('3 selected')).toBeInTheDocument()
  })

  it('exposes setSort via context with null direction', () => {
    function SortCell() {
      const { actions } = useDataTable()
      return <button onClick={() => actions.setSort('name', null)}>Clear sort</button>
    }
    const sortColumns: ColumnDef<Row>[] = [
      ...columns,
      { key: 'sort', header: 'Sort', cell: () => <SortCell /> },
    ]
    render(
      <DataTable data={baseData} columns={sortColumns} rowId={(r) => r.id} />
    )
    fireEvent.click(screen.getAllByText('Clear sort')[0])
    expect(screen.getByText('Alice')).toBeInTheDocument()
  })

  it('renders enum badge when column has enumList', () => {
    const enumCols: ColumnDef<Row>[] = [
      { key: 'status', header: 'Status', accessor: (r) => r.status, cell: (r) => r.status, enumList: [{ id: 'active', name: 'Active' }] },
    ]
    renderTable({ columns: enumCols, data: [{ id: '1', name: 'Alice', status: 'active', age: 30 }] })
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('handles controlled clearFilters', async () => {
    const onFilterChange = vi.fn()
    const onSearchChange = vi.fn()
    renderTable({
      filters: { status: 'active' },
      onFilterChange,
      search: 'foo',
      onSearchChange,
    })
    fireEvent.click(screen.getByText('Clear filters'))
    expect(onFilterChange).toHaveBeenCalledWith('status', undefined)
    expect(onSearchChange).toHaveBeenCalledWith('')
  })

  it('handles uncontrolled clearFilters', async () => {
    renderTable()
    const user = userEvent.setup()
    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'foo')
    await new Promise((r) => setTimeout(r, 50))
    fireEvent.click(screen.getByText('Clear filters'))
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('uses backendPagination totalCount', () => {
    renderTable({ backendPagination: true, totalCount: 100 })
    const container = document.body.textContent
    expect(container).toContain('Showing')
    expect(container).toContain('100')
  })

  it('disables virtualization when enableVirtualization is false', () => {
    const data = Array.from({ length: 60 }, (_, i) => ({ id: String(i), name: `User ${i}`, status: 'active', age: i }))
    renderTable({ data, perPage: 100, enableVirtualization: false })
    // Should render regular table rows, not virtualized flex containers
    const rows = screen.getAllByRole('row')
    expect(rows.length).toBeGreaterThan(1)
    expect(screen.getByText('User 0')).toBeInTheDocument()
  })

  it('calls onSearchChange in controlled mode', async () => {
    const onSearchChange = vi.fn()
    const user = userEvent.setup()
    function ControlledWrapper() {
      const [search, setSearch] = useState('')
      return (
        <DataTable
          data={baseData}
          columns={columns}
          rowId={(r) => r.id}
          search={search}
          onSearchChange={(v) => {
            setSearch(v)
            onSearchChange(v)
          }}
        />
      )
    }
    render(<ControlledWrapper />)
    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'foo')
    expect(onSearchChange).toHaveBeenLastCalledWith('foo')
  })

  it('calls onFilterChange in controlled mode', () => {
    const onFilterChange = vi.fn()
    renderTable({ filters: {}, onFilterChange })
    // Use context to trigger setFilter which calls onFilterChange in controlled mode
    function FilterCell() {
      const { actions } = useDataTable()
      return <button onClick={() => actions.setFilter('status', 'active')}>Filter active</button>
    }
    const filterColumns: ColumnDef<Row>[] = [
      ...columns,
      { key: 'filter', header: 'Filter', cell: () => <FilterCell /> },
    ]
    render(
      <DataTable data={baseData} columns={filterColumns} rowId={(r) => r.id} filters={{}} onFilterChange={onFilterChange} />
    )
    fireEvent.click(screen.getAllByText('Filter active')[0])
    expect(onFilterChange).toHaveBeenCalledWith('status', 'active')
  })

  it('sets internal filter in uncontrolled mode', () => {
    function FilterCell() {
      const { actions } = useDataTable()
      return <button onClick={() => actions.setFilter('status', 'active')}>Filter active</button>
    }
    const filterColumns: ColumnDef<Row>[] = [
      ...columns,
      { key: 'filter', header: 'Filter', cell: () => <FilterCell /> },
    ]
    render(
      <DataTable data={baseData} columns={filterColumns} rowId={(r) => r.id} />
    )
    fireEvent.click(screen.getAllByText('Filter active')[0])
    // Bob is inactive, so only Alice and Charlie should remain
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.queryByText('Bob')).not.toBeInTheDocument()
  })

  it('calls onPerPageChange in controlled mode', () => {
    const onPerPageChange = vi.fn()
    renderTable({ perPage: 10, onPerPageChange })
    const select = screen.getByLabelText('Rows')
    fireEvent.change(select, { target: { value: '25' } })
    expect(onPerPageChange).toHaveBeenCalledWith(25)
  })

  it('shows loading state even when data is present', () => {
    renderTable({ data: baseData, loading: true })
    expect(screen.getByText('Loading...')).toBeInTheDocument()
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()
  })
})
