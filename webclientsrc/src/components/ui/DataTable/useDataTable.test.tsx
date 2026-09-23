// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useDataTable, useClientPagination, useSelectionCount, useUrlTableState } from './useDataTable'
import { DataTableContext } from './types'
import type { DataTableState, DataTableActions } from './types'

function wrapper(state: DataTableState, actions: DataTableActions<unknown>) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <DataTableContext.Provider value={{ state, actions }}>{children}</DataTableContext.Provider>
  }
}

describe('useDataTable', () => {
  it('throws when used outside provider', () => {
    expect(() => renderHook(() => useDataTable())).toThrow(/must be used inside a DataTable provider/)
  })

  it('returns state and actions', () => {
    const state: DataTableState = {
      sort: null,
      filters: {},
      pagination: { page: 1, perPage: 10 },
      selection: new Set(),
    }
    const actions = {
      setSort: vi.fn(),
      toggleSort: vi.fn(),
      setFilter: vi.fn(),
      clearFilters: vi.fn(),
      setPage: vi.fn(),
      setPerPage: vi.fn(),
      toggleSelection: vi.fn(),
      toggleAllSelection: vi.fn(),
      clearSelection: vi.fn(),
      isSelected: vi.fn(),
      areAllSelected: vi.fn(),
      someSelected: vi.fn(),
      sortedData: [],
    }
    const { result } = renderHook(() => useDataTable(), { wrapper: wrapper(state, actions) })
    expect(result.current.state.pagination.page).toBe(1)
    expect(result.current.actions.setPage).toBe(actions.setPage)
  })
})

describe('useClientPagination', () => {
  it('returns correct slice', () => {
    const { result } = renderHook(() => useClientPagination([1, 2, 3, 4, 5], 2, 2))
    expect(result.current).toEqual([3, 4])
  })
})

describe('useSelectionCount', () => {
  it('returns selection size', () => {
    const { result } = renderHook(() => useSelectionCount(new Set(['a', 'b'])))
    expect(result.current).toBe(2)
  })
})

describe('useUrlTableState', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reads defaults when no params', () => {
    vi.stubGlobal('window', { location: { search: '' } } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    expect(result.current.read()).toEqual({ page: 1, perPage: 25, sort: null, search: null })
  })

  it('reads page and perPage from URL', () => {
    vi.stubGlobal('window', {
      location: { search: '?t_page=3&t_perPage=50&t_sort=name:asc&t_search=foo' },
    } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    expect(result.current.read()).toEqual({ page: 3, perPage: 50, sort: 'name:asc', search: 'foo' })
  })

  it('falls back to defaults for invalid perPage', () => {
    vi.stubGlobal('window', {
      location: { search: '?t_perPage=999' },
    } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    expect(result.current.read().perPage).toBe(25)
  })

  it('writes params to history', () => {
    const replaceState = vi.fn()
    vi.stubGlobal('window', {
      location: { search: '', pathname: '/test' },
      history: { replaceState },
    } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    result.current.write({ page: 2, search: 'bar' })
    expect(replaceState).toHaveBeenCalledWith({}, '', '/test?t_page=2&t_search=bar')
  })

  it('removes params when value is null', () => {
    const replaceState = vi.fn()
    vi.stubGlobal('window', {
      location: { search: '?t_page=2', pathname: '/test' },
      history: { replaceState },
    } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    result.current.write({ page: null })
    expect(replaceState).toHaveBeenCalledWith({}, '', '/test?')
  })

  it('clears search param when empty string is written', () => {
    const replaceState = vi.fn()
    vi.stubGlobal('window', {
      location: { search: '?t_search=foo', pathname: '/test' },
      history: { replaceState },
    } as unknown as Window & typeof globalThis)
    const { result } = renderHook(() => useUrlTableState('t'))
    result.current.write({ search: '' })
    expect(replaceState).toHaveBeenCalledWith({}, '', '/test?')
  })
})
