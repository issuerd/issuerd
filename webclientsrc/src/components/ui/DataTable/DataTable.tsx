// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useCallback, useMemo, useRef, useState, useEffect } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { cn } from '@/lib/utils'
import { ChevronDown, ChevronUp, ChevronsUpDown, Search, X } from 'lucide-react'
import type { ColumnDef, DataTableState, SortDirection } from './types'
import { DataTableContext } from './types'
import DataTablePagination from './DataTablePagination'
import EnumBadge from '../EnumBadge'
import Button from '../Button'

interface DataTableProps<T> {
  data: T[]
  columns: ColumnDef<T>[]
  rowId: (row: T) => string
  totalCount?: number
  loading?: boolean
  backendPagination?: boolean
  page?: number
  perPage?: number
  onPageChange?: (page: number) => void
  onPerPageChange?: (perPage: number) => void
  sort?: { key: string; direction: SortDirection } | null
  onSortChange?: (sort: { key: string; direction: SortDirection } | null) => void
  search?: string
  onSearchChange?: (search: string) => void
  filters?: Record<string, string | string[] | undefined>
  onFilterChange?: (key: string, value: string | string[] | undefined) => void
  bulkActions?: { label: string; variant?: 'primary' | 'danger' | 'ghost'; icon?: React.ReactNode; onClick: (ids: string[]) => void }[]
  emptyState?: React.ReactNode
  className?: string
  tableKey?: string
  enableVirtualization?: boolean
  onRowClick?: (row: T) => void
  rowClassName?: (row: T) => string | undefined
}

function parseSortParam(sort: string | null | undefined): { key: string; direction: SortDirection } | null {
  if (!sort) return null
  const [key, dir] = sort.split(':')
  if (!key || (dir !== 'asc' && dir !== 'desc')) return null
  return { key, direction: dir as SortDirection }
}

function serializeSort(sort: { key: string; direction: SortDirection } | null): string | null {
  if (!sort || !sort.direction) return null
  return `${sort.key}:${sort.direction}`
}

export default function DataTable<T>({
  data,
  columns,
  rowId,
  totalCount,
  loading,
  backendPagination = false,
  page: controlledPage,
  perPage: controlledPerPage,
  onPageChange,
  onPerPageChange,
  sort: controlledSort,
  onSortChange,
  search: controlledSearch,
  onSearchChange,
  filters: controlledFilters,
  onFilterChange,
  bulkActions,
  emptyState,
  className,
  tableKey = 'dt',
  enableVirtualization = true,
  onRowClick,
  rowClassName,
}: DataTableProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null)

  // Internal state for uncontrolled usage
  const [internalPage, setInternalPage] = useState(1)
  const [internalPerPage, setInternalPerPage] = useState(25)
  const [internalSort, setInternalSort] = useState<{ key: string; direction: SortDirection } | null>(null)
  const [internalSearch, setInternalSearch] = useState('')
  const [internalFilters, setInternalFilters] = useState<Record<string, string | string[] | undefined>>({})
  const [selection, setSelection] = useState<Set<string>>(new Set())

  // URL sync for controlled mode
  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    const sortParam = params.get(`${tableKey}_sort`)
    const searchParam = params.get(`${tableKey}_search`)
    const pageParam = params.get(`${tableKey}_page`)
    const perPageParam = params.get(`${tableKey}_perPage`)

    if (sortParam && !controlledSort) {
      const parsed = parseSortParam(sortParam)
      if (parsed) setInternalSort(parsed)
    }
    if (searchParam && controlledSearch === undefined) {
      setInternalSearch(searchParam)
    }
    if (pageParam && controlledPage === undefined) {
      const p = parseInt(pageParam, 10)
      if (!Number.isNaN(p)) setInternalPage(Math.max(1, p))
    }
    if (perPageParam && controlledPerPage === undefined) {
      const pp = parseInt(perPageParam, 10)
      if ([10, 25, 50, 100].includes(pp)) setInternalPerPage(pp)
    }
  }, [tableKey, controlledSort, controlledSearch, controlledPage, controlledPerPage])

  const page = controlledPage ?? internalPage
  const perPage = controlledPerPage ?? internalPerPage
  const sort = controlledSort ?? internalSort
  const search = controlledSearch ?? internalSearch
  const filters = controlledFilters ?? internalFilters

  const updateUrl = useCallback(
    (updates: Record<string, string | null>) => {
      if (typeof window === 'undefined') return
      const params = new URLSearchParams(window.location.search)
      Object.entries(updates).forEach(([key, value]) => {
        if (value === null || value === '') {
          params.delete(`${tableKey}_${key}`)
        } else {
          params.set(`${tableKey}_${key}`, value)
        }
      })
      window.history.replaceState({}, '', `${window.location.pathname}?${params.toString()}`)
    },
    [tableKey]
  )

  const setPage = useCallback(
    (p: number) => {
      if (onPageChange) onPageChange(p)
      else {
        setInternalPage(p)
        updateUrl({ page: String(p) })
      }
      setSelection(new Set())
    },
    [onPageChange, updateUrl]
  )

  const setPerPage = useCallback(
    (pp: number) => {
      if (onPerPageChange) onPerPageChange(pp)
      else {
        setInternalPerPage(pp)
        setInternalPage(1)
        updateUrl({ perPage: String(pp), page: '1' })
      }
      setSelection(new Set())
    },
    [onPerPageChange, updateUrl]
  )

  const setSort = useCallback(
    (nextSort: { key: string; direction: SortDirection } | null) => {
      if (onSortChange) {
        onSortChange(nextSort)
      } else {
        setInternalSort(nextSort)
        updateUrl({ sort: serializeSort(nextSort) })
      }
    },
    [onSortChange, updateUrl]
  )

  const toggleSort = useCallback(
    (key: string) => {
      if (!sort || sort.key !== key) {
        setSort({ key, direction: 'asc' })
      } else if (sort.direction === 'asc') {
        setSort({ key, direction: 'desc' })
      } else {
        setSort(null)
      }
    },
    [sort, setSort]
  )

  const setSearch = useCallback(
    (value: string) => {
      if (onSearchChange) {
        onSearchChange(value)
      } else {
        setInternalSearch(value)
        setInternalPage(1)
        updateUrl({ search: value || null, page: '1' })
      }
      setSelection(new Set())
    },
    [onSearchChange, updateUrl]
  )

  const setFilter = useCallback(
    (key: string, value: string | string[] | undefined) => {
      if (onFilterChange) {
        onFilterChange(key, value)
      } else {
        setInternalFilters((prev) => ({ ...prev, [key]: value }))
        setInternalPage(1)
      }
      setSelection(new Set())
    },
    [onFilterChange]
  )

  const clearFilters = useCallback(() => {
    if (onFilterChange) {
      Object.keys(filters).forEach((k) => onFilterChange(k, undefined))
    } else {
      setInternalFilters({})
      setInternalSearch('')
      setInternalPage(1)
      updateUrl({ search: null, page: '1' })
    }
    if (onSearchChange) onSearchChange('')
  }, [filters, onFilterChange, onSearchChange, updateUrl])

  // Client-side sorting + filtering
  const filteredData = useMemo(() => {
    let result = data
    if (search) {
      const q = search.toLowerCase()
      result = result.filter((row) =>
        columns.some((col) => {
          const raw = col.accessor ? col.accessor(row) : null
          if (raw === null || raw === undefined) return false
          return String(raw).toLowerCase().includes(q)
        })
      )
    }
    Object.entries(filters).forEach(([key, value]) => {
      if (!value) return
      const col = columns.find((c) => c.key === key)
      if (!col?.accessor) return
      const values = Array.isArray(value) ? value : [value]
      result = result.filter((row) => {
        const raw = col.accessor!(row)
        return values.some((v) => String(raw) === v)
      })
    })
    return result
  }, [data, search, filters, columns])

  const sortedData = useMemo(() => {
    if (!sort || !sort.direction) return filteredData
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.accessor) return filteredData
    const dir = sort.direction === 'asc' ? 1 : -1
    return [...filteredData].sort((a, b) => {
      const av = col.accessor!(a)
      const bv = col.accessor!(b)
      if (av === null || av === undefined) return 1
      if (bv === null || bv === undefined) return -1
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
      return String(av).localeCompare(String(bv)) * dir
    })
  }, [filteredData, sort, columns])

  const paginatedData = useMemo(() => {
    if (backendPagination) return sortedData
    const start = (page - 1) * perPage
    return sortedData.slice(start, start + perPage)
  }, [sortedData, backendPagination, page, perPage])

  const total = backendPagination ? (totalCount ?? data.length) : sortedData.length

  // Selection
  const pageIds = useMemo(() => paginatedData.map(rowId), [paginatedData, rowId])

  const toggleSelection = useCallback((id: string) => {
    setSelection((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggleAllSelection = useCallback(
    (ids: string[]) => {
      setSelection((prev) => {
        const allSelected = ids.length > 0 && ids.every((id) => prev.has(id))
        if (allSelected) {
          const next = new Set(prev)
          ids.forEach((id) => next.delete(id))
          return next
        }
        return new Set([...prev, ...ids])
      })
    },
    []
  )

  const clearSelection = useCallback(() => setSelection(new Set()), [])

  const isSelected = useCallback((id: string) => selection.has(id), [selection])
  const areAllSelected = useCallback(
    (ids: string[]) => ids.length > 0 && ids.every((id) => selection.has(id)),
    [selection]
  )
  const someSelected = useCallback(
    (ids: string[]) => ids.some((id) => selection.has(id)) && !areAllSelected(ids),
    [selection, areAllSelected]
  )

  // Virtualization
  const useVirtual = enableVirtualization && paginatedData.length > 50
  const virtualizer = useVirtualizer({
    count: paginatedData.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 52,
    overscan: 5,
    enabled: useVirtual,
  })

  const state: DataTableState = {
    sort,
    filters: { ...filters, search },
    pagination: { page, perPage },
    selection,
  }

  const actions = {
    setSort: (key: string, direction: SortDirection) => setSort(direction ? { key, direction } : null),
    toggleSort,
    setFilter,
    clearFilters,
    setPage,
    setPerPage,
    toggleSelection,
    toggleAllSelection,
    clearSelection,
    isSelected,
    areAllSelected,
    someSelected,
    sortedData: sortedData as unknown[],
  }

  const startRow = (page - 1) * perPage + 1
  const endRow = Math.min(page * perPage, total)

  return (
    <DataTableContext.Provider value={{ state, actions }}>
      <div className={cn('flex flex-col gap-4', className)}>
        {/* Toolbar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" aria-hidden="true" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search..."
              className="w-full h-10 pl-9 pr-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-tertiary hover:text-text-primary"
                aria-label="Clear search"
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            )}
          </div>
          {(search || Object.values(filters).some(Boolean)) && (
            <button
              onClick={clearFilters}
              className="text-xs text-cyan-neon hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>

        {/* Table */}
        <div
          ref={parentRef}
          className={cn(
            'bg-surface-dark border border-border-custom rounded-xl overflow-hidden',
            useVirtual && 'overflow-auto max-h-[600px]'
          )}
        >
          <table className="w-full">
            <thead className="sticky top-0 z-10 bg-surface-dark">
              <tr className="bg-white/[0.02]">
                {bulkActions && (
                  <th className="w-12 px-4 h-12 text-left" scope="col">
                    <input
                      type="checkbox"
                      checked={areAllSelected(pageIds)}
                      ref={(el) => {
                        if (el) el.indeterminate = someSelected(pageIds)
                      }}
                      onChange={() => toggleAllSelection(pageIds)}
                      className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                      aria-label="Select all rows"
                    />
                  </th>
                )}
                {columns.map((col) => (
                  <th
                    key={col.key}
                    scope="col"
                    className={cn(
                      'px-4 h-12 text-left text-xs font-semibold uppercase tracking-wider text-text-secondary',
                      col.sortable && 'cursor-pointer select-none'
                    )}
                    style={{ width: col.width }}
                    onClick={() => col.sortable && toggleSort(col.key)}
                    aria-sort={
                      col.sortable
                        ? sort?.key === col.key
                          ? sort.direction === 'asc'
                            ? 'ascending'
                            : 'descending'
                          : 'none'
                        : undefined
                    }
                  >
                    <div className="flex items-center gap-1">
                      {col.header}
                      {col.sortable && (
                        <span className="inline-flex text-text-tertiary">
                          {sort?.key === col.key ? (
                            sort.direction === 'asc' ? (
                              <ChevronUp className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5" />
                            )
                          ) : (
                            <ChevronsUpDown className="w-3.5 h-3.5" />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan={columns.length + (bulkActions ? 1 : 0)}
                    className="px-4 py-8 text-center text-text-secondary"
                  >
                    Loading...
                  </td>
                </tr>
              ) : paginatedData.length === 0 ? (
                <tr>
                  <td
                    colSpan={columns.length + (bulkActions ? 1 : 0)}
                    className="px-4 py-8"
                  >
                    {emptyState ?? (
                      <div className="text-center text-text-tertiary text-sm">
                        No results found.
                      </div>
                    )}
                  </td>
                </tr>
              ) : useVirtual ? (
                <>
                  <tr style={{ height: `${virtualizer.getTotalSize()}px` }}>
                    <td
                      colSpan={columns.length + (bulkActions ? 1 : 0)}
                      className="p-0"
                    >
                      {virtualizer.getVirtualItems().map((virtualRow) => {
                        const row = paginatedData[virtualRow.index]
                        const id = rowId(row)
                        return (
                          <div
                            key={id}
                            data-index={virtualRow.index}
                            ref={virtualizer.measureElement}
                            style={{
                              transform: `translateY(${virtualRow.start}px)`,
                              position: 'absolute',
                              top: 0,
                              left: 0,
                              width: '100%',
                              height: `${virtualRow.size}px`,
                            }}
                            className={cn(
                              'flex items-center border-t border-border-custom table-row-hover-border',
                              onRowClick && 'cursor-pointer',
                              rowClassName?.(row)
                            )}
                            onClick={(e) => {
                              if ((e.target as HTMLElement).closest('input[type="checkbox"]')) return
                              onRowClick?.(row)
                            }}
                          >
                            {bulkActions && (
                              <div className="w-12 px-4 flex items-center">
                                <input
                                  type="checkbox"
                                  checked={isSelected(id)}
                                  onChange={() => toggleSelection(id)}
                                  className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                                  aria-label={`Select row ${id}`}
                                />
                              </div>
                            )}
                            {columns.map((col) => (
                              <div
                                key={col.key}
                                className="px-4 py-4 text-sm flex-1"
                                style={{ width: col.width }}
                              >
                                {col.enumList && col.accessor ? (
                                  <EnumBadge enumList={col.enumList} value={String(col.accessor(row) ?? '')} />
                                ) : (
                                  col.cell(row)
                                )}
                              </div>
                            ))}
                          </div>
                        )
                      })}
                    </td>
                  </tr>
                </>
              ) : (
                paginatedData.map((row) => {
                  const id = rowId(row)
                  return (
                    <tr
                      key={id}
                      className={cn(
                        'border-t border-border-custom table-row-hover-border',
                        onRowClick && 'cursor-pointer',
                        rowClassName?.(row)
                      )}
                      onClick={(e) => {
                        if ((e.target as HTMLElement).closest('input[type="checkbox"]')) return
                        onRowClick?.(row)
                      }}
                    >
                      {bulkActions && (
                        <td className="w-12 px-4">
                          <input
                            type="checkbox"
                            checked={isSelected(id)}
                            onChange={() => toggleSelection(id)}
                            className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                            aria-label={`Select row ${id}`}
                          />
                        </td>
                      )}
                      {columns.map((col) => (
                        <td
                          key={col.key}
                          className="px-4 py-4 text-sm"
                          style={{ width: col.width }}
                        >
                          {col.enumList && col.accessor ? (
                            <EnumBadge enumList={col.enumList} value={String(col.accessor(row) ?? '')} />
                          ) : (
                            col.cell(row)
                          )}
                        </td>
                      ))}
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <DataTablePagination
          page={page}
          perPage={perPage}
          total={total}
          startRow={startRow}
          endRow={endRow}
        />
      </div>

      {/* Bulk action bar */}
      {bulkActions && selection.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-surface-card border border-cyan-neon/30 shadow-glow-cyan rounded-xl px-4 py-3 flex items-center gap-3">
          <span className="text-sm text-text-secondary">
            {selection.size} selected
          </span>
          <div className="w-px h-4 bg-border-custom" />
          {bulkActions.map((action) => (
            <Button
              key={action.label}
              variant={action.variant ?? 'primary'}
              size="sm"
              onClick={() => action.onClick(Array.from(selection))}
            >
              {action.icon}
              {action.label}
            </Button>
          ))}
          <button
            onClick={clearSelection}
            className="text-xs text-text-tertiary hover:text-text-primary"
          >
            Clear
          </button>
        </div>
      )}
    </DataTableContext.Provider>
  )
}
