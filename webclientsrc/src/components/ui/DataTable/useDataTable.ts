// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useContext, useMemo, useCallback } from 'react'
import { DataTableContext } from './types'
import type { DataTableActions, DataTableState } from './types'

export function useDataTable<T = unknown>() {
  const ctx = useContext(DataTableContext)
  if (!ctx) {
    throw new Error('useDataTable must be used inside a DataTable provider')
  }

  const typedActions: DataTableActions<T> = {
    setSort: ctx.actions.setSort,
    toggleSort: ctx.actions.toggleSort,
    setFilter: ctx.actions.setFilter,
    clearFilters: ctx.actions.clearFilters,
    setPage: ctx.actions.setPage,
    setPerPage: ctx.actions.setPerPage,
    toggleSelection: ctx.actions.toggleSelection,
    toggleAllSelection: ctx.actions.toggleAllSelection,
    clearSelection: ctx.actions.clearSelection,
    isSelected: ctx.actions.isSelected,
    areAllSelected: ctx.actions.areAllSelected,
    someSelected: ctx.actions.someSelected,
    sortedData: ctx.actions.sortedData as T[],
  }

  return {
    state: ctx.state as DataTableState,
    actions: typedActions,
  }
}

export function useClientPagination<T>(data: T[], page: number, perPage: number) {
  return useMemo(() => {
    const start = (page - 1) * perPage
    return data.slice(start, start + perPage)
  }, [data, page, perPage])
}

export function useSelectionCount(selection: Set<string>) {
  return useMemo(() => selection.size, [selection])
}

export function useUrlTableState(paramPrefix = 't') {
  const read = useCallback((): { page: number; perPage: number; sort: string | null; search: string | null } => {
    if (typeof window === 'undefined') {
      return { page: 1, perPage: 25, sort: null, search: null }
    }
    const params = new URLSearchParams(window.location.search)
    const page = Math.max(1, parseInt(params.get(`${paramPrefix}_page`) ?? '1', 10) || 1)
    const parsedPerPage = parseInt(params.get(`${paramPrefix}_perPage`) ?? '25', 10)
    const perPage = [10, 25, 50, 100].includes(parsedPerPage) ? parsedPerPage : 25
    const sort = params.get(`${paramPrefix}_sort`)
    const search = params.get(`${paramPrefix}_search`)
    return { page, perPage, sort, search }
  }, [paramPrefix])

  const write = useCallback(
    (updates: Partial<{ page: number; perPage: number; sort: string | null; search: string | null }>) => {
      if (typeof window === 'undefined') return
      const params = new URLSearchParams(window.location.search)
      Object.entries(updates).forEach(([key, value]) => {
        const paramKey = `${paramPrefix}_${key}`
        if (value === null || value === undefined || value === '') {
          params.delete(paramKey)
        } else {
          params.set(paramKey, String(value))
        }
      })
      const newUrl = `${window.location.pathname}?${params.toString()}`
      window.history.replaceState({}, '', newUrl)
    },
    [paramPrefix]
  )

  return { read, write }
}
