// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import type { EnumValueRepresentation } from '@generated'

export type SortDirection = 'asc' | 'desc' | null

export interface SortState {
  key: string
  direction: SortDirection
}

export interface FilterState {
  search?: string
  [columnKey: string]: string | string[] | undefined
}

export interface PaginationState {
  page: number
  perPage: number
}

export interface ColumnDef<T> {
  key: string
  header: React.ReactNode
  accessor?: (row: T) => string | number | null | undefined
  cell: (row: T) => React.ReactNode
  sortable?: boolean
  width?: number | string
  enumList?: EnumValueRepresentation[]
}

export interface DataTableState {
  sort: SortState | null
  filters: FilterState
  pagination: PaginationState
  selection: Set<string>
}

export interface DataTableActions<T> {
  setSort: (key: string, direction: SortDirection) => void
  toggleSort: (key: string) => void
  setFilter: (key: string, value: string | string[] | undefined) => void
  clearFilters: () => void
  setPage: (page: number) => void
  setPerPage: (perPage: number) => void
  toggleSelection: (id: string) => void
  toggleAllSelection: (ids: string[]) => void
  clearSelection: () => void
  isSelected: (id: string) => boolean
  areAllSelected: (ids: string[]) => boolean
  someSelected: (ids: string[]) => boolean
  sortedData: T[]
}

export const DataTableContext = React.createContext<{
  state: DataTableState
  actions: DataTableActions<unknown>
} | null>(null)
