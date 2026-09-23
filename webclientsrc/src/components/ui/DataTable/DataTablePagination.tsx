// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useDataTable } from './useDataTable'

interface DataTablePaginationProps {
  page: number
  perPage: number
  total: number
  startRow: number
  endRow: number
}

export default function DataTablePagination({
  page,
  perPage,
  total,
  startRow,
  endRow,
}: DataTablePaginationProps) {
  const { actions } = useDataTable()
  const pageCount = Math.max(1, Math.ceil(total / perPage))

  const pageButtons: (number | '...')[] = []
  const maxVisible = 7
  if (pageCount <= maxVisible) {
    for (let i = 1; i <= pageCount; i++) pageButtons.push(i)
  } else {
    pageButtons.push(1)
    let start = Math.max(2, page - 2)
    let end = Math.min(pageCount - 1, page + 2)
    if (page <= 4) {
      end = Math.min(pageCount - 1, 5)
    } else if (page >= pageCount - 3) {
      start = Math.max(2, pageCount - 4)
    }
    if (start > 2) pageButtons.push('...')
    for (let i = start; i <= end; i++) pageButtons.push(i)
    if (end < pageCount - 1) pageButtons.push('...')
    pageButtons.push(pageCount)
  }

  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-sm text-text-secondary">
      <div>
        Showing <span className="text-text-primary font-medium">{total === 0 ? 0 : startRow}</span>
        –<span className="text-text-primary font-medium">{endRow}</span> of{' '}
        <span className="text-text-primary font-medium">{total}</span>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <label htmlFor="per-page" className="text-xs text-text-tertiary uppercase tracking-wider">
            Rows
          </label>
          <select
            id="per-page"
            value={perPage}
            onChange={(e) => actions.setPerPage(Number(e.target.value))}
            className="h-8 px-2 bg-surface-card border border-border-custom rounded-md text-sm text-text-primary focus:border-cyan-neon outline-none"
          >
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => actions.setPage(page - 1)}
            disabled={page <= 1}
            className="p-1.5 rounded-md border border-border-custom text-text-secondary hover:border-border-hover hover:text-text-primary disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            aria-label="Previous page"
          >
            <ChevronLeft className="w-4 h-4" aria-hidden="true" />
          </button>

          {pageButtons.map((p, idx) =>
            p === '...' ? (
              <span key={`ellipsis-${idx}`} className="px-2 text-text-tertiary">
                …
              </span>
            ) : (
              <button
                key={p}
                onClick={() => actions.setPage(p)}
                aria-current={p === page ? 'page' : undefined}
                className={`min-w-[2rem] h-8 px-2 rounded-md text-sm font-medium transition-all ${
                  p === page
                    ? 'bg-cyan-neon text-obsidian'
                    : 'border border-border-custom text-text-secondary hover:border-border-hover hover:text-text-primary'
                }`}
              >
                {p}
              </button>
            )
          )}

          <button
            onClick={() => actions.setPage(page + 1)}
            disabled={page >= pageCount}
            className="p-1.5 rounded-md border border-border-custom text-text-secondary hover:border-border-hover hover:text-text-primary disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            aria-label="Next page"
          >
            <ChevronRight className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  )
}
