// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo } from 'react'
import { useAuthStore } from '../../state/authStore'
import { useSessions, useSessionCount, useDeleteSession } from '../../api/hooks/useSessions'
import DataTable from '../../components/ui/DataTable/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable/types'
import PageLoader from '../../components/ui/PageLoader'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Badge from '../../components/ui/Badge'
import PageHeader from '@/components/layout/PageHeader'
import Drawer from '../../components/ui/Drawer'
import { Timer, LogOut, Monitor, Clock, MapPin, User } from 'lucide-react'
import type { UserSessionRepresentation } from '@generated'

const DEFAULT_PER_PAGE = 25

export default function SessionListPage() {
  const realm = useAuthStore((s) => s.currentRealm)!
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE)
  const [selectedSession, setSelectedSession] = useState<UserSessionRepresentation | null>(null)

  const first = (page - 1) * perPage
  const { data: sessions, isLoading, error } = useSessions(realm, { first, max: perPage })
  const { data: totalCount } = useSessionCount(realm)
  const del = useDeleteSession()

  const columns = useMemo<ColumnDef<UserSessionRepresentation>[]>(() => [
    {
      key: 'username',
      header: 'Username',
      accessor: (s) => s.username ?? '',
      cell: (s) => <span className="text-sm font-medium text-white">{s.username}</span>,
      sortable: true,
    },
    {
      key: 'ip_address',
      header: 'IP Address',
      accessor: (s) => s.ip_address ?? '',
      cell: (s) => <span className="text-text-secondary font-mono text-xs">{s.ip_address || '—'}</span>,
      sortable: true,
    },
    {
      key: 'offline',
      header: 'Type',
      accessor: (s) => (s.offline ? 1 : 0),
      cell: (s) =>
        s.offline ? (
          <Badge variant="warning">Offline</Badge>
        ) : (
          <span className="text-text-tertiary text-xs">Online</span>
        ),
      sortable: true,
    },
    {
      key: 'started',
      header: 'Started',
      accessor: (s) => s.started ?? 0,
      cell: (s) => (
        <span className="text-text-secondary text-xs">
          {s.started ? new Date(s.started * 1000).toLocaleString() : '—'}
        </span>
      ),
      sortable: true,
    },
    {
      key: 'last_access',
      header: 'Last Access',
      accessor: (s) => s.last_access ?? 0,
      cell: (s) => (
        <span className="text-text-secondary text-xs">
          {s.last_access ? new Date(s.last_access * 1000).toLocaleString() : '—'}
        </span>
      ),
      sortable: true,
    },
  ], [])

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <div>
      <PageHeader title="Sessions" icon={Timer} />

      <DataTable
        data={sessions ?? []}
        columns={columns}
        rowId={(s) => s.id}
        tableKey="sessions"
        backendPagination
        totalCount={totalCount}
        page={page}
        perPage={perPage}
        onPageChange={setPage}
        onPerPageChange={(pp) => {
          setPerPage(pp)
          setPage(1)
        }}
        emptyState={
          <EmptyState
            illustration="sessions"
            title="No sessions"
            description="There are no active sessions."
          />
        }
        bulkActions={[
          {
            label: 'Revoke Selected',
            variant: 'danger',
            icon: <LogOut className="w-4 h-4" />,
            onClick: (ids) => {
              if (confirm(`Revoke ${ids.length} session(s)?`)) {
                ids.forEach((id) => del.mutate({ realm, session: id }))
              }
            },
          },
        ]}
        onRowClick={(s) => setSelectedSession(s)}
      />

      <Drawer
        open={!!selectedSession}
        onClose={() => setSelectedSession(null)}
        title="Session Detail"
      >
        {selectedSession && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <DetailCard icon={User} label="Username" value={selectedSession.username} />
              <DetailCard icon={MapPin} label="IP Address" value={selectedSession.ip_address} />
              <DetailCard
                icon={Clock}
                label="Started"
                value={selectedSession.started ? new Date(selectedSession.started * 1000).toLocaleString() : '—'}
              />
              <DetailCard
                icon={Monitor}
                label="Last Access"
                value={selectedSession.last_access ? new Date(selectedSession.last_access * 1000).toLocaleString() : '—'}
              />
            </div>

            {selectedSession.offline && (
              <div className="flex items-center gap-2">
                <Badge variant="warning">Offline</Badge>
                <span className="text-xs text-text-tertiary">
                  Backs an offline_access refresh token; survives SSO session expiry and logout.
                </span>
              </div>
            )}

            {selectedSession.user_id && (
              <div className="bg-surface-elevated border border-border-custom rounded-lg p-3">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary mb-1">User ID</div>
                <div className="text-sm text-text-primary font-mono">{selectedSession.user_id}</div>
              </div>
            )}

            <button
              onClick={() => {
                if (confirm('Revoke this session?')) {
                  del.mutate({ realm, session: selectedSession.id })
                  setSelectedSession(null)
                }
              }}
              className="w-full px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center justify-center gap-2"
            >
              <LogOut className="w-4 h-4" />
              Revoke Session
            </button>
          </div>
        )}
      </Drawer>
    </div>
  )
}

function DetailCard({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value?: string | null }) {
  return (
    <div className="bg-surface-elevated border border-border-custom rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-3.5 h-3.5 text-text-tertiary" />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">{label}</span>
      </div>
      <div className="text-sm text-text-primary truncate">{value || '—'}</div>
    </div>
  )
}
