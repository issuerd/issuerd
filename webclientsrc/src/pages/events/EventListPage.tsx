// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo, useState } from 'react'
import { format } from 'date-fns'
import { useQueryClient } from '@tanstack/react-query'
import { Activity, Filter, Copy, Check, RefreshCw } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useEvents,
  useEventCount,
  type EventFilters,
  useAdminEvents,
  useAdminEventCount,
  type AdminEventFilters,
} from '../../api/hooks/useEvents'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import type {
  EventType,
  EventRepresentation,
  AdminEventRepresentation,
  EnumValueRepresentation,
} from '@generated'
import EmptyState from '../../components/ui/EmptyState'
import ErrorMessage from '../../components/ui/ErrorMessage'
import EventFilterBar from '../../components/domain/EventFilterBar'
import AdminEventFilterBar from '../../components/domain/AdminEventFilterBar'
import PageHeader from '@/components/layout/PageHeader'
import EnumBadge from '../../components/ui/EnumBadge'
import Drawer from '../../components/ui/Drawer'
import { DataTable } from '../../components/ui/DataTable'
import type { ColumnDef } from '../../components/ui/DataTable'

type Tab = 'login' | 'admin'

const DEFAULT_PER_PAGE = 25

function eventTypeToString(et: EventType | null | undefined): string {
  if (!et) return ''
  if (typeof et === 'string') return et
  return et.custom
}

/** Display name for the user an event belongs to: resolved username, then the
 * recorded `username` detail, then the raw ID as a last resort. */
function displayUsername(e: EventRepresentation): string | null {
  return e.username ?? e.details?.username ?? e.user_id ?? null
}

function displayAdminUsername(e: AdminEventRepresentation): string | null {
  return e.auth_username ?? e.auth_user_id ?? null
}

function EventDetailPanel({
  event,
  allEvents,
  realmName,
  eventTypes,
}: {
  event: EventRepresentation
  allEvents?: EventRepresentation[]
  realmName: string
  eventTypes?: EnumValueRepresentation[]
}) {
  const [copied, setCopied] = useState(false)
  const json = JSON.stringify(event, null, 2)

  const relatedEvents = (allEvents ?? []).filter((e) => {
    if (e.id === event.id) return false
    const sameUser = e.user_id && e.user_id === event.user_id
    const sameIp = e.ip_address && e.ip_address === event.ip_address
    const timeDiff = Math.abs(e.time - event.time)
    const withinHour = timeDiff <= 3600
    return (sameUser || sameIp) && withinHour
  }).slice(0, 5)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <EnumBadge
          enumList={eventTypes}
          value={eventTypeToString(event.event_type)}
        />
        <span className="text-xs text-text-tertiary font-mono">
          {format(new Date(event.time * 1000), 'yyyy-MM-dd HH:mm:ss')}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <DetailField label="User" value={displayUsername(event)} />
        <DetailField label="Realm" value={realmName} />
        <DetailField label="Client ID" value={event.client_id} />
        <DetailField label="Session ID" value={event.session_id} />
        <DetailField label="IP Address" value={event.ip_address} />
        <DetailField label="Error" value={event.error} />
      </div>

      {/* Related Events */}
      {relatedEvents.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-2">
            Related Events (±1h)
          </h4>
          <div className="space-y-2">
            {relatedEvents.map((e, idx) => (
              <div key={idx} className="bg-surface-elevated border border-border-custom rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <EnumBadge enumList={eventTypes} value={eventTypeToString(e.event_type)} className="text-[10px]" />
                  <span className="text-[10px] text-text-tertiary">
                    {format(new Date(e.time * 1000), 'HH:mm:ss')}
                  </span>
                </div>
                <div className="text-xs text-text-secondary mt-1">
                  {displayUsername(e) ?? '—'} — {e.ip_address ?? '—'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {event.details && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-2">Details</h4>
          <div className="bg-surface-elevated border border-border-custom rounded-lg p-3">
            <pre className="text-xs text-text-secondary overflow-auto whitespace-pre-wrap">
              {JSON.stringify(event.details, null, 2)}
            </pre>
          </div>
        </div>
      )}

      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-2">Full JSON</h4>
        <div className="relative bg-surface-elevated border border-border-custom rounded-lg p-3">
          <button
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(json)
                setCopied(true)
                setTimeout(() => setCopied(false), 2000)
              } catch { /* ignore */ }
            }}
            className="absolute top-2 right-2 p-1.5 hover:bg-white/5 rounded transition-colors text-text-tertiary hover:text-cyan-neon"
            title="Copy JSON"
          >
            {copied ? <Check className="w-4 h-4 text-matrix-green" /> : <Copy className="w-4 h-4" />}
          </button>
          <pre className="text-xs text-text-secondary overflow-auto max-h-64 whitespace-pre-wrap pr-8">
            {json}
          </pre>
        </div>
      </div>
    </div>
  )
}

function AdminEventDetailPanel({
  event,
  realmName,
  operationTypes,
}: {
  event: AdminEventRepresentation
  realmName: string
  operationTypes?: EnumValueRepresentation[]
}) {
  const [copied, setCopied] = useState(false)
  const json = JSON.stringify(event, null, 2)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <EnumBadge enumList={operationTypes} value={event.operation_type} />
        <span className="text-xs text-text-tertiary font-mono">
          {format(new Date(event.time * 1000), 'yyyy-MM-dd HH:mm:ss')}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <DetailField label="Resource Type" value={event.resource_type} />
        <DetailField label="Resource Path" value={event.resource_path} />
        <DetailField label="Auth User" value={displayAdminUsername(event)} />
        <DetailField label="Realm" value={realmName} />
        <DetailField label="Error" value={event.error} />
      </div>

      {event.representation && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-2">Representation</h4>
          <div className="bg-surface-elevated border border-border-custom rounded-lg p-3">
            <pre className="text-xs text-text-secondary overflow-auto whitespace-pre-wrap">
              {JSON.stringify(event.representation, null, 2)}
            </pre>
          </div>
        </div>
      )}

      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-2">Full JSON</h4>
        <div className="relative bg-surface-elevated border border-border-custom rounded-lg p-3">
          <button
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(json)
                setCopied(true)
                setTimeout(() => setCopied(false), 2000)
              } catch { /* ignore */ }
            }}
            className="absolute top-2 right-2 p-1.5 hover:bg-white/5 rounded transition-colors text-text-tertiary hover:text-cyan-neon"
            title="Copy JSON"
          >
            {copied ? <Check className="w-4 h-4 text-matrix-green" /> : <Copy className="w-4 h-4" />}
          </button>
          <pre className="text-xs text-text-secondary overflow-auto max-h-64 whitespace-pre-wrap pr-8">
            {json}
          </pre>
        </div>
      </div>
    </div>
  )
}

function DetailField({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="bg-surface-elevated border border-border-custom rounded-lg p-3">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary mb-1">{label}</div>
      <div className="text-sm text-text-primary truncate">{value || '—'}</div>
    </div>
  )
}

const errorRowClass = (e: { error?: string | null }) =>
  e.error ? 'border-l-2 border-l-alert-red/30 bg-alert-red/[0.02]' : undefined

export default function EventListPage() {
  const realm = useAuthStore((s) => s.currentRealm)!
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<Tab>('login')

  // Login events tab state
  const [eventFilters, setEventFilters] = useState<EventFilters>({})
  const [appliedEventFilters, setAppliedEventFilters] = useState<EventFilters>({})
  const [showFilters, setShowFilters] = useState(false)
  const [eventPage, setEventPage] = useState(1)
  const [eventPerPage, setEventPerPage] = useState(DEFAULT_PER_PAGE)
  const [eventSearch, setEventSearch] = useState('')

  // Admin events tab state
  const [adminFilters, setAdminFilters] = useState<AdminEventFilters>({})
  const [appliedAdminFilters, setAppliedAdminFilters] = useState<AdminEventFilters>({})
  const [showAdminFilters, setShowAdminFilters] = useState(false)
  const [adminPage, setAdminPage] = useState(1)
  const [adminPerPage, setAdminPerPage] = useState(DEFAULT_PER_PAGE)
  const [adminSearch, setAdminSearch] = useState('')

  const [selectedEvent, setSelectedEvent] = useState<EventRepresentation | null>(null)
  const [selectedAdminEvent, setSelectedAdminEvent] = useState<AdminEventRepresentation | null>(null)

  const { data: serverInfo } = useServerInfo()

  const {
    data: events,
    isLoading: eventsLoading,
    isFetching: eventsFetching,
    error: eventsError,
  } = useEvents(realm, {
    ...appliedEventFilters,
    first: (eventPage - 1) * eventPerPage,
    max: eventPerPage,
  })
  const { data: eventsTotal } = useEventCount(realm, appliedEventFilters)

  const {
    data: adminEvents,
    isLoading: adminEventsLoading,
    isFetching: adminEventsFetching,
    error: adminEventsError,
  } = useAdminEvents(realm, {
    ...appliedAdminFilters,
    first: (adminPage - 1) * adminPerPage,
    max: adminPerPage,
  })
  const { data: adminEventsTotal } = useAdminEventCount(realm, appliedAdminFilters)

  const isRefreshing = eventsFetching || adminEventsFetching

  function handleRefresh() {
    qc.invalidateQueries({ queryKey: ['events', realm] })
    qc.invalidateQueries({ queryKey: ['admin-events', realm] })
  }

  const loginColumns = useMemo<ColumnDef<EventRepresentation>[]>(() => [
    {
      key: 'time',
      header: 'Time',
      accessor: (e) => e.time,
      cell: (e) => (
        <span className="text-text-secondary text-xs font-mono">
          {format(new Date(e.time * 1000), 'yyyy-MM-dd HH:mm:ss')}
        </span>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      accessor: (e) => eventTypeToString(e.event_type),
      enumList: serverInfo?.event_types,
      cell: (e) => (
        <EnumBadge enumList={serverInfo?.event_types} value={eventTypeToString(e.event_type)} />
      ),
    },
    {
      key: 'realm',
      header: 'Realm',
      accessor: () => realm,
      cell: () => <span className="text-text-secondary">{realm}</span>,
    },
    {
      key: 'user',
      header: 'User',
      accessor: (e) => displayUsername(e),
      cell: (e) => <span className="text-white">{displayUsername(e) ?? '—'}</span>,
    },
    {
      key: 'ip',
      header: 'IP',
      accessor: (e) => e.ip_address,
      cell: (e) => (
        <span className="text-text-secondary font-mono text-xs">{e.ip_address || '—'}</span>
      ),
    },
    {
      key: 'error',
      header: 'Error',
      accessor: (e) => e.error,
      cell: (e) => <span className="text-alert-red text-xs">{e.error || '—'}</span>,
    },
  ], [serverInfo?.event_types, realm])

  const adminColumns = useMemo<ColumnDef<AdminEventRepresentation>[]>(() => [
    {
      key: 'time',
      header: 'Time',
      accessor: (e) => e.time,
      cell: (e) => (
        <span className="text-text-secondary text-xs font-mono">
          {format(new Date(e.time * 1000), 'yyyy-MM-dd HH:mm:ss')}
        </span>
      ),
    },
    {
      key: 'operation',
      header: 'Operation',
      accessor: (e) => e.operation_type,
      enumList: serverInfo?.operation_types,
      cell: (e) => <EnumBadge enumList={serverInfo?.operation_types} value={e.operation_type} />,
    },
    {
      key: 'resource_type',
      header: 'Resource Type',
      accessor: (e) => e.resource_type,
      enumList: serverInfo?.resource_types,
      cell: (e) => <EnumBadge enumList={serverInfo?.resource_types} value={e.resource_type} />,
    },
    {
      key: 'resource_path',
      header: 'Resource Path',
      accessor: (e) => e.resource_path,
      cell: (e) => <span className="text-white text-xs">{e.resource_path}</span>,
    },
    {
      key: 'auth_user',
      header: 'Auth User',
      accessor: (e) => displayAdminUsername(e),
      cell: (e) => (
        <span className="text-text-secondary">{displayAdminUsername(e) ?? '—'}</span>
      ),
    },
    {
      key: 'error',
      header: 'Error',
      accessor: (e) => e.error,
      cell: (e) => <span className="text-alert-red text-xs">{e.error || '—'}</span>,
    },
  ], [serverInfo?.operation_types, serverInfo?.resource_types])

  const isLoading = activeTab === 'login' ? eventsLoading : adminEventsLoading
  const error = activeTab === 'login' ? eventsError : adminEventsError

  return (
    <div>
      <PageHeader
        title="Events & Logs"
        icon={Activity}
        actions={
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-2 px-4 py-2.5 bg-white/[0.03] border border-border-custom rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        }
      />

      <div className="flex items-center gap-4 mb-4 border-b border-border-custom">
        <button
          onClick={() => setActiveTab('login')}
          className={`px-4 py-2.5 text-sm font-medium transition-all border-b-2 ${
            activeTab === 'login'
              ? 'border-cyan-neon text-cyan-neon'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          Login Events
        </button>
        <button
          onClick={() => setActiveTab('admin')}
          className={`px-4 py-2.5 text-sm font-medium transition-all border-b-2 ${
            activeTab === 'admin'
              ? 'border-cyan-neon text-cyan-neon'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          Admin Events
        </button>

        <div className="flex-1" />

        <button
          onClick={() => {
            if (activeTab === 'login') {
              setShowFilters(!showFilters)
            } else {
              setShowAdminFilters(!showAdminFilters)
            }
          }}
          className="flex items-center gap-2 px-4 py-2.5 mb-1 bg-white/[0.03] border border-border-custom rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-all"
        >
          <Filter className="w-4 h-4" />
          Filters
        </button>
      </div>

      {activeTab === 'login' && showFilters && (
        <div className="mb-6">
          <EventFilterBar
            filters={eventFilters}
            onChange={setEventFilters}
            onApply={() => {
              setAppliedEventFilters(eventFilters)
              setEventPage(1)
            }}
          />
        </div>
      )}

      {activeTab === 'admin' && showAdminFilters && (
        <div className="mb-6">
          <AdminEventFilterBar
            filters={adminFilters}
            onChange={setAdminFilters}
            onApply={() => {
              setAppliedAdminFilters(adminFilters)
              setAdminPage(1)
            }}
          />
        </div>
      )}

      {error && <ErrorMessage message={error.message} />}

      {activeTab === 'login' ? (
        <DataTable
          data={events ?? []}
          columns={loginColumns}
          rowId={(e) => e.id ?? `${e.time}-${eventTypeToString(e.event_type)}-${e.user_id ?? ''}`}
          tableKey="login-events"
          backendPagination
          totalCount={eventsTotal}
          page={eventPage}
          perPage={eventPerPage}
          onPageChange={setEventPage}
          onPerPageChange={(pp) => {
            setEventPerPage(pp)
            setEventPage(1)
          }}
          search={eventSearch}
          onSearchChange={(v) => {
            setEventSearch(v)
            setEventPage(1)
          }}
          loading={isLoading}
          emptyState={
            <EmptyState
              illustration="events"
              title="No events"
              description="No events match the current filters."
            />
          }
          onRowClick={setSelectedEvent}
          rowClassName={errorRowClass}
        />
      ) : (
        <DataTable
          data={adminEvents ?? []}
          columns={adminColumns}
          rowId={(e) => e.id ?? `${e.time}-${e.operation_type}-${e.auth_user_id ?? ''}`}
          tableKey="admin-events"
          backendPagination
          totalCount={adminEventsTotal}
          page={adminPage}
          perPage={adminPerPage}
          onPageChange={setAdminPage}
          onPerPageChange={(pp) => {
            setAdminPerPage(pp)
            setAdminPage(1)
          }}
          search={adminSearch}
          onSearchChange={(v) => {
            setAdminSearch(v)
            setAdminPage(1)
          }}
          loading={isLoading}
          emptyState={
            <EmptyState
              illustration="events"
              title="No admin events"
              description="No admin events match the current filters."
            />
          }
          onRowClick={setSelectedAdminEvent}
          rowClassName={errorRowClass}
        />
      )}

      {/* Event Detail Drawer */}
      <Drawer
        open={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        title="Event Detail"
      >
        {selectedEvent && (
          <EventDetailPanel
            event={selectedEvent}
            allEvents={events ?? []}
            realmName={realm}
            eventTypes={serverInfo?.event_types}
          />
        )}
      </Drawer>

      <Drawer
        open={!!selectedAdminEvent}
        onClose={() => setSelectedAdminEvent(null)}
        title="Admin Event Detail"
      >
        {selectedAdminEvent && (
          <AdminEventDetailPanel
            event={selectedAdminEvent}
            realmName={realm}
            operationTypes={serverInfo?.operation_types}
          />
        )}
      </Drawer>
    </div>
  )
}
