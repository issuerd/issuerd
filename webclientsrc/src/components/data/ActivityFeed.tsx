// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { formatDistanceToNow } from 'date-fns'
import { cn } from '@/lib/utils'
import EnumBadge from '../ui/EnumBadge'
import type { EnumValueRepresentation, EventRepresentation } from '@generated'
import type { EventType } from '@generated'

interface ActivityFeedProps {
  events: EventRepresentation[]
  maxItems?: number
  eventTypes?: EnumValueRepresentation[]
}

function eventTypeToString(et: EventType | null | undefined): string {
  if (!et) return ''
  if (typeof et === 'string') return et
  return et.custom
}

function eventVariant(eventType: string): 'success' | 'warning' | 'danger' | 'info' {
  const t = eventType.toLowerCase()
  if (t.includes('error') || t.includes('login_error')) return 'danger'
  if (t.includes('register') || t.includes('create')) return 'success'
  if (t.includes('token') || t.includes('code')) return 'warning'
  return 'info'
}

export default function ActivityFeed({ events, maxItems = 10, eventTypes }: ActivityFeedProps) {
  const visible = events.slice(0, maxItems)

  return (
    <div className="flex flex-col gap-0">
      {visible.map((e, idx) => {
        const et = eventTypeToString(e.event_type)
        return (
          <div
            key={e.id ?? `${e.time}-${et}-${idx}`}
            className={cn(
              'flex items-start gap-3 py-3',
              idx !== visible.length - 1 && 'border-b border-border-custom'
            )}
          >
            <span
              className={cn(
                'mt-1.5 w-2 h-2 rounded-full shrink-0',
                eventVariant(et) === 'success' && 'bg-matrix-green',
                eventVariant(et) === 'warning' && 'bg-amber',
                eventVariant(et) === 'danger' && 'bg-alert-red',
                eventVariant(et) === 'info' && 'bg-cyan-neon'
              )}
            />
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <EnumBadge enumList={eventTypes} value={et} />
                {e.user_id && (
                  <span className="text-xs text-text-secondary truncate">{e.user_id}</span>
                )}
              </div>
              {e.ip_address && (
                <p className="text-xs text-text-tertiary mt-0.5 font-mono">{e.ip_address}</p>
              )}
              {e.error && <p className="text-xs text-alert-red mt-0.5">{e.error}</p>}
            </div>
            <time
              className="text-xs text-text-tertiary shrink-0"
              title={new Date(e.time * 1000).toISOString()}
            >
              {formatDistanceToNow(new Date(e.time * 1000), { addSuffix: true })}
            </time>
          </div>
        )
      })}
      {visible.length === 0 && (
        <div className="text-sm text-text-tertiary py-4 text-center">No recent activity</div>
      )}
    </div>
  )
}
