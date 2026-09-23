// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import type { LucideIcon } from 'lucide-react'
import {
  UsersIllustration,
  ClientsIllustration,
  EventsIllustration,
  SessionsIllustration,
  GenericIllustration,
} from '../data/illustrations'

export type EmptyStateIllustration = 'users' | 'clients' | 'events' | 'sessions' | 'generic'

interface EmptyStateProps {
  title: string
  description?: string
  action?: React.ReactNode
  icon?: LucideIcon
  illustration?: EmptyStateIllustration
}

const illustrations: Record<EmptyStateIllustration, React.FC<{ className?: string }>> = {
  users: UsersIllustration,
  clients: ClientsIllustration,
  events: EventsIllustration,
  sessions: SessionsIllustration,
  generic: GenericIllustration,
}

export default function EmptyState({
  title,
  description,
  action,
  icon: Icon,
  illustration = 'generic',
}: EmptyStateProps) {
  const Illustration = illustrations[illustration]

  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {Icon ? (
        <Icon className="w-16 h-16 text-text-tertiary mb-4" />
      ) : (
        <div className="text-cyan-neon/80 mb-4">
          <Illustration />
        </div>
      )}
      <h3 className="font-display text-xl text-text-secondary mb-2">{title}</h3>
      {description && <p className="text-sm text-text-tertiary max-w-md mb-6">{description}</p>}
      {action}
    </div>
  )
}
