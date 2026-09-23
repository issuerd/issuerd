// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import EmptyState from '../components/ui/EmptyState'

export default function NotFoundPage() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <EmptyState
        icon={Compass}
        title="404 — Page not found"
        description="The page you are looking for does not exist or was moved."
        action={
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity"
          >
            Back to Dashboard
          </Link>
        }
      />
    </div>
  )
}
