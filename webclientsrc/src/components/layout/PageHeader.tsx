// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Link } from 'react-router-dom'
import { Fragment } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'

interface BreadcrumbItemType {
  label: string
  to?: string
}

interface PageHeaderProps {
  title: string
  icon?: LucideIcon
  breadcrumbs?: BreadcrumbItemType[]
  actions?: ReactNode
}

export default function PageHeader({ title, icon: Icon, breadcrumbs, actions }: PageHeaderProps) {
  return (
    <div className="pb-6">
      {breadcrumbs && breadcrumbs.length > 0 && (
        <Breadcrumb className="mb-4">
          <BreadcrumbList>
            {breadcrumbs.map((crumb, i) => (
              // The separator is its own <li> — it must be a sibling between
              // BreadcrumbItems, not nested inside one (invalid <li> in <li>).
              <Fragment key={i}>
                {i > 0 && <BreadcrumbSeparator />}
                <BreadcrumbItem>
                  {crumb.to ? (
                    <BreadcrumbLink asChild>
                      <Link to={crumb.to}>{crumb.label}</Link>
                    </BreadcrumbLink>
                  ) : (
                    <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
                  )}
                </BreadcrumbItem>
              </Fragment>
            ))}
          </BreadcrumbList>
        </Breadcrumb>
      )}
      <div className="flex items-center justify-between gap-4">
        <h1 className="font-heading text-2xl text-foreground flex items-center gap-3">
          {Icon && <Icon className="w-6 h-6 text-primary" />}
          {title}
        </h1>
        {actions && <div className="flex items-center gap-3">{actions}</div>}
      </div>
      <div className="mt-6 h-px bg-border" />
    </div>
  )
}
