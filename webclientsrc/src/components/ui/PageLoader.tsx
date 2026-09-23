// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import Spinner from './Spinner'

interface PageLoaderProps {
  /** Section/tab-level loader: centered with vertical padding instead of filling the content area. */
  inline?: boolean
}

export default function PageLoader({ inline = false }: PageLoaderProps) {
  return (
    <div className={`flex items-center justify-center ${inline ? 'py-12' : 'h-full'}`}>
      <Spinner size={inline ? 24 : 40} />
    </div>
  )
}
