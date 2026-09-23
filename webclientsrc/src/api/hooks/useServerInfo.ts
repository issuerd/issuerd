// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useQuery } from '@tanstack/react-query'
import { getServerinfo } from '@generated'

const key = 'serverinfo'

export function useServerInfo() {
  return useQuery({
    queryKey: [key],
    queryFn: async () => {
      const res = await getServerinfo()
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    staleTime: Infinity,
  })
}
