// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import AccountApp from './account/App'
import { queryClient } from './api/queryClient'
import { useAuthStore } from './state/authStore'
import { ThemeProvider } from './components/theme-provider'
import './styles/global.css'

useAuthStore.getState().hydrate()

const pathname = window.location.pathname
const match = pathname.match(/^\/realms\/([^/]+)\/account/)
const basename = match ? match[0] : '/account'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename={basename}>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <AccountApp />
        </QueryClientProvider>
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
