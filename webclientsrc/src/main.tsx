// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import App from './App'
import { queryClient } from './api/queryClient'
import { useAuthStore } from './state/authStore'
import { ThemeProvider } from './components/theme-provider'
import { CONSOLE_BASENAME } from './config'
import { startSessionRefresh } from './api/tokenRefresh'
import './api/client'
import './styles/global.css'

useAuthStore.getState().hydrate()
// Resume the proactive token-refresh schedule for a restored session.
startSessionRefresh()

// axe-core accessibility auditing in development
if (import.meta.env.DEV) {
  import('@axe-core/react').then((axe) => {
    axe.default(React, ReactDOM, 1000)
  })
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename={CONSOLE_BASENAME}>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <App />
          <ReactQueryDevtools initialIsOpen={false} />
        </QueryClientProvider>
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
