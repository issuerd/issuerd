// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  server: {
    // Same-origin in dev: API calls are proxied to a locally running daemon.
    // Start it with `cargo run --bin issuerd -- daemon -c issuerd.toml`.
    proxy: {
      '/admin': 'http://localhost:8080',
      '/realms': 'http://localhost:8080',
      '/api': 'http://localhost:8080',
      '/login.html': 'http://localhost:8080',
    },
  },
  resolve: {
    alias: {
      '@': '/src',
      '@generated': resolve(__dirname, 'generated'),
    },
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        account: resolve(__dirname, 'account.html'),
      },
    },
  },
})
