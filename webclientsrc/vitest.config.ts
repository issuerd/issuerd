// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': '/src',
      '@generated': resolve(__dirname, 'generated'),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      thresholds: { lines: 92 },
      // json-summary feeds scripts/coverage_badges.py (CI coverage job);
      // lcov.info + lcov-report/ (HTML) go into the CI artifacts; cobertura
      // feeds GitHub Code Quality's native pull-request coverage check.
      reporter: ['text', 'lcov', 'json-summary', 'cobertura'],
      exclude: [
        'generated/**',
        'src/**/*.module.css',
        'src/test/**',
        'src/main.tsx',
        'src/account.tsx',
        'src/account/App.tsx',
        'src/App.tsx',
        'src/pages/Callback.tsx',
        // Vendored shadcn layout primitives; Issuerd application wrappers stay measured.
        'src/components/ui/avatar.tsx',
        'src/components/ui/breadcrumb.tsx',
        'src/components/ui/dropdown-menu.tsx',
        'src/components/ui/input-field.tsx',
        'src/components/ui/separator.tsx',
        'src/components/ui/sheet.tsx',
        'src/components/ui/sidebar.tsx',
        'src/components/ui/tabs.tsx',
        'src/vite-env.d.ts',
        'src/**/index.ts',
      ],
    },
  },
})
