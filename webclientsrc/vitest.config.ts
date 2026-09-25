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
      // json-summary feeds scripts/coverage_badges.py (CI coverage job);
      // lcov.info + lcov-report/ (HTML) go into the CI artifacts.
      reporter: ['text', 'lcov', 'json-summary'],
      exclude: [
        'generated/**',
        'src/**/*.module.css',
        'src/test/**',
        'src/main.tsx',
        'src/account.tsx',
        'src/account/App.tsx',
        'src/App.tsx',
        'src/pages/Callback.tsx',
        'src/vite-env.d.ts',
        'src/**/index.ts',
      ],
    },
  },
})
