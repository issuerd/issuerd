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
