// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import tseslint from 'typescript-eslint'

// Focused lint gate: ban explicit `any` in production TypeScript so API
// payloads keep their generated types end-to-end. Test files are exempt —
// mock-heavy fixtures legitimately loosen types (same precedent as the
// CodeQL paths-ignore for test trees).
export default tseslint.config(
  {
    ignores: ['dist', 'coverage', 'generated', 'node_modules'],
  },
  {
    files: ['**/*.{ts,tsx,mts}'],
    languageOptions: {
      parser: tseslint.parser,
    },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
  {
    files: ['**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
)
