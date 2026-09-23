// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import '@testing-library/jest-dom'

// Radix UI primitives require ResizeObserver in jsdom.
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// @ts-ignore
window.ResizeObserver = window.ResizeObserver || ResizeObserverMock

// Import the configured API client so that generated-client singleton
// has baseUrl, auth, and interceptors set in every test.
import '../api/client'
