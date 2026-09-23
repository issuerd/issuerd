# Issuerd Web Client

React-based admin console and end-user account console for the Issuerd IAM server.

## Quick Start

```bash
npm install
npm run dev          # Vite dev server, port 5173 (proxies API calls to the daemon on localhost:8080)
npm run build        # Type-check + production build → dist/
npm run test         # Vitest unit tests
npm run generate-api # Regenerate SDK from openapi.json
```

## Architecture

This is a **Vite + React 19 + TypeScript** SPA with two entry points. Both are served by the Rust backend as embedded static files (`dist/` compiled into the binary via `include_dir!`):

- **Admin console** — `index.html` + `src/`, mounted under `/admin/console`
- **Account console** — `account.html` + `src/account/`, mounted at `/realms/{realm}/account` (profile, credentials/TOTP/passkeys, consents, linked accounts, sessions)

### Login Page (Critical)

The login page is **`public/login.html`** — a static HTML file, **not** a React component.

- The Issuerd OIDC auth endpoint redirects to `/login.html?execution_id=...&realm=...`
- When visited without `execution_id`, it generates PKCE params and redirects to the auth endpoint
- When visited with `execution_id`, it shows a username/password form and POSTs to `/api/v1/auth/login`
- The server returns `302 Found` on success; the browser follows to `/admin/console/callback` in the SPA

**Rule:** Never use React Router `<Navigate to="/login.html">`. Because `login.html` is outside the SPA route table, this produces a blank screen. Always use `window.location.href = '/login.html'`.

### Key Files

| File | Purpose |
|------|---------|
| `src/App.tsx` | Admin console route table (React Router `basename="/admin/console"`). Unauthenticated users are sent to `/login.html` via `window.location.href`. |
| `src/components/layout/RealmContextGuard.tsx` | Guards console routes: unauthenticated → `window.location.href = '/login.html'`; no realm selected → `/realm-picker`. |
| `src/pages/Callback.tsx` | Exchanges OAuth authorization code for tokens after login (`/admin/console/callback`). |
| `src/account/App.tsx` | Account console route table (profile, password/credentials, consents, linked accounts, sessions). |
| `src/state/authStore.ts` | Zustand store: token, realm, logout. |
| `src/api/client.ts` | Generated API client base URL + auth interceptors. |
| `generated/*` | **Auto-generated** from OpenAPI. Do not edit by hand. |
| `public/login.html` | Universal login page (SPA + external OIDC clients + conformance suite). |

## State Management

- **Server state:** TanStack Query v5 (`src/api/hooks/*.ts`)
- **Client state:** Zustand v5 (`src/state/authStore.ts`)
- **Forms:** react-hook-form v7

## Styling

- Tailwind CSS v4 utility classes + shadcn/ui black-and-white design system (`src/components/ui/`)
- Theme tokens are OKLCH CSS variables defined in `src/styles/global.css` (`@theme`): the shadcn palette plus Issuerd-specific tokens (`cyan-neon`, `obsidian`, `surface-*`, `shadow-glow-*`, …); use `cn()` from `src/lib/utils.ts` for conditional class merging
- Admin console defaults to dark mode via `next-themes`; press `d` to toggle light/dark
- Dropdowns are fully dynamic: options come from `useServerInfo()` (`GET /admin/serverinfo`), never hardcoded enum arrays

## API Generation

```bash
# From repo root — export backend OpenAPI spec
cargo run --bin issuerd -- openapi -o webclientsrc/openapi.json

# From webclientsrc — regenerate TypeScript SDK
cd webclientsrc && npm run generate-api
```

## Testing

Vitest + jsdom + `@testing-library/react` + MSW.

```bash
npm run test
npx vitest --watch
```

Use `renderWithProviders` from `src/test/utils.tsx` to wrap components in `QueryClientProvider + BrowserRouter`.
