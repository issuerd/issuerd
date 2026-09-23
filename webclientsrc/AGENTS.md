# Issuerd Web Client — Agent Guide

> This file contains project-specific context for AI coding agents working on the Issuerd React admin SPA.
> All documentation, comments, and design artifacts are written in **English**.

---

## Project Overview

The **Issuerd Web Client** is a React-based Single Page Application (SPA) that provides the administrative console and the end-user account console for the Issuerd IAM server. It is a Vite-built TypeScript project that communicates with the Issuerd REST Admin API.

- **Framework**: React 19 + TypeScript 6
- **Build Tool**: Vite 8
- **Router**: `react-router-dom` v7
- **State Management**:
  - Server state: **TanStack Query (React Query)** v5
  - Client state: **Zustand** v5 (auth + realm context)
  - Forms: **react-hook-form** v7
- **API Client**: Auto-generated from OpenAPI via `@hey-api/openapi-ts`
- **Styling**: Tailwind CSS v4 + shadcn/ui black-and-white design system
- **Testing**: Vitest 4 + `@testing-library/react` + jsdom + MSW

---

## Directory Structure

```
webclientsrc/
├── index.html                 # Admin console entry (served under /admin/console)
├── account.html               # Account console entry (served at /realms/{realm}/account)
├── public/
│   ├── login.html             # Static login page (OIDC entry point)
│   ├── brand/                 # Issuerd logo SVGs (wordmark + square mark, black/white)
│   └── fonts/                 # Vendored Google Fonts (woff2 + fonts.css, scripts/fetch-fonts.mjs)
├── src/
│   ├── api/
│   │   ├── client.ts          # Generated API client config (base URL, auth interceptors)
│   │   ├── tokenRefresh.ts    # Activity-gated proactive token refresh + 401 refresh-retry
│   │   ├── queryClient.ts     # TanStack QueryClient defaults
│   │   └── hooks/             # One hook file per domain (useRealms, useUsers, etc.)
│   ├── account/               # End-user account console (separate entry via account.html)
│   │   ├── App.tsx            # Account console route table
│   │   ├── api/               # Account-scoped error mapping (requests use the shared generated SDK)
│   │   ├── components/        # AccountLayout + account widgets
│   │   ├── pages/             # Profile, Password (credentials/TOTP/passkeys), Consents, LinkedAccounts, Sessions
│   │   └── webauthn.ts        # Passkey ceremony helpers
│   ├── components/
│   │   ├── ui/                # Generic reusable components (Button, Input, Modal, Table, Spinner, shadcn primitives, etc.)
│   │   ├── domain/            # Business-specific form components (RealmForm, ClientForm, UserForm, etc.)
│   │   ├── layout/            # AppLayout, AppSidebar/Sidebar, SiteHeader/TopNav, PageHeader, Footer, SkipLinks, mobile nav, RealmContextGuard
│   │   └── theme-provider.tsx # next-themes dark/light provider
│   ├── hooks/
│   │   ├── use-mobile.ts      # shadcn sidebar mobile breakpoint hook
│   │   ├── useEnumDescription.ts # serverinfo-driven enum descriptions (backs EnumTooltip/EnumBadge)
│   │   ├── useFormDraft.ts    # Unsaved-form draft persistence
│   │   └── useKeyboardShortcuts.ts # Global shortcut bindings (e.g. `d` theme toggle)
│   ├── lib/
│   │   ├── utils.ts           # cn() class merging + shared helpers
│   │   ├── pkce.ts            # PKCE verifier/challenge generation
│   │   └── keyboardShortcuts.ts
│   ├── generated/             # AUTO-GENERATED — do not edit manually
│   │   ├── client.gen.ts
│   │   ├── sdk.gen.ts         # All API functions (listRealms, createUser, etc.)
│   │   ├── types.gen.ts       # All TypeScript types from OpenAPI
│   │   └── index.ts           # Re-exports
│   ├── pages/                 # Route-level page components (admin console)
│   │   ├── dashboard/
│   │   ├── realms/
│   │   ├── users/
│   │   ├── clients/
│   │   ├── client-scopes/
│   │   ├── roles/
│   │   ├── groups/
│   │   ├── sessions/
│   │   ├── events/
│   │   ├── identity-providers/
│   │   ├── keys/
│   │   ├── auth-flows/
│   │   ├── security/
│   │   ├── server-info/
│   │   ├── Callback.tsx          # OAuth callback handler (code exchange)
│   │   ├── NotFoundPage.tsx      # Unknown console routes
│   │   └── RealmPicker.tsx
│   ├── state/
│   │   └── authStore.ts       # Zustand store: token, currentRealm, logout, hydrate
│   ├── styles/
│   │   └── global.css         # @theme tokens, CSS variables, reset, keyframes
│   ├── test/
│   │   ├── utils.tsx          # renderWithProviders (QueryClient + Router wrapper)
│   │   ├── setup.ts           # Vitest setup (jest-dom matchers, etc.)
│   │   └── mocks/             # Shared fixtures (MSW-style)
│   ├── config.ts              # Same-origin constants + one-time SDK client base URL
│   ├── main.tsx               # Entry point: React root, QueryClientProvider, Router
│   └── App.tsx                # Route definitions
├── generated/                 # Auto-generated TypeScript SDK from OpenAPI
├── openapi.json               # OpenAPI spec — auto-generated from backend
├── openapi-ts.config.ts       # @hey-api/openapi-ts config
├── package.json
├── tsconfig.json
├── vite.config.ts
└── vitest.config.ts
```

---

## Build & Development Commands

```bash
# Install dependencies
npm install

# Dev server (Vite, port 5173 by default; proxies /admin, /realms, /api and
# /login.html to a locally running daemon on http://localhost:8080).
# Open http://localhost:5173/admin/console — the bare dev root renders nothing
# because the router basename is /admin/console.
npm run dev

# Type-check + production build
npm run build

# Run tests (Vitest)
npm run test

# Run tests in watch mode
npx vitest

# Regenerate API client from OpenAPI spec
npm run generate-api

# Re-vendor the self-hosted fonts into public/fonts/ (requires internet;
# the woff2 files and fonts.css are committed — never fetch fonts at runtime)
node scripts/fetch-fonts.mjs
```

---

## API Client Generation

The TypeScript SDK is **auto-generated** from `openapi.json` (produced by the Rust backend). The spec covers the Admin API **and** the account-console, public protocol, and internal SPA endpoints (merged via `issuerd_server::openapi::full_openapi()`).

**Generated-SDK rule:** every API request the UI makes must go through a generated SDK function. Hand-written endpoint layers (custom clients with URL strings, raw `fetch` against backend routes) are not allowed — `public/login.html` is the only exception. If an endpoint is missing from the spec, add it to the backend first (admin endpoints: utoipa-annotated `issuerd-admin-api` handlers; account/protocol endpoints: utoipa-annotated `issuerd-server` route handlers), then export the spec and regenerate.

**Workflow when backend APIs change:**
1. Backend team exports new OpenAPI spec:
   ```bash
   cargo run --bin issuerd -- openapi -o webclientsrc/openapi.json
   ```
2. Regenerate SDK:
   ```bash
   cd webclientsrc && npm run generate-api
   ```
3. Commit `openapi.json` (tracked). `generated/` is gitignored — every clone/dev
   machine regenerates it with `npm run generate-api` after pulling API changes.

**Agent rule:** Never hand-edit files inside `generated/`. If a generated type is wrong, fix the Rust backend's `utoipa` annotations and re-generate.

---

## State Management Patterns

### Server State — TanStack Query

Every domain has a hook file in `src/api/hooks/`. Pattern:

```typescript
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listRealms, createRealm } from '@generated'

const key = 'realms'

export function useRealms() {
  return useQuery({
    queryKey: [key],
    queryFn: async () => {
      const res = await listRealms()
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
  })
}

export function useCreateRealm() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: RealmRepresentation) => {
      const res = await createRealm({ body })
      if (res.error) throw new Error(res.error.errorMessage)
      return res.data!
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: [key] }),
  })
}
```

**Error handling convention:** Always check `res.error`. If present, throw `new Error(res.error.errorMessage)` so React Query surfaces it as `error` on the hook result.

### Client State — Zustand

`src/state/authStore.ts` holds:
- `token` — JWT bearer token (persisted to `sessionStorage`)
- `currentRealm` — Active realm for the admin console (persisted to `localStorage`)
- `logout()` — Clears both stores and redirects

Access in components:
```typescript
const token = useAuthStore((s) => s.token)
const setRealm = useAuthStore((s) => s.setRealm)
```

---

## Component Conventions

### Generic UI Components (`src/components/ui/`)

Components live in `src/components/ui/`. The design system is based on shadcn/ui v4 (copied from `ui/apps/v4/registry/new-york-v4/ui/`) with Issuerd-specific legacy wrappers (`Button`, `Input`, `Badge`, `Table`, `Skeleton`, `Tooltip`).

| Component | Props of note |
|-----------|---------------|
| `Button` | `variant?: 'primary' \| 'danger' \| 'ghost' \| 'outline' \| 'secondary' \| 'link'`, `size?: 'sm' \| 'md' \| 'icon'`, `loading?: boolean` |
| `Input` | `label?: string`, `error?: string`, `helperText?: string`, `success?: boolean`, `copyable?: boolean`, `iconLeft?: LucideIcon`, `iconRight?: LucideIcon` |
| `Modal` | `open: boolean`, `onClose: () => void`, `title?: string` |
| `Table` | `Table`, `Thead`, `Tbody`, `Tr`, `Th`, `Td` — composable |
| `Spinner` | `size?: number` (px) |
| `Logo` / `LogoMark` | Brand logos (`Logo.tsx`): `Logo` = wordmark, `LogoMark` = square one-letter mark; inline SVG with `fill="currentColor"` so they follow the theme. The four static SVGs live in `public/brand/` (favicons reference `logo-small*.svg` with `prefers-color-scheme` media queries) |
| `PageLoader` | `inline?: boolean` — centered loading state; fills the content area (matches the route Suspense fallback) by default, `inline` centers with padding for tabs/sections |
| `EmptyState` | `title`, `description` |
| `ErrorMessage` | `message` |
| shadcn primitives | `button.tsx`/`Button.tsx`, `card.tsx`, `input.tsx`/`Input.tsx`, `badge.tsx`/`Badge.tsx`, `table.tsx`/`Table.tsx`, `select.tsx`, `switch.tsx`, `checkbox.tsx`, `dialog.tsx`, `dropdown-menu.tsx`, `avatar.tsx`, `tooltip.tsx`/`Tooltip.tsx`, `tabs.tsx`, `breadcrumb.tsx`, `sidebar.tsx`, `sheet.tsx`, `separator.tsx`, `skeleton.tsx`/`Skeleton.tsx`, `collapsible.tsx`, `label.tsx`, `textarea.tsx` |

**Styling:** Tailwind CSS v4 utility classes in `src/styles/global.css`. Use `cn()` from `src/lib/utils.ts` for conditional class merging.

**Theme tokens:** All theme tokens are defined in `global.css` `@theme`: the shadcn CSS
variables (`bg-card`, `bg-popover`, `text-foreground`, `text-muted-foreground`,
`border-border`, `bg-primary`, …) plus Issuerd-specific tokens (`bg-surface-dark`,
`bg-surface-card`, `bg-surface-elevated`, `bg-obsidian`, `border-border-custom`,
`text-text-primary|secondary|tertiary`, `cyan-neon`, `alert-red`, `matrix-green`,
`font-display`, `shadow-modal`, `shadow-glow-*`) mapped onto the same variables. Never use
a token that is not defined in `@theme`; undefined utilities are silently dropped by
Tailwind v4 and produce transparent/unstyled surfaces.
**Overlay z-index:** Use the named scale from `global.css` (`z-fab` 80, `z-sidebar` 90,
`z-top-nav` 100, `z-modal-overlay` 200, `z-modal-content` 210, `z-toast` 300, `z-dropdown` 400)
— not raw `z-50`. Dropdowns/listboxes must portal to `document.body` at `z-dropdown` so they
escape clipping by modal bodies (`overflow-y-auto`) — see `FormSelect`.

### Domain Form Components (`src/components/domain/`)

Each major entity has a dedicated form component:
- `RealmForm`
- `ClientForm`
- `ClientScopeForm`
- `UserForm`
- `IdPForm`
- `RoleForm`
- `GroupForm`
- `EventFilterBar`

Shared building blocks: `ProtocolMapperEditor` (client/client-scope mapper CRUD, mapper-type dropdown from `serverinfo.mapper_types`), `RoleMappingsSection` (realm + client role available↔assigned pickers; pages inject their domain hooks via the `RoleMappingsHooks` adapter), `TwoColumnPicker`.

**Form conventions:**
- Use `react-hook-form`'s `useForm<T>()` where `T` is the generated representation type.
- For array fields stored as newline-separated text in the UI (e.g. `redirect_uris`), use helper functions `arrayFromLines` / `linesFromArray` inside the component file.
- Forms receive `defaultValues`, `onSubmit`, `onCancel`, and optional `loading` props.
- **Dropdowns must be fully dynamic.** All `<select>` options must come from `useServerInfo()` — never hardcode enum arrays in components. Default values (e.g., `protocol: 'openid-connect'`) are OK as string literals, but the option list itself must be dynamic.
- **Descriptions must be visible.** Every `EnumValueRepresentation` from the backend carries a `description`. Pass it through to the UI:
  - `FormSelect` options: include `description` in the `SelectOption` object; the component renders it as a subtitle.
  - Native `<select>` `<option>` elements: add `title={opt.description ?? undefined}` for hover tooltips.
  - Badges / labels: use `title` attributes or info icons to expose the description text.

### Adding a New Page

1. Create page component in `src/pages/<domain>/`.
2. Add route in `src/App.tsx` inside the console catch-all route (console URLs live under the `/admin/console` basename; in-router paths are basename-relative, e.g. `path="users"`).
3. If it needs sidebar navigation, add the item to `src/components/layout/Sidebar.tsx`.
4. Add API hooks in `src/api/hooks/use<Domain>.ts` if they don't exist.
5. Add tests in `src/pages/<domain>/<Page>.test.tsx` or `src/api/hooks/use<Domain>.test.tsx`.

---

## Server Info / Enum Dropdowns

The backend exposes `GET /admin/serverinfo` which returns all constant lists needed for dropdowns (protocols, SSL modes, event types, algorithms, grant types, etc.).

**Critical rule:** The UI is **fully dynamic**. Every dropdown bootstraps its values from the backend at runtime. If an enum value is missing from `serverInfo`, it is not exposed by the API yet — do not add a local fallback array.

**Hook:** `src/api/hooks/useServerInfo.ts`

Usage in forms:
```typescript
import { useServerInfo } from '../../api/hooks/useServerInfo'

const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

// In JSX:
<select {...register('protocol')} disabled={infoLoading}>
  {serverInfo?.protocols.map((p) => (
    <option key={p.id} value={p.id}>{p.name}</option>
  ))}
</select>
```

The source of truth for available enums is the backend: `issuerd-admin-api/src/enums.rs` defines the lists exposed via `GET /admin/enums/*` and `GET /admin/serverinfo`. If a value is missing from `ServerInfoRepresentation`, add it to the backend first (enums.rs → DTO → routes → regenerate `openapi.json` → regenerate SDK), then wire it into the UI — never hardcode a local fallback array.

---

## Testing

### Unit / Component Tests

- Framework: **Vitest** with `globals: true`
- DOM: **jsdom**
- Helpers: `@testing-library/react`, `@testing-library/jest-dom`
- Mock server: **MSW** (Mock Service Worker)

**Wrapper for tests:**
```typescript
import { renderWithProviders } from '../test/utils'
```
This wraps components in `QueryClientProvider` + `BrowserRouter`.

### Mocking API Hooks

Preferred pattern: `vi.mock('../../api/hooks/use<Domain>')` at the top of the test file:

```typescript
vi.mock('../../api/hooks/useRealms', () => ({
  useRealms: () => ({ data: [...], isLoading: false, error: null }),
  useCreateRealm: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
```

If a form uses `useServerInfo`, you **must also mock** `../../api/hooks/useServerInfo` or the component will crash with "No QueryClient set".

---

## Authentication & Authorization

- ### Login Architecture

There is **one unified login page**: `public/login.html` (static HTML, not a React component).

**Why static HTML?** The Issuerd OIDC auth endpoint (`/realms/{realm}/protocol/openid-connect/auth`) redirects unauthenticated users to `/login.html?execution_id=...&realm=...`. This page must work for:
- The React admin SPA
- External OIDC clients
- The OIDC conformance suite browser automation

Because the page is served as a static file, it is deterministic and loads instantly — no React bundle hydration required.

**Console mount:** the SPA is served by the daemon only below `/admin/console` (`web_ui::admin_console_handler`, mounted as the fallback of the nested `/admin` router). `/` and bare `/admin` redirect there. The REST admin API owns the remaining `/admin/*` paths directly — an unmatched API path answers JSON 404, never the SPA shell. Unknown client-side routes under `/admin/console` render the SPA's own `NotFoundPage`. React Router runs with `basename="/admin/console"` (`CONSOLE_BASENAME` in `src/config.ts`), so `useLocation().pathname` is basename-stripped and every `navigate()`/`Link` target must be basename-relative (`/users`, not `/admin/console/users`); raw anchors/`window.location` need the full path (`consoleHref()`).

**Flow:**
1. User visits `/admin/console` (SPA) while unauthenticated → `App.tsx` does `window.location.href = '/login.html'` (full page nav)
2. `login.html` with **no** `execution_id` → generates PKCE params (`code_verifier`, `code_challenge`, `state`), stores them in `sessionStorage`, and redirects to the OIDC auth endpoint
3. Auth endpoint validates the request and redirects back to `/login.html?execution_id=...&realm=...`
4. `login.html` with `execution_id` → shows the username/password form
5. Form submits to `/api/v1/auth/login` as `application/x-www-form-urlencoded`
6. Server returns `302 Found` + `Set-Cookie` + `Location: redirect_uri` on success
7. Browser follows redirect to `/admin/console/callback` (SPA route) which exchanges the code for tokens

**Passwordless email-code mode:** when the realm sets the `email_code_login` attribute, `GET /realms/{realm}/login/context` returns `email_code_login: true` and `login.html` switches to an email-only form (password field, remember-me and forgot-password link are hidden; the submit button becomes "Send code"). The code-entry and resend pages are server-rendered by the daemon (like the TOTP challenge page), so `login.html` itself only handles the email step.

**Never use React Router `<Navigate>` to go to `/login.html`.** Because `login.html` is a static file outside the SPA's route table, `<Navigate>` performs a client-side history push that React Router cannot match, resulting in a blank screen. Always use `window.location.href = '/login.html'` for unauthenticated redirects.

**Token storage:**
- On success, the JWT is stored in `sessionStorage` and the Zustand store.
- The generated API client (`src/api/client.ts`) attaches the token to every request automatically.
- Token refresh is proactive and activity-gated (`src/api/tokenRefresh.ts`): while the user interacts with the console, the access token is refreshed ~30 s before expiry (each refresh slides the server-side SSO idle window). With no user interaction the refresh stops, the access token lapses, and once the realm's SSO idle timeout passes the server answers the next refresh with `invalid_grant` → the session ends.
- On 401, the client interceptor (`src/api/client.ts`) attempts one token refresh and retries the original request; only if the refresh fails with `invalid_grant` (or the retry still 401s) does it call `logout()` and redirect to `/login.html?logged_out=1`.
- Admin API endpoints require realm-management roles (`view-realm`, `manage-realm`, `view-users`, `manage-users`, etc.). The backend returns 403 if roles are missing.

---

## Styling Guidelines

### CSS Variables (defined in `src/styles/global.css`)

The theme is a shadcn/ui v4 black-and-white palette using OKLCH color variables:

```css
:root {
  --background: oklch(1 0 0);
  --foreground: oklch(0% 0 0);
  --card: oklch(1 0 0);
  --card-foreground: oklch(0% 0 0);
  --primary: oklch(0% 0 0);
  --primary-foreground: oklch(0.985 0 0);
  --secondary: oklch(0.97 0 0);
  --muted: oklch(0.97 0 0);
  --border: oklch(0.922 0 0);
  --input: oklch(0.922 0 0);
  --ring: oklch(0.708 0 0);
  --radius: 0.625rem;
}

.dark {
  --background: oklch(0.145 0 0);
  --foreground: oklch(0.985 0 0);
  --card: oklch(0.205 0 0);
  --primary: oklch(0.922 0 0);
  --primary-foreground: oklch(0.205 0 0);
  --border: oklch(1 0 0 / 10%);
  --input: oklch(1 0 0 / 15%);
  --ring: oklch(0.556 0 0);
}
```

The admin console defaults to dark mode via `next-themes` (`src/components/theme-provider.tsx`). Press `d` to toggle light/dark (skipped when focus is in an input).

### Rules

- Use Tailwind v4 utility classes and shadcn primitives for all new UI.
- Use `cn()` from `src/lib/utils.ts` for conditional class merging.
- Keep forms at `max-width: 560px` for readability.

---

## Environment & Runtime Config

There is no runtime config file. The SPA is served **same-origin** by the Issuerd daemon (embedded `dist/`), so the API base URL is always `window.location.origin` (`src/config.ts`).

In development, `npm run dev` proxies `/admin`, `/realms`, `/api`, and `/login.html` to a locally running daemon on `http://localhost:8080` (see `server.proxy` in `vite.config.ts`). Start the daemon first (`cargo run --bin issuerd -- daemon -c issuerd.toml`) — no `config.js` editing is needed.

---

## Key Files for Agents

| File | Purpose |
|------|---------|
| `package.json` | Dependencies, scripts |
| `src/App.tsx` | Route table |
| `src/api/client.ts` | API client base URL + auth interceptors |
| `src/api/hooks/*.ts` | Domain data hooks pattern |
| `generated/index.ts` | All API functions and types |
| `src/components/ui/*.tsx` | Reusable UI primitives |
| `src/components/domain/*.tsx` | Business form components |
| `src/state/authStore.ts` | Auth state |
| `src/test/utils.tsx` | Test wrapper |
| `openapi.json` | OpenAPI spec (source of truth for API) |

---

## Common Pitfalls

1. **Using `<Navigate to="/login.html">` for unauthenticated redirects** — This causes a blank screen because React Router cannot match the static file route. Always use `window.location.href = '/login.html'`.
2. **Forgetting to mock `useServerInfo` in tests** — Any form with a dropdown calls this hook. Mock it or wrap in `QueryClientProvider`.
3. **Editing `generated/` manually** — Changes will be lost on the next `npm run generate-api`.
4. **Not checking `res.error`** — The generated client returns `{ data, error, response }`. Always guard against `error`.
5. **Importing generated code with relative paths** — Import from `@generated` everywhere instead of deep relative paths like `../../../generated`.
6. **Hardcoding enum arrays in components** — This violates the fully-dynamic rule. Always source dropdown options from `useServerInfo()`. If the enum is missing from `ServerInfoRepresentation`, add it to the backend first (`issuerd-admin-api/src/enums.rs` → regenerate `openapi.json` → regenerate SDK → wire in UI).
7. **Dropping `description` from enum values** — `EnumValueRepresentation` includes `description` for a reason. It explains the value to the admin user. Never map only `id` + `name`; always thread `description` into the UI via tooltips, subtitles, or `title` attributes.
8. **Calling an endpoint that is not in `openapi.json`, or bypassing the generated SDK** — every request must use a generated SDK function (see the Generated-SDK rule above). The account console and admin SPA share the same SDK singleton, configured once in `src/config.ts` (auth resolver covers both token stores).
9. **Linking the Google Fonts CDN** — all HTML entry points (`index.html`, `account.html`, `public/login.html`) must load fonts only from the same-origin vendored `/fonts/fonts.css` (populated by `node scripts/fetch-fonts.mjs`). Runtime requests to `fonts.googleapis.com`/`fonts.gstatic.com` fail in hermetic networks (the OIDC conformance stack is `internal: true`) and flood the suite's browser logs with exceptions.
