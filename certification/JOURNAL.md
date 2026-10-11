# Certification Expansion — Handoff Journal

> **Purpose:** this journal is the single source of truth for work-in-progress
> on the certification expansion. It exists so that **any agent or human can
> pick the work up cold** after a break, context loss, or handoff — without
> re-reading chat history or re-deriving state.
>
> **Rules (binding, see `README.md` §6 "Working rules"):**
> 1. **Commit often.** Every completed task (or coherent half-task) is its own
>    commit on `feat/oidc-certification-expansion`. Never end a working session
>    with uncommitted changes.
> 2. **Journal before you stop.** Before ending any working session — and after
>    every commit that changes state — update this file: the status tables, the
>    "Next action" line, and a dated log entry with the commit hash.
> 3. **Everything lives in `./certification/`.** Plans, matrices, this journal,
>    scratch analyses that are still decision-relevant. If it's not here, it
>    doesn't survive handoff. (Test evidence still lands in
>    `tests/conformance/results/` as before — reference it, don't copy it.)
> 4. **Write for a reader with zero context.** State commands verbatim, name
>    files with full repo-relative paths, record *why* decisions were made.

---

## Where we are (read this first)

- **Branch:** `feat/oidc-certification-expansion` (from `main` @ plan baseline).
- **Suite tag:** `release-v5.3.2` (all references updated; re-run green).
- **M1 — DONE (exit gate green 2026-10-11):** RFC 7591/7592 DCR + logout
  client fields landed (commit `4410659`); harness + 3rd-party ×6 runner loop
  landed (`593379a`, `281f93b`). Full `run.sh` green: Config/Basic/FormPost
  unchanged (0 failures/0 warnings) + **3rd-Party-Init OP 6/6 runs PASSED
  (12/12 module executions)** — evidence
  `tests/conformance/results/html-reports-20261011-092241`.
- **Cumulative: 85/634 green** (Config 1 + Basic 36 + FormPost-basic 36 +
  3rd-Party-Init 12).
- **Next action:** Milestone M2 — authorization response types & nonce
  (README §4 WS-A, §5 M2): accept `id_token token` / `code token` /
  `code id_token token` at the authorization endpoint
  (`crates/issuerd-server/src/routes/oidc.rs:889-921`), mint access tokens in
  `finish_sso_login`, enforce nonce for id_token-bearing response types
  (realm-attribute escape hatch per README §8), discovery update.

## Status by milestone

Milestones are defined in `certification/README.md` §5 (implementation order).
Legend: ⬜ not started · 🔶 in progress · ✅ done.

| Milestone | Scope | Status | Evidence |
|---|---|---|---|
| M1 | Client metadata & registration foundation (DCR RFC 7591/7592 plumbing, logout URIs, `initiate_login_uri`) | ✅ | `4410659` + gate 2026-10-11 (3rd-party 12/12) |
| M2 | Authorization response types + nonce rules (`id_token token`, `code token`, `code id_token token`) | ⬜ | |
| M3 | Session management (`session_state`, `check_session_iframe`) | ⬜ | |
| M4 | Registration-backed deep features (sector fetch, signed userinfo, `jwks_uri` verification) | ⬜ | sector fetch/validate already existed (`issuerd_core::pairwise`) — M4 shrinks accordingly |
| M5 | Harness & rotation automation (configs, bootstrap, runner matrix, focus generalization, rotate-keys sidecar) | 🔶 | 3rd-party config + bootstrap + runner loop landed in M1; rest pending |
| M6 | Full-matrix gate + submission prep | ⬜ | |

## Status by profile (634 module executions total)

| Profile | Tests | Suite green? | Notes |
|---|---|---|---|
| Config OP | 1 | ✅ (v5.3.2, 2026-10-11) | |
| Basic OP | 36 | ✅ (v5.3.2, 2026-10-11) | |
| Form Post OP (basic leg) | 36 | ✅ (v5.3.2, 2026-10-11) | |
| Implicit OP | 58 | ⬜ | needs M2 |
| Hybrid OP | 102 | ⬜ | needs M2 |
| Form Post OP (implicit+hybrid legs) | 160 | ⬜ | needs M2 |
| Dynamic OP | 127 | ⬜ | needs M4+M5.1 (DCR plumbing landed in M1) |
| 3rd Party-Init OP | 12 | ✅ (v5.3.2, 2026-10-11) | M1 exit gate |
| RP-Initiated OP | 66 | ⬜ | needs M2 (logout client fields landed in M1) |
| Session OP | 12 | ⬜ | needs M3 (+M2) |
| Front-Channel OP | 12 | ⬜ | needs M2 (+M1 done) |
| Back-Channel OP | 12 | ⬜ | needs M2 (+M1 done) |

## How to resume (verbatim commands)

```bash
git checkout feat/oidc-certification-expansion
git log --oneline main..HEAD          # what has landed on this branch
cat certification/JOURNAL.md          # this file — status + next action

# Run the current conformance gate (3 passing plans):
cd tests/conformance && ./run.sh

# Focused single-module debugging:
cd tests/conformance && ./run-focus.sh <module-name>

# Repo gates that must stay green at every commit:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --lib
```

## Log

### 2026-10-11 — plan baseline + suite bump to v5.3.2

- Commit `1ec2070` — plan documents created: `certification/README.md`
  (master plan), `certification/execution-matrix.md` (run matrix), verified
  against suite `release-v5.2.4`.
- Suite clone moved `release-v5.2.4` → `release-v5.3.2` (latest tag; fetched
  from gitlab.com/openid/conformance-suite). **Full `run.sh` against v5.3.2:
  ALL GREEN** (Config 39 conditions; Basic 36/1858; FormPost 36/2010; 0
  failures, 0 warnings — identical to the v5.2.4 baseline; evidence in
  `tests/conformance/results/html-reports-20261011-075455`). Suite-tag
  references updated everywhere: `tests/conformance/README.md`, `run.sh`,
  `COVERAGE.md`, `.github/workflows/heavy.yml`, `AGENTS.md`.
- **Module-count re-verification at v5.3.2: unchanged.** All 13 OIDCC OP plan
  classes byte-identical between the tags; `execution-matrix.md` counts stand
  as written. Noted behavioral deltas (no count impact): unsolicited-nonce
  id_tokens are now a FAILURE (`ValidateIdTokenNonce` fix — issuerd only
  echoes requested nonces; covered by the green run); lenient JWKS parsing;
  REVIEW now outranks WARNING in module status.
- Plan restructured into **convergence-ordered milestones M1–M6**
  (`certification/README.md` §5): M1 client-metadata/DCR foundation → M2
  response types & nonce → M3 session management → M4 deep registration
  features → M5 harness/rotation automation → M6 full-matrix gate. Each
  milestone turns profiles green immediately (see the convergence table).
- Working rules adopted (commit often, journal before stopping, everything in
  `./certification/`) — `certification/README.md` §6; journal file created.
- Decisions recorded so far (details in README §8): nonce-tightening gets a
  realm-attribute escape hatch; open registration stays opt-in per realm;
  `session_state` mirrors Keycloak's session-id approach; iframe JS is
  ES5-grade string comparison only (HtmlUnit); `oidcc-server-rotate-keys`
  evidence comes from a standalone suite-API-driven run.
- **Next:** begin M1 — C1 (RFC 7591 metadata acceptance in
  `crates/issuerd-server/src/routes/client_registration.rs`).

### 2026-10-11 — M1 complete: 3rd-Party-Init OP green (85/634)

- Commit `4410659` — M1 server-side (delegated to a coder subagent, all repo
  gates green): new `crates/issuerd-server/src/client_metadata.rs`
  (constants + typed accessors); RFC 7591 request translation in
  `client_registration.rs` (client_name/grant_types/response_types/
  token_endpoint_auth_method/scope/jwks/jwks_uri/subject_type/
  sector_identifier_uri/initiate_login_uri/post_logout_redirect_uris/
  front+backchannel fields/logo/policy/tos/signed-alg fields; https and
  allowlist validation with 400 `invalid_client_metadata`); additive RFC
  response fields (`registration_access_token`, `registration_client_uri`,
  `client_id_issued_at`, `client_secret_expires_at`, `client_secret`) + full
  metadata echo on create/read/update; `post_logout_redirect_uris` allowlist
  preferred over `redirect_uris` in logout validation; `sid` omitted from
  logout tokens / `iss`+`sid` from front-channel URLs when the per-client
  `*_session_required` attribute is `false`. 23 new unit tests; integration:
  `dynamic_client_registration.rs` +3, `logout_channels.rs` +3; full
  integration suite 375/375.
  Notable sub-decisions by the implementer (recorded in the commit report):
  `response_types` attribute stores a JSON array (space-joining is lossy for
  multi-token types); `client_id_issued_at` stamped on every DCR create;
  Keycloak spelling wins when both spellings of a field arrive.
- Commit `593379a` — harness: bootstrap enables
  `dynamic_client_registration_enabled` on the conformance realm, pre-
  registers logout URIs on both static clients, mints an unlimited
  initial-access token into `/results/initial-access-token.txt`; config
  template `configs/issuerd-3rdparty-init-op.json`; run-conformance runs the
  3rd-party plan once per response type.
- Commit `281f93b` — fix: the 3rd-party/dynamic/logout plans PIN
  server_metadata/client_auth/response_mode; only `response_type` (and
  `client_registration` on logout plans) may be passed. First gate attempt
  failed plan creation on exactly this; matrix + runner corrected.
- **Gate result:** `run.sh` exit 0 — existing 3 plans unchanged-green, plus
  6/6 3rd-party runs PASSED (2 modules each; evidence
  `tests/conformance/results/html-reports-20261011-092241`).
- **Decision (supersedes README WS-C C4):** no open-registration changes —
  the suite's `client.initial_access_token` + issuerd's unlimited initial
  access tokens cover dynamic registration; the open endpoint and its rate
  limit are untouched. README updated.
- Sector `sector_identifier_uri` fetch+validation turned out to already exist
  (`issuerd_core::pairwise::validate_pairwise_subject_config`, wired into
  registration) — M4 scope shrinks to sector *confirmation tests* + signed
  userinfo + `jwks_uri` verification.
- **Next:** M2 — response types & nonce (see "Where we are").
