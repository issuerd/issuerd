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
- **Suite tag:** `release-v5.3.2` checked out at
  `tests/conformance/conformance-suite/` (moved up from `release-v5.2.4`;
  all references — `tests/conformance/README.md`, `run.sh`, `COVERAGE.md`,
  `.github/workflows/heavy.yml`, `AGENTS.md` — updated in the same pass).
- **Conformance run vs v5.3.2: ALL GREEN** (2026-10-11, `run.sh`, exit 0) —
  Config OP 39 conditions; Basic OP 36 modules / 1858 conditions; Form Post
  OP 36 modules / 2010 conditions; **0 failures, 0 warnings**. Identical
  numbers to the v5.2.4 baseline. Evidence: `tests/conformance/results/`
  (html-reports-20261011-075455, export-json zips).
- **Module-count re-verification at v5.3.2: unchanged** — all 13 plan classes
  byte-identical to v5.2.4 except a semantics-preserving discovery-check
  refactor; counts in `execution-matrix.md` stand. One OP-facing behavioral
  change to remember: an id_token carrying a nonce when none was requested is
  now a FAILURE (`ValidateIdTokenNonce`, issue-2027 fix) — issuerd only
  echoes requested nonces, confirmed by the green v5.3.2 run.
- **Code changes:** none yet — repository code is untouched; only
  `certification/` docs + suite-tag reference bumps exist so far.
- **Next action:** start Milestone M1 (`certification/README.md` §5) —
  client metadata & registration foundation, task C1 (RFC 7591 metadata
  acceptance in `crates/issuerd-server/src/routes/client_registration.rs`).

## Status by milestone

Milestones are defined in `certification/README.md` §5 (implementation order).
Legend: ⬜ not started · 🔶 in progress · ✅ done.

| Milestone | Scope | Status | Evidence |
|---|---|---|---|
| M1 | Client metadata & registration foundation (DCR RFC 7591/7592 plumbing, logout URIs, `initiate_login_uri`) | ⬜ | |
| M2 | Authorization response types + nonce rules (`id_token token`, `code token`, `code id_token token`) | ⬜ | |
| M3 | Session management (`session_state`, `check_session_iframe`) | ⬜ | |
| M4 | Registration-backed deep features (sector fetch, signed userinfo, `jwks_uri` verification) | ⬜ | |
| M5 | Harness & rotation automation (configs, bootstrap, runner matrix, focus generalization, rotate-keys sidecar) | ⬜ | |
| M6 | Full-matrix gate + submission prep | ⬜ | |

## Status by profile (634 module executions total)

| Profile | Tests | Suite green? | Notes |
|---|---|---|---|
| Config OP | 1 | ✅ (since 2026-09-13, v5.2.4) | re-validating vs v5.3.2 |
| Basic OP | 36 | ✅ (since 2026-09-13, v5.2.4) | re-validating vs v5.3.2 |
| Form Post OP (basic leg) | 36 | ✅ (since 2026-09-13, v5.2.4) | re-validating vs v5.3.2 |
| Implicit OP | 58 | ⬜ | needs M2 |
| Hybrid OP | 102 | ⬜ | needs M2 |
| Form Post OP (implicit+hybrid legs) | 160 | ⬜ | needs M2 |
| Dynamic OP | 127 | ⬜ | needs M1+M4+M5 |
| 3rd Party-Init OP | 12 | ⬜ | needs M1 |
| RP-Initiated OP | 66 | ⬜ | needs M2 (+M1) |
| Session OP | 12 | ⬜ | needs M3 (+M2) |
| Front-Channel OP | 12 | ⬜ | needs M2 (+M1) |
| Back-Channel OP | 12 | ⬜ | needs M2 (+M1) |

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
