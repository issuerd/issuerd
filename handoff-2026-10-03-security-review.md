# Handoff — Security review findings & planned fixes

**Written:** 2026-10-02 · **For:** implementation session 2026-10-03
**Origin:** external AI security review (source/docs-only) + full verification against this
repo at commit-time HEAD by six parallel code investigations. Every finding below is
**confirmed against local source** with file:line anchors (function names included — line
numbers drift once edits start).

This is an uncommitted working artifact. Delete or fold into docs once all batches land.

---

## Status at a glance

| Item | Status |
|---|---|
| RUSTSEC-2023-0071 justification corrections | **DONE** (committed: `4b6f7fd`) |
| **EXTRA — both advisory exceptions eliminated** (rsa → aws_lc_rs backend + OpenSSL keygen; rustls-pemfile → redis 0.29; deny zero ignores, audit one scoped tooling-gap entry for the sqlx weak-dep lockfile quirk cargo#10801) | **DONE** (`830bba8`) |
| **EXTRA — release.yml: Docker Hub publish is the final gated stage** (after heavy suites + platform builds + GitHub Release + crates.io) | **DONE** (`a40fd7f`) |
| Batch 1a — jwks.url fetch routed through SSRF-guarded path (https-only, IP checks, no redirects, 64 KiB cap) | **DONE** |
| Batch 1b — DCR open-endpoint payload policy (strip JWKS/logout attrs, force no service account, redirect-scheme allowlist, reject `*` origin) | **DONE** |
| Batch 1c — master-only keys rotate/disable + audit events always on master realm | **DONE** |
| Batch 1d — JAR unknown-kid refetch shares the 60 s cooldown | **DONE** |
| Batch 2 — explicit CIDR blocklist + guarded fetch is a required trait method | **DONE** |
| Batch 3 — PKCE S256-only at authorize AND token (plain + missing method rejected; breaking-hardening, CHANGELOG migration note) | **DONE** (recommended variant implemented) |
| Batch 4 — first-broker-login audit | **DONE** — verdict: 2 High + 1 Low findings (see §3 Batch 4 notes below) |
| Batch 4b — fixes: callback browser-correlation cookie (SameSite=None;Secure on TLS), link-page brute-force wiring + per-entry attempt cap + LOGIN_ERROR events, link-token alias binding (fail-closed for pre-change tokens) | **DONE** |
| Deferred hardening (dpop_jkt, DNS pinning, boot warnings, rotate-loop cap, IdP test-connection, backchannel-logout client) | PENDING / optional (unchanged) |

Batch 4 audit verdict (summary): the broker callback consumed the single-use state without checking the browser-correlation cookie (login CSRF → session injection; phishing-assisted account linking) — High, fixed in 4b; the link-via-password page verified the existing account's password with no lockout/events/attempt cap (unthrottled guessing oracle bypassing `brute_force_protected`) — High, fixed in 4b; link action tokens were not IdP-alias-bound — Low, fixed in 4b. Everything else (re-auth-by-default linking, trust-email gate, action-token signature/expiry/single-use-via-BrokerState, mapper confinement, kc_idp_hint order, external id_token validation) verified SAFE with code anchors; full report in the session history.

Known residuals recorded for follow-up:
- RFC 7592 self-management PUT (`clients-registrations/openid-connect/{id}`) can re-add attributes the open-endpoint policy strips (needs registration-provenance tracking to gate cleanly); mitigated in the interim by the SSRF-guarded fetch path (Batch 1a) which is the real boundary for `jwks.url`.
- 2FA on the link-confirmation page (Keycloak runs the full browser flow) — larger redesign, not started.
- `__Host-` cookie-prefix rename for flow cookies — noted in `flow_cookie_header`'s doc comment.
- `PkceCodeChallengeMethod::Plain` core variant retained for parsing stored values; no longer advertised via the admin enum endpoint nor accepted anywhere.

Process rules that apply to every batch (from AGENTS.md):
- CHANGELOG.md entry per PR under `## [Unreleased]` — **state the class of fix, not an
  exploit recipe** (public repo; fixes self-disclose).
- Backward compatibility is a hard requirement: DCR filtering is write-path only (existing
  registered clients unaffected); authorization tightening and PKCE-plain rejection are
  breaking-hardening and need explicit CHANGELOG migration notes.
- Gates before merge: `cargo test --workspace`, `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`, `cargo fmt -- --check`.

---

## §1 DONE — RUSTSEC-2023-0071 (rsa / Marvin) justification corrections

The advisory ignore previously claimed the `rsa` crate was "only used for key generation"
with signing/verification via `ring`, and that Marvin is a decryption-only oracle. All
wrong: RS256/384/512 JWT signing runs through `rsa` via jsonwebtoken's `rust_crypto`
backend (`EncodingKey::from_rsa_der` → `jsonwebtoken::encode`,
`crates/issuerd-token/src/crypto_provider.rs:512-513,621`); `ring` is used only for
Ed25519 key generation (`crypto_provider.rs:383-388`); Marvin covers RSA **private-key
operations** (decryption AND PKCS#1 v1.5 signing); no patched `rsa` release exists.

Corrected text (accepted-residual-risk framing + residual plan) now lives in:
`deny.toml`, `.cargo/audit.toml` (kept in sync — separate tool configs), `Cargo.toml`
(two comment blocks), `crates/issuerd-token/src/crypto_provider.rs:438` (doc comment),
`docs/administration.md`, `docs/configuration.md`, `CHANGELOG.md` (Unreleased → Security).
Verified green: `cargo deny check advisories` → ok; `cargo audit` → clean (596 crates).

Longer-term residual plan recorded in `deny.toml`: migrate RSA key generation off `rsa`
(openssl is already in-tree via webauthn) + evaluate jsonwebtoken's `aws_lc_rs` backend —
the only architecture that removes `rsa` entirely; costs cmake/C toolchain on every build
target and a full heavy-suite re-run. Not scheduled.

---

## §2 Confirmed findings (the fix backlog)

Severity framing: B1 (items 1–3) is **High** in deployments with dynamic client
registration enabled (the agentic/MCP pitch makes that likely) and wherever delegated
realm admins exist. Everything is reachable only in supported configurations — no
speculation involved.

### Item 1 — Unguarded `jwks.url` outbound fetch (blind SSRF + unbounded body)
`fetch_client_jwks` (`crates/issuerd-server/src/client_assertion.rs:315-338`) calls
`state.broker_client.get_json(jwks_url)` (`client_assertion.rs:330`) →
`ReqwestBrokerClient::get_json` (`crates/issuerd-server/src/broker.rs:106-121`): client
built with only a 10 s timeout (`broker.rs:54-57`) — **no https requirement, no IP/SSRF
check, reqwest-default redirect following, no response-size cap**. URL read verbatim from
client attributes (`client_assertion.rs:217-225`). Blind on the wire (uniform
`invalid_client` at `oidc.rs:2791-2792`; JAR → `invalid_request` at `jar.rs:201-213`);
timing oracle remains. Trigger is **unauthenticated** (token endpoint client assertion,
and JAR request-object validation at the authorize endpoint). The hardened sibling
`get_json_untrusted` (`broker.rs:188-251`: https-only, resolved-IP checks, no redirects,
64 KiB cap, generic error) exists but is used ONLY for `sector_identifier_uri`.

### Item 2 — Open DCR honors nearly the full admin `ClientRepresentation`
`POST /realms/{realm}/clients-registrations/default` (`register_open_handler`,
`crates/issuerd-server/src/routes/client_registration.rs:403`): unauthenticated when realm
attribute `dynamic_client_registration_enabled="true"` (default off,
`crates/issuerd-core/src/models.rs:2122-2131`); rate limit 50/h/IP fixed window
(`client_registration.rs:53,413-425`). The ONLY payload filter is dropping
`protocol_mappers` (`client_registration.rs:178-185`, comment admits "no
client-registration policy engine"). Honored wholesale: `attributes` map incl.
`jwks.url`/`use.jwks.url`/`jwks.string` (`crates/issuerd-admin-api/src/dto.rs:1559`),
`service_accounts_enabled` (dto.rs:1553), `enabled` default true, confidential-by-default
with caller-chosen `client_authenticator_type` incl. `client-jwt` (dto.rs:1523-1530),
`default_scopes`/`optional_scopes` when supplied, `full_scope_allowed` default true,
`backchannel_logout_uri`/`frontchannel_logout_uri`, `web_origins` incl. `"*"`,
`redirect_uris` with syntax-only validation — **no scheme allowlist** (`RedirectUri::new`,
`crates/issuerd-core/src/models.rs:435-447`; `javascript:`/`data:` parse as valid URLs).
→ Chain with Item 1 is **anonymously exploitable** when DCR is on.

### Item 3 — Server-global signing keys mutable by any realm's `manage-realm`
`crates/issuerd-admin-api/src/keys.rs:145` (rotate) and `:266` (disable):
`require_roles(&auth, &["manage-realm"])` — pure claim check, no master-realm restriction
(realm binding passes for path-realm tokens, `auth.rs:110-116`). Handlers operate on the
unscoped global `signing_keys` table (`keys.rs:148,209,218,270,278`); issuance key
selection is server-global (`crates/issuerd-token/src/token_manager.rs:789-791`).
Effects: disable of the active EdDSA key silently downgrades every un-pinned realm to the
next active key of ANY algorithm (fallback `token_manager.rs:786-791`); rotate demotes
same-algorithm keys and a rotate loop bloats the shared key set + every realm's JWKS
(secondary DoS; nothing prunes passive keys). Audit events are recorded against the
**path (attacker's) realm** and skipped entirely when that realm has
`admin_events_enabled=false` (`crates/issuerd-admin-api/src/audit.rs:43-45`) — a global
mutation with no guaranteed audit trail.

### Item 5 — Brute-force lockout: per-(username, IP) only, off by default
Default `brute_force_protected: false` (`crates/issuerd-core/src/models.rs:1908-1909,2040`
— matches Keycloak). Keys: `login-failure:{realm}:{username}:{ip}` /
`login-lockout:...` (`crates/issuerd-auth-flow/src/login_failures.rs:90-97`) — **no
per-username-global and no per-IP-only counter exists**; 300 s failure TTL;
`max_login_failures=5`, progressive wait ≤900 s, all lockouts temporary, no permanent
lockout. Failures keyed on canonical username, counted only for existing users. Empty
`trusted_proxies` (default, `crates/issuerd-server/src/config.rs:240-247`) behind an LB →
`ClientIp` = LB peer for everyone (`crates/issuerd-server/src/middleware/proxy_ip.rs:54-55`)
→ attacker can lock out any user for the whole site. Documented in three docs files
(deployment.md:246, configuration.md:314-320, security.md:88-92) but nothing enforces at
boot. ROPC + device-verify + SPA login share the counter. **Decision needed:** likely
docs/defaults/boot-warning only — no cheap code fix that keeps Keycloak parity.

### Item 6 — SSRF guard range gaps + DNS-rebinding TOCTOU
Guard = `is_publicly_routable` (`crates/issuerd-server/src/broker.rs:75-97`), a std-method
denylist. **Missing:** 100.64.0.0/10 (CGNAT; Alibaba metadata 100.100.100.200),
198.18.0.0/15, 240.0.0.0/4, 64:ff9b::/96 (NAT64), plus 0.0.0.0/8 beyond /32, 192.0.0.0/24,
2001:db8::/32, Teredo 2001::/32, 6to4 2002::/16. v4-mapped IPv6 inherits the v4 holes.
DNS: resolved IPs are checked, but reqwest re-resolves the hostname at connect
(`broker.rs:206-218` vs `:222-228`) — TOCTOU admitted in the code's own comment
(`broker.rs:184-187`). Footgun: trait default `get_json_untrusted` body is the UNGUARDED
`get_json` (`crates/issuerd-core/src/broker.rs:129-130`) — only the reqwest impl overrides
it; any future `BrokerClient` silently loses all protection.

### Item 7 — PKCE `plain` accepted despite S256-only advertisement; no `dpop_jkt`
Discovery hardcodes `code_challenge_methods_supported: [S256]`
(`crates/issuerd-protocol/src/discovery.rs:326`). Authorize accepts `plain` and even a
MISSING method (verified as plain per RFC 7636 default, `crates/issuerd-protocol/src/
pkce.rs:49-55`); codes issued with `plain` redeem successfully — passing e2e test
`auth_code_pkce_plain_success` (`crates/issuerd-server/src/routes/oidc.rs:11685-11728`).
No realm/client gate exists. `dpop_jkt` (RFC 9449 §10 auth-code↔DPoP binding) is not
implemented anywhere: no field in `AuthorizationRequest`/`AuthCodeData`; DPoP verified
only at token (`oidc.rs:2800,2825`) and userinfo (`oidc.rs:5240`); documented design point
`tests/KEYCLOAK_DIFFS.md:210`. §10 is optional → hardening gap, not a violation.
Compounds with: PKCE optional entirely for confidential clients
(`authorization.rs:206-211`).

### Item 8 — Unknown-`kid` cooldown griefing (bounded) + JAR variant with NO cooldown
`KID_MISS_REFETCH_COOLDOWN_SECS = 60`, per (realm, client)
(`client_assertion.rs:60,68-70`): armed unconditionally after any forced refetch, trigger
reachable unauthenticated (header-only parse, no signature check,
`crates/issuerd-token/src/client_assertion.rs:169-179`). Impact bounded (~60 s delay,
self-heals via 300 s cache refresh). **Worse:** the JAR path repeats the forced-refetch
pattern with NO cooldown at all (`crates/issuerd-server/src/routes/jar.rs:99-112`) — every
unauthenticated request object with an unknown `kid` forces an outbound fetch.

### Extras found during verification (not in the original review)
- **Backchannel logout POST SSRF:** registrant-controlled `backchannel_logout_uri` receives
  server-initiated POSTs of signed logout tokens via another plain reqwest client
  (`crates/issuerd-server/src/routes/logout.rs:58-95`).
- **Keys audit black hole** (in Item 3).
- **IdP "test connection"** reflects fetch failure reasons to the caller (reflective SSRF
  for admins, minor; `crates/issuerd-admin-api/src/idp.rs:538`).
- IdP discovery/JWKS fetches also unguarded (`broker.rs:304,371`) but operator-configured.

### Review claims that held up (no action)
Client assertions solid (per-client jti replay markers fail-closed, bounded audiences/
lifetime, constant-time secret compare); `sector_identifier_uri` guard real; auth-code
reuse revokes first-exchange tokens; DCR off by default and honestly documented;
registration does NOT eagerly fetch `jwks.url`; the registration-time
`sector_identifier_uri` fetch IS guarded.

---

## §3 Fix batches (implementation plan)

### Batch 1 — High chain (do first, one PR or stacked commits)

**1a. Harden the jwks.url fetch.** Route `fetch_client_jwks`
(`crates/issuerd-server/src/client_assertion.rs:330`) through the hardened path
(`get_json_untrusted` semantics: https-only, resolved-IP checks, no redirects, 64 KiB cap,
uniform error). Consider renaming `get_json_untrusted` → something URL-agnostic
(e.g. `get_json_ssrf_guarded`) since it stops being pairwise-specific; keep the old name
as deprecated alias if downstream crates reference it. Note: https-only is a behavior
change for admin-configured `http://` jwks URLs — acceptable (Keycloak also expects TLS);
call out in CHANGELOG.

**1b. DCR payload policy for the anonymous endpoint** (`register_open_handler` /
`register_client`, `crates/issuerd-server/src/routes/client_registration.rs:158-275`).
Write-path only; existing clients untouched. Strip or reject:
- attributes `jwks.url`, `use.jwks.url`, `jwks.string`, `use.jwks.string` → strip
  (anonymous clients must use `client_secret` or register JWKs by value only if a policy
  allows — simplest: strip all four; document);
- `service_accounts_enabled` → force false (Keycloak anonymous-registration parity);
- `backchannel_logout_uri` / `frontchannel_logout_uri` → strip (or https-only +
  scheme validation);
- `redirect_uris` → scheme allowlist: reject `javascript:`/`data:`/`vbscript:`; decide
  `http` policy (allow only loopback/localhost for dev? document);
- `web_origins` → reject literal `"*"`;
- keep the existing `protocol_mappers` drop.
Add integration tests in `tests/integration/dynamic_client_registration.rs` asserting each
field is stripped/forced on the open endpoint but still honored on the token-gated/admin
paths.

**1c. Master-only key administration.** `crates/issuerd-admin-api/src/keys.rs:145,266`:
require a master-realm token (mirror the realm-less-path rule in
`crates/issuerd-admin-api/src/auth.rs:106-109` — extract a helper, e.g.
`require_master_token`). Fix audit attribution: emit the admin event against the master
realm (or both realms), and do not let the path realm's `admin_events_enabled` suppress a
global mutation. CHANGELOG: security fix, delegated realm admins lose keys/rotate+disable
(migration: use a master-realm admin).

**1d. JAR refetch cooldown parity.** Share the kid-miss cooldown helper from
`client_assertion.rs` with `crates/issuerd-server/src/routes/jar.rs:99-112` (same
`client_jwks_kid_miss:{realm}:{client}` key namespace is fine).

Tests for the batch: existing suites `tests/integration/dynamic_client_registration.rs`,
admin-api keys tests, plus new unit/integration tests per above. Run
`cargo test --workspace` + clippy + fmt.

### Batch 2 — SSRF guard explicit range list
Replace the std-method denylist in `is_publicly_routable`
(`crates/issuerd-server/src/broker.rs:75-97`) with an explicit CIDR list. Block, IPv4:
0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24,
192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4; IPv6: ::/128, ::1/128,
::ffff:0:0/96 (recurse into v4 rules — keep existing behavior), 64:ff9b::/96, 2001::/32,
2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, ff00::/8. Unit-test every range boundary
(one passing + one blocked address each). Also: remove the unguarded default body of
`get_json_untrusted` in `crates/issuerd-core/src/broker.rs:129-130` (make it a required
trait method — compile-time guarantee).

### Batch 3 — Reject PKCE `plain` (DECISION REQUIRED before implementing)
Reject `code_challenge_method=plain` (and missing method?) at the authorize endpoint to
match the S256-only advertisement (OAuth 2.1 direction; the conformance suite never sends
plain — `tests/conformance/COVERAGE.md:131`). Update the passing plain e2e test
(`oidc.rs:11685`) to expect rejection. **Breaking change** for any client relying on
plain → CHANGELOG migration note. Note the RFC 7636 nuance: a missing
`code_challenge_method` means plain per spec — decide reject-missing too (recommended)
and say so in the note.

### Batch 4 — First-broker-login account-linking audit (read-only)
The external reviewer's unread account-takeover spot. Read the first-broker-login flow
(`crates/issuerd-server/src/broker.rs` + auth-flow first-broker-login handling): verify
account linking requires re-authentication as the existing local user (not just email
match), action-token binding/expiry/single-use, IdP mapper trust, and that
`kc_idp_hint`-driven flows can't bypass the link step. Deliverable: verdict report; fix
whatever it finds as Batch 4b.

### Deferred / optional hardening (list for later, don't lose)
- `dpop_jkt` authorization-code DPoP binding (RFC 9449 §10 feature; touches
  AuthorizationRequest/AuthCodeData/token endpoint).
- DNS-pinning connector for the guarded fetch (close the rebinding TOCTOU,
  `broker.rs:184-187`).
- Boot-time WARN when `brute_force_protected=false` or when `trusted_proxies` is empty
  while proxy headers would be honored (Item 5).
- Cap/ prune passive signing keys (rotate-loop JWKS bloat, Item 3 secondary DoS).
- Harden `backchannel_logout_uri` delivery client itself (`logout.rs:58-95`) independent of
  DCR filtering (admin-configured URLs): consider the guarded client + https-only.
- IdP "test connection": stop reflecting fetch internals to the caller (`idp.rs:538`).
- Long-term: `rsa` full exclusion (aws_lc_rs backend + openssl keygen) — see §1.

---

## §4 Quick commands for the pickup session

```bash
# state check
git status && git diff --stat          # §1 changes should be visible (or committed)
cargo deny check advisories            # expect: advisories ok
cargo audit                            # expect: clean

# gates before merging each batch
cargo fmt -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```
