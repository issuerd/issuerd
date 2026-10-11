# Certification Execution Matrix

Exact suite invocations this plan adds to `tests/conformance/scripts/run-conformance.sh`.
Suite pinned at `release-v5.3.2`; counts verified against the plan classes in
`conformance-suite/src/main/java/net/openid/conformance/openid/`.

> **Status 2026-10-11: the full matrix below is GREEN** — `run.sh` exit 0
> (gate v10, evidence `tests/conformance/results/html-reports-20261011-193753`):
> 0 failures / 0 unexpected warnings across all 43 invocations — **612 executed
> test modules green**; the only in-plan failure is the expected
> `oidcc-server-rotate-keys` (real evidence via `run-rotation-check.sh`:
> PASSED). The published 634 counts the suite's reporting convention (the
> runner prints listing+1 per plan) plus the dynamic_client-only modules
> (`oidcc-id-token-signature`, `oidcc-idtoken-unsigned`) that static runs mark
> N/A — the M6 certification-grade dynamic reruns cover them.

Variant-string syntax is the one already in use
(`plan[server_metadata=discovery][client_registration=static_client]`).
Variants not pinned by the plan and not listed here have no suite-side default
and would be menu-selected in interactive use — always spell them out.

Legend: ✅ passing today · 🆕 added by this plan · *(dyn)* count under
`client_registration=dynamic_client` · *(static)* count under `static_client`.

## Regular profiles

### Basic OP — ✅ done

```
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
```

Config `issuerd-basic-op.json` · 36 modules · skips `issuerd-expected-skips.json`.

### Config OP — ✅ done

```
oidcc-config-certification-test-plan
```

Config `issuerd-config-op.json` · 1 module · skips `issuerd-expected-skips-config.json`.

### Implicit OP — 🆕 (WS-A)

```
oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]
```

Config `issuerd-implicit-op.json` · 54 modules *(static, listed)* / 58 *(dyn, published count)*.
One run covers both `id_token` (27 modules) and `id_token token` (27 + 4
userinfo/response-type-missing modules). Certification-grade submission run:
same plan with `[client_registration=dynamic_client]` (post-WS-C).

### Hybrid OP — 🆕 (WS-A)

```
oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]
```

Config `issuerd-hybrid-op.json` · 96 *(static, listed)* / 102 *(dyn, published count)*.
One run covers `code id_token` (36), `code token` (33), `code id_token token`
(33). Certification-grade run: dynamic_client (post-WS-C).

### Form Post OP — basic ✅ / implicit+hybrid 🆕 (WS-A)

```
oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]     # ✅ 36
oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]  # 🆕 54/58
oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]    # 🆕 96/102
```

Configs `issuerd-formpost-op.json` (exists), `issuerd-formpost-implicit-op.json`,
`issuerd-formpost-hybrid-op.json`. `response_mode=form_post` is pinned by the
plans themselves. Published Form Post total: 196 = 36 + 58 + 102 (dyn counts
for the two new runs).

### Dynamic OP — 🆕 (WS-C)

Six invocations, one per response type (client auth pinned to
`private_key_jwt` by the plan; `client_registration=dynamic_client` pinned):

```
oidcc-dynamic-certification-test-plan[response_type=code]
oidcc-dynamic-certification-test-plan[response_type=code id_token]
oidcc-dynamic-certification-test-plan[response_type=code id_token token]
oidcc-dynamic-certification-test-plan[response_type=code token]
oidcc-dynamic-certification-test-plan[response_type=id_token]
oidcc-dynamic-certification-test-plan[response_type=id_token token]
```

Config `issuerd-dynamic-op.json` (same file for all six) · per-run modules
(exact `[1:N]` listings, verified against the gate-v10 logs):
`code` 23 · `code id_token` 22 · `code id_token token` 22 · `code token` 23 ·
`id_token` 18 · `id_token token` 19 → **127** total (the published count).
Skips `issuerd-expected-skips-dynamic.json`; failures
`issuerd-expected-failures-dynamic.json` lists only
`oidcc-server-rotate-keys` (manual-step module — see README §5.3; evidence via
`run-rotation-check.sh` standalone run).
URL-encoded response-type values (`%20` for spaces) if the runner requires it —
mirror however the suite CLI accepts multi-word variant values; verify on first
run.

### 3rd Party-Init OP — 🆕 (WS-C)

Six invocations (response type is menu-selected but never exercised; run all
six for the published total):

```
oidcc-3rdparty-init-login-certification-test-plan[response_type=<each of the six>]
```

Config `issuerd-3rdparty-init-op.json` · 2 modules per run
(`oidcc-3rd_party-init-login`, `oidcc-3rd_party-init-login-nohttps`) → **12** total.

## Logout profiles

All four: `server_metadata=discovery` pinned by the plans;
`client_registration=static_client` chosen (clients pre-provisioned by
`bootstrap-issuerd.sh` with the logout URIs — see README §5.1);
`client_auth_type=client_secret_basic`; six invocations each, one per
response type.

### RP-Initiated OP — 🆕 (WS-A + WS-D)

```
oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=<each of the six>]
```

Config `issuerd-rpinitiated-logout-op.json` · 11 modules per run
(1 discovery verification + 10 logout scenarios) → **66** total.
Expect REVIEW flags on the screenshot modules (error/confirmation pages) —
same posture as today's `oidcc-ensure-registered-redirect-uri`.

### Session OP — 🆕 (WS-B)

```
oidcc-session-management-certification-test-plan[client_registration=static_client][response_type=<each of the six>]
```

Config `issuerd-session-op.json` · 2 modules per run
(`oidcc-session-management-discovery-endpoint-verification`,
`oidcc-session-management-rp-initiated-logout`) → **12** total.

### Front-Channel OP — 🆕 (WS-A + WS-D)

```
oidcc-frontchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=<each of the six>]
```

Config `issuerd-frontchannel-logout-op.json` · 2 modules per run → **12** total.

### Back-Channel OP — 🆕 (WS-A + WS-D)

```
oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=<each of the six>]
```

Config `issuerd-backchannel-logout-op.json` · 2 modules per run → **12** total.

## Totals

| Group | Plans (invocations) | Module executions | Passing today |
|---|---|---|---|
| Regular | 8 (1+1+1+1+3+6+6 …) | 532 | 73 |
| Logout | 4 (6+6+6+6) | 102 | 0 |
| **Combined** | | **634** | **73** |

Full-green target: **634/634** (REVIEW-flagged screenshot modules count as
passing once visually verified; the only expected-failure entry anywhere is
`oidcc-server-rotate-keys` inside the six Dynamic runs, covered by the
standalone rotation check).
