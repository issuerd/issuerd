# Issuerd Performance Benchmark Rig

Hermetic k6 benchmark environment comparing **Issuerd** against **Keycloak 26.7** under
identical Docker CPU/memory limits. Results feed `docs/PERFORMANCE.md`.

## Properties

- **Fully isolated**: the compose network is `internal: true` — no internet access in
  either direction at runtime, nothing is published. All container-to-container
  traffic stays on `perf-net` (172.34.0.0/24).
- **No remote fetches at run time**: every image must already be local; k6 scripts import
  only local files (`k6/lib.js`); k6 usage reporting is disabled.
- **Reproducible**: fixed image tags (`issuerd:perf` built from the repo root `Dockerfile`,
  `keycloak-optimized:26.7.4` built from `keycloak/Dockerfile` on top of `keycloak/keycloak:26.7.4`,
  `postgres:15-alpine`, `grafana/k6:2.1.0`, `python:3.12-alpine`), tier limits via
  `deploy.resources.limits`, results + raw stats land in `results/<RUN_ID>/`.

## Layout

```
docker-compose.perf.yml   # isolated stack: postgres-issuerd, issuerd, postgres-kc, keycloak,
                          # ad-simulator, k6
issuerd.perf.toml       # daemon config (Postgres, JSON logs at INFO)
provision.perf.yaml       # realm perf + clients perf-service / perf-public + base users
keycloak/Dockerfile       # optimized production build of KC 26.7 (kc.sh build → start --optimized)
keycloak/realm-perf.json  # generated (gitignored) — gen_kc_realm.py, mirrors the same setup
ad-simulator/server.py    # Keycloak CIBA authentication-device simulator (auto-approve)
k6/lib.js                 # shared helpers incl. DPoP proof minting (WebCrypto ES256), CIBA, PKCE
k6/smoke.js               # end-to-end validation of every flow (run first!)
k6/scenarios/*.js         # discovery, client_credentials, password_grant, userinfo,
                          # introspect, auth_code_flow, dpop, ciba, admin_users
scripts/run.sh            # orchestrator (up/seed/scenario/matrix/sizes/down)
scripts/stats_sampler.sh  # docker stats → JSONL during a scenario
scripts/measure_sizes.sh  # DB size, row counts, log bytes, image sizes → sizes.txt
scripts/charts.py         # results → PNG charts into docs/images/perf/ + results/digest.json
```

## Prerequisites

- Docker images present locally: `issuerd:perf` (build from repo root:
  `docker build -t issuerd:perf -f Dockerfile .`), `keycloak-optimized:26.7.4`
  (build once from this directory:
  `docker compose -f docker-compose.perf.yml build keycloak` — multi-stage on top of
  `keycloak/keycloak:26.7.4`, `kc.sh build` bakes db/health/metrics so the container runs
  `start --optimized`), `postgres:15-alpine`, `grafana/k6:2.1.0`, `python:3.12-alpine`
  (CIBA ad-simulator).
- Python 3 with matplotlib (charts only): `pip install matplotlib`.

## Quick start

```bash
cd tests/perf

# one-time: generate the Keycloak realm import (1000 users, mirrors provision.perf.yaml)
python scripts/gen_kc_realm.py

# one-time: build the optimized production Keycloak image
docker compose -f docker-compose.perf.yml build keycloak

# boot both sides at the medium tier (2 CPU / 1 GiB app limits)
./scripts/run.sh up-issuerd medium
./scripts/run.sh up-kc medium

# validate all request shapes (DPoP, CIBA, auth-code, admin seeding, ...)
./scripts/run.sh smoke issuerd
./scripts/run.sh smoke keycloak

# seed 1000 users WITH passwords into Issuerd (user pool for ROPC scenarios)
./scripts/run.sh seed-issuerd 1000 true

# full scenario matrix for one target+tier (results under results/<RUN_ID>/)
export RUN_ID=$(date +%Y%m%d-%H%M%S)
./scripts/run.sh matrix issuerd medium
./scripts/run.sh matrix keycloak medium

# individual scenario, custom load
./scripts/run.sh scenario userinfo issuerd medium 100 60s

# disk/log/image snapshots (labels are free-form)
./scripts/run.sh sizes baseline

# charts + digest (after runs)
python scripts/charts.py results/

# teardown
./scripts/run.sh down     # keep DB volumes
./scripts/run.sh wipe     # delete volumes too (required to re-provision / re-import)
```

## Full campaign (the numbers in docs/PERFORMANCE.md)

```bash
RUN_ID=myrun ./scripts/campaign.sh
```

Unattended ~1.5 h: wipe → fresh boot → baselines/idle → medium matrices (both servers)
→ small/large tier matrices → seeding ladder to 116k users → 100k-user login scale
tests → log-volume bursts with size snapshots. Then regenerate the doc artifacts:

```bash
python scripts/charts.py results/myrun   # PNGs → docs/images/perf/, digest → results/digest.json
```

Published numbers in `docs/PERFORMANCE.md` come only from real runs of this stack —
never hand-edit them.


## Tiers

| tier   | app container limits | applied to |
|--------|----------------------|------------|
| small  | 1.0 CPU / 512 MiB    | `ISSUERD_CPUS`/`ISSUERD_MEM` or `KC_CPUS`/`KC_MEM` |
| medium | 2.0 CPU / 1 GiB      |            |
| large  | 4.0 CPU / 2 GiB      |            |

PostgreSQL is fixed at 2 CPU / 2 GiB; k6 at 4 CPU / 2 GiB so neither is the bottleneck.
Switching tiers requires recreating the app container, e.g.
`ISSUERD_CPUS=1.0 ISSUERD_MEM=512m docker compose -f docker-compose.perf.yml up -d --force-recreate issuerd`
(or `./scripts/run.sh up-issuerd small` after `down`).

## Scenarios and fairness notes

- Same realm/client/user shape on both servers (`perf` realm; `perf-service` confidential,
  `perf-public` public w/ PKCE; users `user0001..user1000`, password `Perf-Pass-123!`).
- `password_grant` is password-hash-bound. Both servers hash with their **out-of-box
  defaults**, now both Argon2id but with different parameters (verified from stored
  credentials): Issuerd m=19,456 KiB / t=2 / p=1 (RFC 9106 first recommendation),
  Keycloak 26.7 m=7,168 KiB / t=5 / p=1. KC 24's default was PBKDF2-SHA256, so KC's
  login-path numbers are not comparable across baselines — see `docs/PERFORMANCE.md`
  §1.3. `client_credentials` shows the raw issuance path without password hashing.
- Issuerd writes `events` rows per login by default (Keycloak does not persist login
  events by default) — see `docs/PERFORMANCE.md` for the measured cost and how to toggle it.
- DPoP and CIBA run against both targets. KC 26.7 supports both by default; CIBA approval
  (out of spec, per-deployment) is performed by the `ad-simulator` container through KC's
  `ciba-http-auth-channel`: KC POSTs each backchannel auth request to the simulator, which
  answers 201 immediately and approves from a background thread via KC's CIBA callback
  (the callback only works after bc-auth commits, so a synchronous approve would 403).
  The k6 KC path then waits a modeled 200 ms device-approval latency before its first
  poll — the KC analogue of issuerd's in-loop `ext/ciba/approve` call.

## Troubleshooting

- **`docker compose config` fails / image missing** — build/pull the images first (the base
  images are never pulled at `up` time because the network is internal; pull from a shell with
  network; `docker compose -f docker-compose.perf.yml build keycloak` builds the optimized
  Keycloak image from the local `keycloak/keycloak:26.7.4` base).
- **Smoke fails at `auth_code_login` for keycloak** — the realm import didn't happen; check
  `docker logs issuerd-perf-keycloak` and that `keycloak/realm-perf.json` exists before first boot
  (imports run only against a fresh database — `wipe` and retry).
- **k6 cannot resolve hosts** — always run k6 via `docker compose run --rm k6 ...` (it must be
  on `perf-net`).
