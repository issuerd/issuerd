# Issuerd OIDC Conformance Test Suite

Automated runs of the [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) against Issuerd in a **hermetic environment**: an isolated docker network with no internet access, bind9 as the only DNS, and TLS everywhere from a local root CA. The conformance suite runs **pristine** — unpatched JAR built from the untouched upstream sources, no intercepting proxies, upstream runner scripts byte-for-byte. The only deviation from a stock deployment is the local root CA imported into the suite's JVM truststore at container start.

## How to run

```bash
# 1. Clone the conformance suite source (once; gitignored):
git clone https://gitlab.com/openid/conformance-suite.git tests/conformance/conformance-suite
cd tests/conformance/conformance-suite && git checkout release-v5.2.4 && cd -

# 2. Run everything:
cd tests/conformance
docker compose up
```

or `./run.sh` from anywhere — same thing, but it also tears the stack down
at the end and exits non-zero on unexpected failures (CI-friendly). On Linux
it exports `DOCKER_HOST_UID`/`DOCKER_HOST_GID` from `id -u`/`id -g` so the
runner containers can write into the bind-mounted `./pki` and `./results`
(the compose default 1000 only matches the first local user; the GitHub
Actions runner is 1001); on failure it dumps the stack logs before teardown.

`docker compose up` builds missing images on first run (the suite JAR is
built in-docker from `conformance-suite/` — maven downloads are cached
between builds; the OP image builds the full Issuerd release binary),
generates the local PKI, bootstraps the realm, runs all three test plans
and exports the reports. Watch for `Conformance test run complete: all
plans OK` in the log, then Ctrl+C (or `docker compose down --volumes` from
another shell). Subsequent runs reuse the build cache and take ~3 minutes.

Results land in `tests/conformance/results/`:

- `html-reports-<timestamp>/index.html` — human-readable reports per plan
- `export-json/` — machine-readable JSON exports (upstream `--export-dir`)
- `exports/` — raw exporthtml zips
- `oidcc-*-output.log` — full runner logs

Useful variations:

```bash
docker compose up --build            # force image rebuilds (e.g. after Issuerd changes)
docker compose down --volumes        # tear down and reset all state
./run-focus.sh oidcc-refresh-token   # run a single module of the Basic OP plan
```

Internet access is needed only at build time (base images, maven/npm/cargo
downloads). The test environment itself never touches the internet —
`run-conformance.sh` verifies this on every run.

## How it works

```
┌──────────────────────────────────────────────────────────────────────┐
│  conformance-net (docker bridge, internal: true — no internet)       │
│  Every container resolves via bind9 (172.31.0.2) only; bind9 is      │
│  authoritative for conformance.test + the shimmed CDN hostnames and  │
│  refuses everything else.                                            │
│                                                                      │
│  bind9             172.31.0.2   DNS: conformance.test + CDN shim zones│
│  mongodb           172.31.0.10  mongo.conformance.test:27017         │
│  conformance-server 172.31.0.11 suite.conformance.test:8443 (HTTPS)  │
│  issuerd-op      172.31.0.12  op.conformance.test:8443 (HTTPS)     │
│  cdn-shim          172.31.0.15  nginx: vendored CDN assets (HTTPS)   │
│  pki-init          172.31.0.3   one-shot: ./pki via gen-certs.sh     │
│  conformance-run   172.31.0.13  one-shot: bootstrap + plans + reports│
│  test-runner       172.31.0.14  idle debug shell (run-focus.sh)      │
└──────────────────────────────────────────────────────────────────────┘
```

- **TLS / trust**: `pki/gen-certs.sh` creates a local root CA and issues certs for `op.conformance.test` (Issuerd, native rustls TLS) and `suite.conformance.test` (suite, native Spring Boot HTTPS via `server.ssl.*` JVM flags). At container start `scripts/suite-entrypoint.sh` imports the root CA into the JVM cacerts — so the suite's HtmlUnit browser trusts both endpoints. The suite's own outbound HTTP client is trust-all by design; the runner skips verification in dev mode (upstream behavior).
- **Pristine suite**: the JAR is built by `Dockerfile.suite` straight from `conformance-suite/` and never patched. Browser automation works without hacks because (a) upstream's `implicitCallback.html` self-heals via its issue-#766 `assumeComplete()` fallback, and (b) screenshot placeholders are filled by the suite's own `update-image-placeholder(-optional)` browser-task commands — including per-module `override` sections in `configs/issuerd-basic-op.json`, the same pattern upstream's CI uses.
- **Isolation**: `internal: true` blocks routing in both directions (Docker does not publish ports on such networks — all host interaction goes through `docker compose exec`). bind9 has no forwarders and no recursion, so external names are REFUSED instantly — with six deliberate exceptions, the CDN hostnames the pristine suite web UI references (`cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `cdn.datatables.net`, `fonts.googleapis.com`, `fonts.gstatic.com`, `oss.maxcdn.com`): those resolve to the `cdn-shim` container, which serves the vendored mirror under `cdn-shim/<host>/<path>` over CA-trusted TLS, so HtmlUnit gets 200s instead of logging `UnknownHostException` stacks. `run-conformance.sh` still asserts on every run that a real external name is refused. Re-vendor with `cdn-shim/fetch.sh` (needs internet). Docker's embedded DNS chains unknown names to bind9, so container names keep working.
- **Quiet mongo**: the `mongodb` service runs `mongod --quiet`, suppressing per-connection NETWORK INFO lines (the 5s healthcheck would otherwise be the loudest container in the stack).
- **Realm bootstrap**: `bootstrap-issuerd.sh` creates the `conformance` realm, two confidential clients, and a fully attributed user over the Admin API (inside the network, CA-verified TLS). Issuerd runs on in-memory storage — every `docker compose up` starts from a clean slate.

## Test plans

| Plan | Config | Description |
|------|--------|-------------|
| `oidcc-config-certification-test-plan` | `configs/issuerd-config-op.json` | Discovery metadata & JWKS — **PASSED** |
| `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` | `configs/issuerd-basic-op.json` | Authorization code flow — **PASSED** |
| `oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` | `configs/issuerd-formpost-op.json` | Code flow via `response_mode=form_post` — **PASSED** |

Suite version `release-v5.2.4`. Latest full run: **0 failures, 0 warnings** on all three plans — per-module detail in `COVERAGE.md`. The two request-object modules are expected skips (a signed-only OP must not advertise `none` in `request_object_signing_alg_values_supported`).

## Files

```
tests/conformance/
├── README.md                  # this file
├── COVERAGE.md                # per-module results, known gaps
├── docker-compose.yml         # the whole environment (see "How it works")
├── run.sh                     # one-command wrapper: compose up with exit-code propagation
├── run-focus.sh               # run a single Basic OP module against the stack
├── Dockerfile.suite           # pristine suite image (maven JAR build + temurin JRE)
├── Dockerfile.runner          # runner image (python + deps baked in, no runtime internet)
├── issuerd.toml             # OP config: port 8443, native TLS, issuer op.conformance.test
├── bootstrap-issuerd.sh     # realm/client/user seeding (runs inside the network)
├── pki/gen-certs.sh           # local root CA + server certs + PKCS12 keystore (artifacts gitignored)
├── dns/                       # bind9 config: conformance.test zone, no recursion/forwarders
├── configs/                   # test plan configs + expected skips/failures
├── conformance-suite/         # pristine upstream suite clone (gitignored; you create this)
├── scripts/
│   ├── run-conformance.sh     # the one-shot run: checks, bootstrap, 3 plans, reports
│   ├── suite-entrypoint.sh    # suite container entrypoint: root CA -> JVM cacerts, native HTTPS
│   └── export-html.py         # HTML report export/extraction (public suite API only)
└── results/                   # test output (gitignored)
```

## CI integration

```bash
conformance)
  git clone --depth 1 --branch release-v5.2.4 https://gitlab.com/openid/conformance-suite.git 
  tests/conformance/run.sh   # exits non-zero on unexpected failures
  ;;
```
