# Keycloak migration acceptance harness

This directory contains a stdlib-Python acceptance harness for mixed-credential
Keycloak realm migration. Its real-Keycloak lane produces reproducible engineering
acceptance evidence, not an external MLabs certification or a production-cutover
guarantee.

## Real Keycloak 26.7.1 export

```bash
python3 tests/keycloak-migration/run.py
```

The default lane starts a disposable PostgreSQL + `quay.io/keycloak/keycloak:26.7.1`
stack, provisions the realm exclusively through Keycloak's Admin API, changes the
realm password policy between user creations, verifies source logins, stops
Keycloak, runs `kc.sh export --dir /export --realm migration-lab --users realm_file`,
and checks every credential row through a read-only PostgreSQL oracle. The source
User Profile is explicitly configured through `/users/profile` with
`unmanagedAttributePolicy=ADMIN_EDIT`, so the fixture's custom attributes survive
Keycloak 26.7.1 writes without enabling end-user writes.

The realm includes confidential and public clients, top-level group membership,
direct composite realm/client role assignments, a non-member control, all nine
supported mappers, and default/optional scopes. Source claim checks prove that the
composite-derived roles and group membership are present, the non-member does not
receive `developers`, and the optional claim appears only when requested.

The lane then starts a fresh Issuerd target, imports the export through
`partialImport`, and verifies inventory, every enabled user's login, PKCE,
UserInfo claims, negative cases, and an ordinary password change. The target uses
a fresh target-only client secret; source client secrets are never reused.

`target/debug/issuerd` is rebuilt with `cargo build --bin issuerd` by default.
Override it with `--issuerd-bin /path/to/issuerd` to test a particular release
binary instead.

## Backend matrix

Both the real and synthetic lanes accept all five target configurations:

```bash
python3 tests/keycloak-migration/run.py --backend in-memory
python3 tests/keycloak-migration/run.py --backend json-file
python3 tests/keycloak-migration/run.py --backend sqlite
python3 tests/keycloak-migration/run.py --backend postgres
python3 tests/keycloak-migration/run.py --backend postgres-redis
```

The last mode starts a second target container on the same isolated Compose
network, sharing PostgreSQL and Redis but publishing its HTTP port only on the
host's loopback address. Both nodes authenticate every enabled user before and
after restart, including the ordinary changed password.

Durable backends are restarted before a second login pass. A read-only backend
oracle proves that login did not rewrite any imported hash and that changing one
password left every other imported hash unchanged. In-memory no-rehash behavior
is covered by the Rust integration acceptance. Temporary raw exports, secret
inputs, configs, database files, and logs are removed. Sanitized JSON and JUnit
evidence plus redacted target logs are written to
`tests/keycloak-migration/results/<UTC timestamp>/` (gitignored), or to
`--evidence-dir`.

The nightly/release heavy workflow runs the real-Keycloak lane for all five
backends and packs only this sanitized evidence into one artifact with a 30-day
retention period. A failed matrix member blocks release publication.

## Local compatible fixture (no source Keycloak)

Add `--synthetic` to any backend command above. The synthetic lane generates
unique disposable passwords, salts, PBKDF2 digests, and an Argon2id PHC value
using the workspace's existing `argon2` crate. Its manifest explicitly says it
is not Keycloak-produced. Only the default lane is evidence for a real Keycloak
export.

## Independently supplied sanitized fixture

```bash
python3 tests/keycloak-migration/run.py \
  --fixture /path/to/sanitized-keycloak-realm.json \
  --manifest /path/to/fixture-manifest.json \
  --secrets /path/to/fixture-secrets.json
```

If `--manifest` and `--secrets` are omitted, the harness looks for
`fixture-manifest.json` and `fixture-secrets.json` beside the fixture. The secret
input must be local-only with mode `0600` and follows
`fixture-secrets.schema.json`:

```json
{
  "users": {"alice-argon2id": "disposable-password"},
  "client_secret": "disposable-source-client-secret"
}
```

The manifest follows `fixture-manifest.schema.json`: it records algorithms and
per-row parameters, scope/mapper expectations, and semantic claim checks, never
hashes, salts, passwords, tokens, or private keys. All enabled manifest users
must have a disposable password in the secret input. The fixture itself must
contain full `users`, `credentials`, `clientScopes`, and mapper definitions.

A green run prints `KEYCLOAK_MIGRATION_OK`. A failure exits nonzero, identifies
the stage/resource without printing secrets, and leaves only sanitized evidence.
