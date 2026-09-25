#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Full measurement campaign for docs/PERFORMANCE.md. Runs unattended (~1.5 h):
# fresh DBs → baselines → medium matrices (both servers) → tier matrices →
# disk-scale seeding (1k/10k/100k users) → 100k-user login scale test →
# log-volume bursts. Everything lands in results/<RUN_ID>/ (default: run2).
#
# Prereq: issuerd:perf image built from current HEAD, keycloak/realm-perf.json
# generated, all images local. Usage:
#   ./scripts/campaign.sh            # RUN_ID=run2
#   RUN_ID=myrun ./scripts/campaign.sh
set -uo pipefail   # NOT -e: individual stage failures must not abort the campaign
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
export RUN_ID="${RUN_ID:-run2}"
COMPOSE="docker compose -f docker-compose.perf.yml"

stage() { echo; echo "################ stage: $* ($(date +%T)) ################"; }

stage "wipe + fresh boot (medium tier)"
./scripts/run.sh wipe
./scripts/run.sh up-issuerd medium || exit 1
./scripts/run.sh up-kc medium || exit 1
./scripts/run.sh smoke issuerd || exit 1
./scripts/run.sh smoke keycloak || exit 1

stage "baseline sizes + idle footprints"
./scripts/run.sh sizes baseline
./scripts/run.sh idle issuerd
./scripts/run.sh idle keycloak

stage "seed 1k pool users (with passwords)"
./scripts/run.sh seed-issuerd 1000 true
./scripts/run.sh sizes users-1k

stage "matrix: issuerd medium"
./scripts/run.sh matrix issuerd medium
stage "matrix: keycloak medium"
./scripts/run.sh matrix keycloak medium
./scripts/run.sh sizes after-medium

stage "matrix: issuerd small (1 CPU / 512 MiB)"
ISSUERD_CPUS=1.0 ISSUERD_MEM=512m $COMPOSE up -d --force-recreate --wait issuerd && \
  ./scripts/run.sh matrix issuerd small

stage "matrix: issuerd large (4 CPU / 2 GiB)"
ISSUERD_CPUS=4.0 ISSUERD_MEM=2g $COMPOSE up -d --force-recreate --wait issuerd && \
  ./scripts/run.sh matrix issuerd large

stage "matrix: keycloak large (4 CPU / 2 GiB)"
KC_CPUS=4.0 KC_MEM=2g $COMPOSE up -d --force-recreate --wait keycloak && \
  ./scripts/run.sh matrix keycloak large

stage "keycloak small attempt (1 CPU / 512 MiB)"
if KC_CPUS=1.0 KC_MEM=512m $COMPOSE up -d --force-recreate --wait keycloak; then
  ./scripts/run.sh matrix keycloak small
else
  echo "NOTE: keycloak failed to become healthy at the small tier — recorded as unsupported"
  docker logs issuerd-perf-keycloak --tail 5 2>/dev/null | sed 's/^/kc-log: /'
fi

stage "restore medium tiers"
ISSUERD_CPUS=2.0 ISSUERD_MEM=1g $COMPOSE up -d --force-recreate --wait issuerd
KC_CPUS=2.0 KC_MEM=1g $COMPOSE up -d --force-recreate --wait keycloak

stage "seed to 10k users"
VUS=20 ./scripts/run.sh seed-issuerd 10000 true
./scripts/run.sh sizes users-10k

stage "seed to 100k users (bulk provisioning rate is measured by this run)"
VUS=40 ./scripts/run.sh seed-issuerd 100000 true
./scripts/run.sh sizes users-100k-raw

stage "isolate user-count effect: clear accumulated sessions/events"
docker exec issuerd-perf-postgres-issuerd psql -U issuerd -d issuerd \
  -c "TRUNCATE user_sessions, client_sessions, events, admin_events"
./scripts/run.sh sizes users-100k

stage "scale test: password_grant across 100k distinct users (medium, 40 VU, 120 s)"
NUM_USERS=100000 ./scripts/run.sh scenario password_grant issuerd medium 40 120s
./scripts/run.sh sizes after-scale-login

stage "scale test: auth_code_flow at 100k users (medium, 15 VU, 90 s)"
NUM_USERS=100000 ./scripts/run.sh scenario auth_code_flow issuerd medium 15 90s

stage "log-volume bursts (sizes before/after each)"
for s in discovery client_credentials ciba; do
  ./scripts/run.sh sizes "log-pre-$s"
  ./scripts/run.sh scenario "$s" issuerd medium "" 30s
  ./scripts/run.sh sizes "log-post-$s"
done
./scripts/run.sh sizes log-pre-password_grant
NUM_USERS=100000 ./scripts/run.sh scenario password_grant issuerd medium 20 60s
./scripts/run.sh sizes log-post-password_grant

stage "final sizes + idle"
./scripts/run.sh sizes final
./scripts/run.sh idle issuerd
./scripts/run.sh idle keycloak

echo; echo "CAMPAIGN DONE — results in results/$RUN_ID"
