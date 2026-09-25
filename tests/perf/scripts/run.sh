#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Orchestrator for the tests/perf benchmark stack. Run from tests/perf/.
# Git Bash on Windows or any POSIX shell.
#
# Subcommands:
#   genkc [N]                      generate keycloak/realm-perf.json (default 1000 users)
#   up-issuerd [small|medium|large]     boot postgres-issuerd + issuerd with tier limits
#   up-kc [medium|large]           boot postgres-kc + keycloak with tier limits
#   smoke <target>                 run the end-to-end smoke script
#   seed-issuerd <N> [with_password]    seed N users via Admin API (k6 admin_users, seed mode)
#   scenario <name> <target> [tier] [vus] [duration]
#                                  run one k6 scenario with stats sampling
#   matrix <target> <tier>         run the standard scenario set for target+tier
#   sizes <label>                  snapshot disk/log/image sizes
#   idle <target>                  record idle container footprint into sizes file
#   down                           tear down (keep volumes)
#   wipe                           tear down + delete volumes (full reset)
set -euo pipefail
cd "$(dirname "$0")/.."
# Git Bash (MSYS) rewrites /scripts/... arguments into Windows paths when
# invoking docker — disable path conversion for container-side paths.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

COMPOSE="docker compose -f docker-compose.perf.yml"
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULTS="results/$RUN_ID"
mkdir -p "$RESULTS"

tier_limits() { # $1=tier → echoes "CPUS MEM"
  case "$1" in
    small)  echo "1.0 512m" ;;
    medium) echo "2.0 1g" ;;
    large)  echo "4.0 2g" ;;
    *) echo "unknown tier $1" >&2; exit 1 ;;
  esac
}

app_containers() { # $1=target → containers to sample
  case "$1" in
    issuerd) echo "issuerd-perf-issuerd issuerd-perf-postgres-issuerd" ;;
    keycloak)  echo "issuerd-perf-keycloak issuerd-perf-postgres-kc" ;;
  esac
}

cmd=${1:-help}; shift || true

case "$cmd" in
  genkc)
    python scripts/gen_kc_realm.py "${1:-1000}"
    ;;

  up-issuerd)
    tier=${1:-medium}; read -r cpus mem <<<"$(tier_limits "$tier")"
    ISSUERD_CPUS=$cpus ISSUERD_MEM=$mem $COMPOSE up -d --wait postgres-issuerd issuerd
    echo "issuerd up (tier=$tier, cpus=$cpus, mem=$mem)"
    ;;

  up-kc)
    tier=${1:-medium}; read -r cpus mem <<<"$(tier_limits "$tier")"
    KC_CPUS=$cpus KC_MEM=$mem $COMPOSE up -d --wait postgres-kc ad-simulator keycloak
    # The built-in master realm keeps sslRequired=external, which rejects the
    # admin-cli password grant over the internal HTTP network (loopback inside
    # the container is exempt — kcadm works there). Relax it to NONE so the
    # seeding scenario can obtain admin tokens. Perf-realm traffic is
    # unaffected (realm-perf.json sets sslRequired=none at import).
    docker exec issuerd-perf-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
      --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
    docker exec issuerd-perf-keycloak /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE
    echo "keycloak up (tier=$tier, cpus=$cpus, mem=$mem; master sslRequired=NONE applied)"
    ;;

  smoke)
    $COMPOSE run --rm k6 run "/scripts/smoke.js" --env "TARGET=${1:-issuerd}"
    ;;

  seed-issuerd)
    n=${1:?usage: seed-issuerd N [with_password]}
    withpw=${2:-true}
    $COMPOSE run --rm k6 run /scripts/scenarios/admin_users.js \
      --env TARGET=issuerd --env TIER=seed --env MODE=seed \
      --env "SEED_N=$n" --env "WITH_PASSWORD=$withpw" --env NAMING=pool \
      --env "VUS=${VUS:-20}" --env "RUN_DIR=/results/$RUN_ID"
    ;;

  scenario)
    name=${1:?scenario name}; tgt=${2:?target}; tier=${3:-medium}
    vus=${4:-}; dur=${5:-}
    echo "== scenario=$name target=$tgt tier=$tier run=$RUN_ID =="
    stats_file="$RESULTS/stats_${name}_${tgt}_${tier}.jsonl"
    # shellcheck disable=SC2086
    ./scripts/stats_sampler.sh "$stats_file" $(app_containers "$tgt") &
    sampler=$!
    trap 'kill $sampler 2>/dev/null || true' EXIT
    args=(run --rm k6 run "/scripts/scenarios/$name.js"
      --env "TARGET=$tgt" --env "TIER=$tier" --env "RUN_DIR=/results/$RUN_ID"
      --env "NUM_USERS=${NUM_USERS:-1000}")
    [ -n "$vus" ] && args+=(--env "VUS=$vus")
    [ -n "$dur" ] && args+=(--env "DURATION=$dur")
    $COMPOSE "${args[@]}"
    rc=$?
    kill $sampler 2>/dev/null || true
    trap - EXIT
    exit $rc
    ;;

  matrix)
    tgt=${1:?target}; tier=${2:-medium}
    # Same scenario set for both targets — Keycloak 26.7 supports DPoP and
    # CIBA (CIBA approvals are performed by the ad-simulator container).
    scenarios="discovery client_credentials password_grant userinfo introspect auth_code_flow dpop ciba admin_users"
    for s in $scenarios; do
      # Keep collecting later scenarios even if one crosses its error
      # threshold (k6 exits non-zero then); error rates are recorded in the
      # JSON summaries and reported, not hidden.
      if ! "$0" scenario "$s" "$tgt" "$tier"; then
        echo "WARNING: scenario $s ($tgt/$tier) crossed a threshold — see results JSON" >&2
      fi
    done
    ;;

  sizes)
    ./scripts/measure_sizes.sh "${1:-snapshot}" "$RESULTS"
    ;;

  idle)
    tgt=${1:?target}
    # container must be up and settled; records a stats sample without load
    # shellcheck disable=SC2086
    docker stats --no-stream --format '{{json .}}' $(app_containers "$tgt") \
      | sed "s/^{/{\"ts\":$(date +%s),\"label\":\"idle\",/" >> "$RESULTS/idle_${tgt}.jsonl"
    echo "idle footprint recorded into $RESULTS/idle_${tgt}.jsonl"
    ;;

  down)
    $COMPOSE down --remove-orphans
    ;;

  wipe)
    $COMPOSE down -v --remove-orphans
    ;;

  *)
    sed -n '1,30p' "$0"
    ;;
esac
