#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot disk/log/size facts into results/<RUN_ID>/sizes.txt (key=value).
#   ./measure_sizes.sh <label> [results_dir]
# label examples: baseline, users-1k, users-10k, after-password-grant, ...
set -euo pipefail
label=$1
out=${2:-.}
file="$out/sizes.txt"
mkdir -p "$out"

pg_issuerd() { docker exec issuerd-perf-postgres-issuerd psql -U issuerd -d issuerd -t -A -c "$1" 2>/dev/null || echo ""; }
pg_kc() { docker exec issuerd-perf-postgres-kc psql -U keycloak -d keycloak -t -A -c "$1" 2>/dev/null || echo ""; }

{
  echo "--- label=$label ts=$(date -Is)"
  echo "issuerd_pg_database_bytes=$(pg_issuerd "SELECT pg_database_size('issuerd')")"
  echo "issuerd_users_count=$(pg_issuerd "SELECT count(*) FROM users")"
  echo "issuerd_credentials_count=$(pg_issuerd "SELECT count(*) FROM credentials")"
  echo "issuerd_user_sessions_count=$(pg_issuerd "SELECT count(*) FROM user_sessions")"
  echo "issuerd_client_sessions_count=$(pg_issuerd "SELECT count(*) FROM client_sessions")"
  echo "issuerd_events_count=$(pg_issuerd "SELECT count(*) FROM events")"
  echo "issuerd_admin_events_count=$(pg_issuerd "SELECT count(*) FROM admin_events")"
  # pg_total_relation_size per table that grows
  pg_issuerd "SELECT 'issuerd_tbl_'||relname||'_bytes='||pg_total_relation_size(relid) FROM pg_stat_user_tables WHERE relname IN ('users','credentials','user_sessions','client_sessions','events','admin_events') ORDER BY 1" || true
  echo "issuerd_logs_bytes=$(docker logs issuerd-perf-issuerd 2>&1 | wc -c | tr -d ' ')"
  echo "kc_pg_database_bytes=$(pg_kc "SELECT pg_database_size('keycloak')")"
  echo "kc_logs_bytes=$(docker logs issuerd-perf-keycloak 2>&1 | wc -c | tr -d ' ')"
  # Image sizes (bytes, exact). NOTE: with Docker Desktop's containerd image
  # store, inspect .Size is the COMPRESSED content size (what a pull transfers),
  # not the uncompressed on-disk usage (`docker images` DISK USAGE column).
  docker image inspect issuerd:perf --format 'image_issuerd_bytes={{.Size}}' 2>/dev/null || true
  docker image inspect keycloak-optimized:26.7.4 --format 'image_keycloak_bytes={{.Size}}' 2>/dev/null || true
} >> "$file"
echo "sizes appended to $file (label=$label)"
