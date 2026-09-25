#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sample `docker stats` for the given containers every SAMPLE_EVERY seconds and
# append JSON-lines with an epoch timestamp to the output file.
# Host-side script (Git Bash / Linux) — docker stats talks to the local daemon.
#
#   ./stats_sampler.sh <outfile.jsonl> <container> [container...]
# Stop with SIGTERM/SIGINT (run.sh backgrounds and kills it per scenario).
set -u
out=$1; shift
every="${SAMPLE_EVERY:-2}"
while true; do
  ts=$(date +%s)
  docker stats --no-stream --format '{{json .}}' "$@" 2>/dev/null \
    | sed "s/^{/{\"ts\":${ts},/" >> "$out"
  sleep "$every"
done
