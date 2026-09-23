# Optimized production build of Keycloak 26 for the benchmark stack.
#
# This is the documented production container shape: build-time options are
# baked into the image with `kc.sh build`, and the container then runs
# `start --optimized`, which refuses any boot-time re-augmentation. The perf
# rig previously used `start-dev` (the quickstart mode); benchmarks comparing
# against Keycloak must run the production build so the comparison is against
# Keycloak's production runtime, not its developer mode.
#
# Build-time options baked here (KC 26 treats them as build options — setting
# them at runtime under `start --optimized` errors on mismatch):
#   KC_DB=postgres          database vendor (runtime DSN stays a runtime flag)
#   KC_HEALTH_ENABLED=true  /health/ready on the management interface :9000
#                           (since KC 25 health/metrics moved off the main
#                           port; the compose healthcheck probes :9000)
#   KC_METRICS_ENABLED=true parity with the previous start-dev stack
#
# DPoP and CIBA are supported features since KC 26.4 / long before — both are
# enabled by default in 26.7, so no --features build option is needed.
#
# Build (from tests/perf/):
#   docker compose -f docker-compose.perf.yml build keycloak
# (needs the local keycloak/keycloak:26.7.4 base image; no network at runtime)
FROM keycloak/keycloak:26.7.4 AS builder

ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true

RUN /opt/keycloak/bin/kc.sh build

FROM keycloak/keycloak:26.7.4

COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
