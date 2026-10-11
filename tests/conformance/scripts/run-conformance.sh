#!/usr/bin/env bash
# Full conformance run, executed INSIDE the isolated network by the
# one-shot `conformance-run` compose service:
#   TLS/CA checks -> isolation check -> bootstrap -> all test plans via
#   the pristine upstream run-test-plan.py -> JSON + HTML reports.
# Exit code 0 only when every plan finished without unexpected failures.
set -uo pipefail

CACERT=/pki/ca.crt
SUITE=https://suite.conformance.test:8443
OP=https://op.conformance.test:8443
CONFIGS=/conformance-suite-configs
OVERALL_RESULT=0

echo "=== Verifying TLS endpoints (CA trust) ==="
curl -sf --cacert "$CACERT" "$SUITE/" -o /dev/null
echo "suite ready at $SUITE"
curl -sf --cacert "$CACERT" "$OP/health/ready" -o /dev/null
echo "op ready at $OP"

echo "=== Verifying network isolation ==="
# Real external names must still be refused by bind9. (The handful of CDN
# hostnames mirrored by the cdn-shim container resolve by design — see
# dns/named.conf — and are asserted separately below.)
if getent hosts example.com >/dev/null 2>&1; then
    echo "ERROR: external DNS name resolved inside the isolated network!"
    exit 1
fi
echo "Isolation OK: external names are refused by bind9"

echo "=== Verifying CDN shim ==="
for host in cdn.jsdelivr.net cdnjs.cloudflare.com cdn.datatables.net \
            fonts.googleapis.com fonts.gstatic.com oss.maxcdn.com; do
    if ! getent hosts "$host" | grep -q "172.31.0.15"; then
        echo "ERROR: $host does not resolve to the cdn-shim (172.31.0.15)!"
        exit 1
    fi
done
curl -sf --cacert "$CACERT" \
    https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js -o /dev/null
echo "CDN shim OK: suite web UI assets answer locally over trusted TLS"

mkdir -p /results/export-json /results/exports

echo "=== Bootstrapping Issuerd realm ==="
ISSUERD_URL="$OP" ISSUERD_CACERT="$CACERT" bash /usr/local/bin/issuerd-bootstrap

run_plan() {
    local plan="$1" config="$2" skips="$3" logname="$4" expected="${5:-issuerd-expected-failures.json}"
    # Absolute config paths (rendered configs under /tmp) pass through;
    # relative ones resolve in the mounted configs directory.
    local config_path="$config"
    if [[ "$config" != /* ]]; then
        config_path="$CONFIGS/$config"
    fi
    echo ""
    echo "=========================================="
    echo "Running: $plan"
    echo "=========================================="
    python3 /upstream-scripts/run-test-plan.py \
        --expected-failures-file "$CONFIGS/$expected" \
        --expected-skips-file "$CONFIGS/$skips" \
        --export-dir /results/export-json \
        "$plan" \
        "$config_path" \
        2>&1 | tee "/results/$logname" || OVERALL_RESULT=1
}

run_plan \
    "oidcc-config-certification-test-plan" \
    "issuerd-config-op.json" \
    "issuerd-expected-skips-config.json" \
    "oidcc-config-certification-test-plan-output.log"

run_plan \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-basic-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-basic-certification-test-plan-output.log"

run_plan \
    "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-formpost-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-formpost-basic-certification-test-plan-output.log"

# Implicit / Hybrid OP (M2): one run each covers all of the plan's response
# types. Form Post legs mirror them with response_mode pinned by the plan.
run_plan \
    "oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-implicit-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-implicit-certification-test-plan-output.log"

run_plan \
    "oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-hybrid-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-hybrid-certification-test-plan-output.log"

run_plan \
    "oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-formpost-implicit-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-formpost-implicit-certification-test-plan-output.log"

run_plan \
    "oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
    "issuerd-formpost-hybrid-op.json" \
    "issuerd-expected-skips.json" \
    "oidcc-formpost-hybrid-certification-test-plan-output.log"

# Logout profiles (M2 gate): the plans pin server_metadata=discovery /
# client_auth_type / response_mode; client_registration and response_type are
# user-selected. Static clients carry the logout URIs from bootstrap. Each
# plan runs once per response type.
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=$rt]" \
        "issuerd-rpinitiated-logout-op.json" \
        "issuerd-expected-skips-config.json" \
        "oidcc-rp-initiated-logout-certification-test-plan-${rt// /-}-output.log"
done
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-frontchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=$rt]" \
        "issuerd-frontchannel-logout-op.json" \
        "issuerd-expected-skips-config.json" \
        "oidcc-frontchannel-rp-initiated-logout-certification-test-plan-${rt// /-}-output.log"
done
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=$rt]" \
        "issuerd-backchannel-logout-op.json" \
        "issuerd-expected-skips-config.json" \
        "oidcc-backchannel-rp-initiated-logout-certification-test-plan-${rt// /-}-output.log" \
        "issuerd-expected-warnings-backchannel.json"
done

# Session Management OP (M3): session_state + check_session_iframe. Runs on
# the RP-initiated logout's static client (post_logout_redirect_uris, no
# front/back-channel URIs) — the module does the iframe postMessage dance
# against the OP's check_session_iframe from the suite's own page.
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-session-management-certification-test-plan[client_registration=static_client][response_type=$rt]" \
        "issuerd-session-op.json" \
        "issuerd-expected-skips-config.json" \
        "oidcc-session-management-certification-test-plan-${rt// /-}-output.log"
done

# 3rd-Party-Init OP: the plan pins server_metadata=discovery,
# client_registration=dynamic_client, client_auth_type=client_secret_basic and
# response_mode=default itself (passing them on the command line is an
# error) — only response_type is user-selected, and it is never exercised by
# the two modules. Registrations flow through the initial-access-token-gated
# endpoint; bootstrap minted an unlimited, non-expiring token into /results.
# Six runs × 2 modules = the published 12.
THIRDPARTY_CONFIG=/tmp/issuerd-3rdparty-init-op.json
sed "s/@INITIAL_ACCESS_TOKEN@/$(cat /results/initial-access-token.txt)/" \
    "$CONFIGS/issuerd-3rdparty-init-op.json" > "$THIRDPARTY_CONFIG"
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-3rdparty-init-login-certification-test-plan[response_type=$rt]" \
        "$THIRDPARTY_CONFIG" \
        "issuerd-expected-skips-config.json" \
        "oidcc-3rdparty-init-login-certification-test-plan-${rt// /-}-output.log"
done

# Dynamic OP (M4): the plan pins discovery + dynamic_client + private_key_jwt;
# only response_type is user-selected. Each run registers its clients via DCR
# with the bootstrap-minted initial access token. oidcc-server-rotate-keys is
# an expected failure in-plan (operator-step module; real rotation evidence is
# produced by scripts/run-rotation-check.sh).
DYNAMIC_CONFIG=/tmp/issuerd-dynamic-op.json
sed "s/@INITIAL_ACCESS_TOKEN@/$(cat /results/initial-access-token.txt)/" \
    "$CONFIGS/issuerd-dynamic-op.json" > "$DYNAMIC_CONFIG"
for rt in "code" "code id_token" "code id_token token" "code token" "id_token" "id_token token"; do
    run_plan \
        "oidcc-dynamic-certification-test-plan[response_type=$rt]" \
        "$DYNAMIC_CONFIG" \
        "issuerd-expected-skips-dynamic.json" \
        "oidcc-dynamic-certification-test-plan-${rt// /-}-output.log" \
        "issuerd-expected-failures-dynamic.json"
done

echo ""
echo "=== Exporting HTML reports ==="
python3 /harness-scripts/export-html.py /results/exports || true

echo ""
echo "=========================================="
if [[ "$OVERALL_RESULT" == "0" ]]; then
    echo "Conformance test run complete: all plans OK"
else
    echo "Conformance test run complete: UNEXPECTED FAILURES (see logs in results/)"
fi
echo "Results directory: /results"
echo "=========================================="
exit "$OVERALL_RESULT"
