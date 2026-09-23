#!/usr/bin/env bash
# Full conformance run, executed INSIDE the isolated network by the
# one-shot `conformance-run` compose service:
#   TLS/CA checks -> isolation check -> bootstrap -> three test plans via
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
    local plan="$1" config="$2" skips="$3" logname="$4"
    echo ""
    echo "=========================================="
    echo "Running: $plan"
    echo "=========================================="
    python3 /upstream-scripts/run-test-plan.py \
        --expected-failures-file "$CONFIGS/issuerd-expected-failures.json" \
        --expected-skips-file "$CONFIGS/$skips" \
        --export-dir /results/export-json \
        "$plan" \
        "$CONFIGS/$config" \
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
