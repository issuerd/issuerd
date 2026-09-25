#!/usr/bin/env python3
"""Download exporthtml zips for every test plan in the conformance suite DB
and extract them into a dated html-reports directory with an index page.

Harness-side helper used by the conformance-run compose service. It only
talks to the suite's public REST API; the upstream runner scripts stay
byte-pristine (they export JSON via --export-dir, which the run also keeps).

Usage: export-html.py [export-dir]
Environment: CONFORMANCE_SERVER (default https://suite.conformance.test:8443)
"""
import os
import re
import sys
import time
import zipfile

import httpx

INDEX_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Issuerd OIDC Conformance Test Reports</title>
    <style>
        body {{ font-family: sans-serif; line-height: 1.5em; padding: 2em 3em; max-width: 900px; margin: 0 auto; }}
        h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.3em; }}
        .plan-link {{ display: block; padding: 1em; margin: 0.5em 0; background: #f5f5f5; border-radius: 6px; text-decoration: none; color: #333; border-left: 4px solid #007acc; }}
        .plan-link:hover {{ background: #e8f4ff; }}
        .plan-title {{ font-size: 1.2em; font-weight: bold; }}
        .plan-desc {{ color: #666; margin-top: 0.3em; }}
        .timestamp {{ color: #888; font-size: 0.9em; margin-top: 1em; }}
    </style>
</head>
<body>
    <h1>Issuerd OIDC Conformance Test Reports</h1>
    <p class="timestamp">Generated: {generated}</p>
    <h2>Test Plans</h2>
{links}
</body></html>
"""

PLAN_TITLES = [
    ("config-certification", "Config OP Test Plan",
     "oidcc-config-certification-test-plan — Discovery metadata &amp; JWKS validation"),
    ("formpost-basic-certification", "Form Post OP Test Plan",
     "oidcc-formpost-basic-certification-test-plan — Authorization code flow via form_post"),
    ("basic-certification", "Basic OP Test Plan",
     "oidcc-basic-certification-test-plan — Authorization code flow"),
]


def plan_title(dirname):
    for needle, title, desc in PLAN_TITLES:
        if needle in dirname:
            return title, desc
    return dirname, "Conformance test plan"


def main():
    base = os.environ.get("CONFORMANCE_SERVER", "https://suite.conformance.test:8443")
    if not base.endswith("/"):
        base += "/"
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/results/exports"
    os.makedirs(out_dir, exist_ok=True)

    # Dev-mode deployment: no API token; the suite is reachable only inside
    # the isolated network, so certificate verification is off here as well
    # (same as the upstream runner's CONFORMANCE_DEV_MODE behaviour).
    client = httpx.Client(verify=False, timeout=180)

    plans = client.get(base + "api/plan", params={"length": 100}).json()
    items = plans.get("data", plans) if isinstance(plans, dict) else plans

    zips = []
    for plan in items:
        plan_id = plan.get("_id") or plan.get("id")
        name = plan.get("planName", "plan")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
        filename = os.path.join(out_dir, "{}-{}.zip".format(safe_name, plan_id))
        with client.stream("GET", base + "api/plan/exporthtml/{}".format(plan_id)) as response:
            response.raise_for_status()
            with open(filename, "wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
        print("exported HTML report: {}".format(filename))
        zips.append(filename)

    if not zips:
        print("no plans found, nothing to extract")
        return

    # Extract into a dated folder with a top-level index.html
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    reports_dir = os.path.join(os.path.dirname(out_dir.rstrip("/")) or "/",
                               "html-reports-" + timestamp)
    links = []
    for zip_path in zips:
        dirname = os.path.splitext(os.path.basename(zip_path))[0]
        target = os.path.join(reports_dir, dirname)
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(target)
        title, desc = plan_title(dirname)
        links.append('    <a class="plan-link" href="{}/index.html">'
                     '<div class="plan-title">{}</div>'
                     '<div class="plan-desc">{}</div></a>'.format(dirname, title, desc))
        print("extracted: {}".format(target))

    with open(os.path.join(reports_dir, "index.html"), "w") as handle:
        handle.write(INDEX_PAGE.format(
            generated=time.strftime("%Y-%m-%d %H:%M:%S"),
            links="\n".join(links)))
    print("HTML reports extracted to: {}".format(reports_dir))


if __name__ == "__main__":
    main()
