#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Generate the PERFORMANCE.md charts from tests/perf results.

Reads:
  results/<run>/<scenario>_<target>_<tier>.json      k6 summary exports
  results/<run>/stats_<scenario>_<target>_<tier>.jsonl   docker stats samples
  results/<run>/sizes.txt                            disk/log measurements
  results/<run>/idle_<target>.jsonl                  idle footprints

Writes PNG charts to docs/images/perf/.

Usage: python scripts/charts.py [results_dir ...]
  With multiple results dirs, later dirs override earlier ones for the same
  (scenario, target, tier) triple — i.e. pass runs chronologically.
"""
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

PERF_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PERF_DIR.parent.parent
OUT_DIR = REPO_ROOT / "docs" / "images" / "perf"

SCENARIOS_BOTH = [
    "discovery",
    "client_credentials",
    "password_grant",
    "userinfo",
    "introspect",
    "auth_code_flow",
    "admin_users",
]
# Agentic workloads run on both targets since the Keycloak 26.7 upgrade
# (DPoP is supported since KC 26.4, CIBA long before); they are charted
# separately because their request shapes are not 1:1 across servers
# (issuerd CIBA = auth+approve+poll, Keycloak CIBA = auth+poll with the
# ad-simulator approving inside the auth call).
SCENARIOS_AGENTIC = ["dpop", "ciba"]
TIERS = ["small", "medium", "large"]

ISSUERD_COLOR = "#b7410e"  # rust
KC_COLOR = "#4d6f9e"  # keycloak blue-ish

TIER_LIMITS = {"small": "1 CPU / 512 MiB", "medium": "2 CPU / 1 GiB", "large": "4 CPU / 2 GiB"}

# admin_users re-runs on small/large tiers reuse the {vu}-{iter} name space of
# the medium run on the same database, so most requests are 409-conflict skips
# (http_req_failed up to 1.0 while the scenario's own `errors` rate stays 0).
# Only the medium tier ran against a fresh user namespace for both servers, so
# only medium-tier admin_users data is a clean creation-rate measurement.
TIER_CHART_EXCLUDE = {("admin_users", "small"), ("admin_users", "large")}


def collect(results_dirs):
    """scenario -> target -> tier -> summary dict"""
    data = {}
    stats = {}
    sizes_blocks = []
    idle = {}
    for rd in results_dirs:
        rd = Path(rd)
        for f in sorted(rd.glob("*.json")):
            m = re.match(r"(.+)_(issuerd|keycloak)_(small|medium|large|seed)\.json$", f.name)
            if not m:
                continue
            scen, tgt, tier = m.groups()
            try:
                data.setdefault(scen, {}).setdefault(tgt, {})[tier] = json.loads(f.read_text())
            except Exception as e:
                print(f"skip {f}: {e}")
        for f in sorted(rd.glob("stats_*.jsonl")):
            m = re.match(r"stats_(.+)_(issuerd|keycloak)_(small|medium|large)\.jsonl$", f.name)
            if not m:
                continue
            scen, tgt, tier = m.groups()
            stats[(scen, tgt, tier)] = f
        for f in sorted(rd.glob("idle_*.jsonl")):
            m = re.match(r"idle_(issuerd|keycloak)\.jsonl$", f.name)
            if m:
                idle[m.group(1)] = f
        sf = rd / "sizes.txt"
        if sf.exists():
            sizes_blocks.append(sf)
    return data, stats, sizes_blocks, idle


def metric(summary, name, field):
    try:
        return summary["metrics"][name]["values"][field]
    except KeyError:
        return None


def rps(summary):
    return metric(summary, "http_reqs", "rate")


def ips(summary):
    """Iterations per second — one iteration is one full scenario cycle (for
    CIBA: bc-auth → approve → poll), the honest throughput unit when the two
    targets issue a different number of HTTP requests per cycle."""
    return metric(summary, "iterations", "rate")


def p99(summary):
    return metric(summary, "http_req_duration", "p(99)")


def p95(summary):
    return metric(summary, "http_req_duration", "p(95)")


def chart_throughput(data, tier="medium"):
    scen = [s for s in SCENARIOS_BOTH if s in data and (s, tier) not in TIER_CHART_EXCLUDE]
    issuerd = [rps(data[s].get("issuerd", {}).get(tier, {})) or 0 for s in scen]
    kc = [rps(data[s].get("keycloak", {}).get(tier, {})) or 0 for s in scen]
    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(scen))
    ax.bar([i - 0.2 for i in x], issuerd, width=0.4, label="Issuerd", color=ISSUERD_COLOR)
    ax.bar([i + 0.2 for i in x], kc, width=0.4, label="Keycloak 26.7", color=KC_COLOR)
    for i, v in enumerate(issuerd):
        ax.text(i - 0.2, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=8)
    for i, v in enumerate(kc):
        ax.text(i + 0.2, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(list(x), scen, rotation=20, ha="right")
    ax.set_ylabel("requests / second")
    ax.set_title(f"Throughput by scenario ({tier} tier: {TIER_LIMITS[tier]} app container)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT_DIR / f"throughput_vs_keycloak_{tier}.png", dpi=150)
    plt.close(fig)


def chart_p99(data, tier="medium"):
    scen = [s for s in SCENARIOS_BOTH if s in data and (s, tier) not in TIER_CHART_EXCLUDE]
    issuerd = [p99(data[s].get("issuerd", {}).get(tier, {})) or 0 for s in scen]
    kc = [p99(data[s].get("keycloak", {}).get(tier, {})) or 0 for s in scen]
    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(scen))
    ax.bar([i - 0.2 for i in x], issuerd, width=0.4, label="Issuerd", color=ISSUERD_COLOR)
    ax.bar([i + 0.2 for i in x], kc, width=0.4, label="Keycloak 26.7", color=KC_COLOR)
    for i, v in enumerate(issuerd):
        ax.text(i - 0.2, v, f"{v:,.1f}", ha="center", va="bottom", fontsize=8)
    for i, v in enumerate(kc):
        ax.text(i + 0.2, v, f"{v:,.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(list(x), scen, rotation=20, ha="right")
    ax.set_ylabel("p99 latency (ms)")
    ax.set_title(f"p99 latency by scenario ({tier} tier: {TIER_LIMITS[tier]} app container)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT_DIR / f"p99_vs_keycloak_{tier}.png", dpi=150)
    plt.close(fig)


def chart_scaling(data):
    fig, ax = plt.subplots(figsize=(9, 5))
    for scen in ["client_credentials", "userinfo", "password_grant", "discovery"]:
        vals = []
        for tier in TIERS:
            s = data.get(scen, {}).get("issuerd", {}).get(tier)
            vals.append(rps(s) if s else None)
        if any(v is not None for v in vals):
            ax.plot(TIERS, vals, marker="o", label=scen)
    ax.set_ylabel("requests / second")
    ax.set_title("Issuerd throughput vs container CPU/memory tier")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "issuerd_scaling.png", dpi=150)
    plt.close(fig)


def parse_mem_bytes(s):
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B)", s)
    if not m:
        return None
    v = float(m.group(1))
    unit = m.group(2)
    mult = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
            "KB": 1000, "MB": 1000**2, "GB": 1000**3}.get(unit, 1)
    return v * mult


def load_stats(path):
    """container -> (peak_cpu_pct, peak_mem_bytes, avg_mem_bytes)"""
    agg = {}
    for line in Path(path).read_text().splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = j.get("Name") or j.get("name") or ""
        cpu = float((j.get("CPUPerc") or "0").rstrip("%") or 0)
        mem = parse_mem_bytes((j.get("MemUsage") or "0").split("/")[0].strip()) or 0
        a = agg.setdefault(name, {"peak_cpu": 0.0, "peak_mem": 0, "mems": []})
        a["peak_cpu"] = max(a["peak_cpu"], cpu)
        a["peak_mem"] = max(a["peak_mem"], mem)
        a["mems"].append(mem)
    return {
        k: (v["peak_cpu"], v["peak_mem"], sum(v["mems"]) / len(v["mems"]) if v["mems"] else 0)
        for k, v in agg.items()
    }


def chart_memory(stats):
    # peak app-container memory per (scenario,target,tier=medium)
    rows = []
    for (scen, tgt, tier), f in sorted(stats.items()):
        if tier != "medium":
            continue
        s = load_stats(f)
        app = "issuerd-perf-issuerd" if tgt == "issuerd" else "issuerd-perf-keycloak"
        if app in s:
            rows.append((scen, tgt, s[app][1] / (1 << 20)))
    scen_order = []
    for r in rows:
        if r[0] not in scen_order:
            scen_order.append(r[0])
    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(scen_order))
    for idx, tgt in enumerate(["issuerd", "keycloak"]):
        vals = [next((m for s, tg, m in rows if s == scen and tg == tgt), 0) for scen in scen_order]
        ax.bar(
            [i - 0.2 + idx * 0.4 for i in x],
            vals,
            width=0.4,
            label="Issuerd" if tgt == "issuerd" else "Keycloak 26.7",
            color=ISSUERD_COLOR if tgt == "issuerd" else KC_COLOR,
        )
    ax.set_xticks(list(x), scen_order, rotation=20, ha="right")
    ax.set_ylabel("peak memory (MiB)")
    ax.set_title("Peak app-container memory under load (medium tier, 1 GiB limit)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT_DIR / "memory_medium.png", dpi=150)
    plt.close(fig)


def parse_sizes(blocks):
    """label -> dict of key=value ints"""
    out = {}
    for f in blocks:
        label = None
        for line in Path(f).read_text().splitlines():
            line = line.strip()
            if line.startswith("---"):
                m = re.search(r"label=(\S+)", line)
                label = m.group(1) if m else None
                continue
            m = re.match(r"([a-z_0-9]+)=(\d+)$", line)
            if m and label:
                out.setdefault(label, {})[m.group(1)] = int(m.group(2))
    return out


def chart_disk(sizes):
    # Panel A: steady-state per-user cost — users + credentials table bytes
    # against the actual stored user count at each measurement point. These two
    # tables grow only with user count, so the series is monotone regardless of
    # how many sessions/events the campaign happened to accumulate.
    # Panel B: whole-database size before/after wiping transient rows at the
    # 100k-user point (sessions, events, admin_events) — shows how much of the
    # raw size is login churn vs steady-state user data.
    per_user_labels = ["baseline", "users-1k", "after-medium", "users-10k", "users-100k"]
    pts = []
    for lbl in per_user_labels:
        blk = sizes.get(lbl)
        if blk and "issuerd_users_count" in blk:
            tbl = blk.get("issuerd_tbl_users_bytes", 0) + blk.get("issuerd_tbl_credentials_bytes", 0)
            pts.append((blk["issuerd_users_count"], tbl / (1 << 20)))
    raw = sizes.get("users-100k-raw", {})
    raw_bytes = raw.get("issuerd_pg_database_bytes")
    clean = sizes.get("users-100k", {}).get("issuerd_pg_database_bytes")
    if len(pts) < 2 and not (raw_bytes and clean):
        return
    fig, (axa, axb) = plt.subplots(1, 2, figsize=(11, 4.5))
    if len(pts) >= 2:
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        axa.plot(xs, ys, marker="o", color=ISSUERD_COLOR)
        for x, y in pts:
            axa.annotate(f"{y:,.1f}", (x, y), textcoords="offset points", xytext=(0, 8),
                         ha="center", fontsize=8)
        axa.set_xscale("symlog")
        axa.set_ylabel("users + credentials tables (MiB)")
        axa.set_xlabel("stored users (log scale)")
        axa.set_title("Steady-state disk per user")
        axa.grid(True, alpha=0.3)
    if raw_bytes and clean:
        n_users = sizes.get("users-100k", {}).get("issuerd_users_count", 0)
        n_sess = raw.get("issuerd_user_sessions_count", 0)
        n_events = raw.get("issuerd_events_count", 0) + raw.get("issuerd_admin_events_count", 0)
        bars = axb.bar(
            [f"with sessions+events\n({n_sess / 1000:,.1f}k sessions, {n_events / 1000:,.0f}k events)",
             "steady state\n(users only)"],
            [raw_bytes / (1 << 20), clean / (1 << 20)],
            color=[KC_COLOR, ISSUERD_COLOR],
        )
        for b, v in zip(bars, [raw_bytes / (1 << 20), clean / (1 << 20)]):
            axb.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f} MiB", ha="center", va="bottom")
        axb.set_ylabel("whole PostgreSQL database (MiB)")
        axb.set_title(f"{n_users:,} users: churn vs steady state")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "disk_users.png", dpi=150)
    plt.close(fig)


def chart_agentic(data, tier="medium"):
    scen = [s for s in SCENARIOS_AGENTIC if s in data]
    if not scen:
        return
    issuerd_ips = [ips(data[s].get("issuerd", {}).get(tier, {})) or 0 for s in scen]
    kc_ips = [ips(data[s].get("keycloak", {}).get(tier, {})) or 0 for s in scen]
    issuerd_p99 = [p99(data[s].get("issuerd", {}).get(tier, {})) or 0 for s in scen]
    kc_p99 = [p99(data[s].get("keycloak", {}).get(tier, {})) or 0 for s in scen]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4.5))
    x = range(len(scen))
    for ax, ic_vals, kc_vals, ylabel, title, fmt in [
        (ax1, issuerd_ips, kc_ips, "cycles / second", "throughput", "{:,.1f}"),
        (ax2, issuerd_p99, kc_p99, "p99 (ms)", "p99 latency", "{:,.1f}"),
    ]:
        ax.bar([i - 0.2 for i in x], ic_vals, width=0.4, label="Issuerd", color=ISSUERD_COLOR)
        ax.bar([i + 0.2 for i in x], kc_vals, width=0.4, label="Keycloak 26.7", color=KC_COLOR)
        for i, v in enumerate(ic_vals):
            ax.text(i - 0.2, v, fmt.format(v), ha="center", va="bottom", fontsize=8)
        for i, v in enumerate(kc_vals):
            ax.text(i + 0.2, v, fmt.format(v), ha="center", va="bottom", fontsize=8)
        ax.set_xticks(list(x), scen)
        ax.set_ylabel(ylabel)
        ax.set_title(f"Agentic workloads — {title}")
        ax.legend()
    fig.suptitle(f"DPoP / CIBA ({tier} tier)")
    fig.tight_layout()
    fig.savefig(OUT_DIR / f"agentic_{tier}.png", dpi=150)
    plt.close(fig)


def chart_image_size(sizes):
    for lbl, blk in sizes.items():
        if "image_issuerd_bytes" in blk and "image_keycloak_bytes" in blk:
            fig, ax = plt.subplots(figsize=(6, 4))
            vals = [blk["image_issuerd_bytes"] / (1 << 20), blk["image_keycloak_bytes"] / (1 << 20)]
            bars = ax.bar(["Issuerd\n(distroless)", "Keycloak 26.7"], vals, color=[ISSUERD_COLOR, KC_COLOR])
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f} MiB", ha="center", va="bottom")
            ax.set_ylabel("image size (MiB, compressed pull size)")
            ax.set_title("Container image footprint")
            fig.tight_layout()
            fig.savefig(OUT_DIR / "image_size.png", dpi=150)
            plt.close(fig)
            return


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results_dirs = sys.argv[1:] or [str(PERF_DIR / "results")]
    # flatten: a dir containing run subdirs expands to those; a dir with its
    # own *.json/sizes.txt is used directly. When expanding, skip the parent
    # itself so stray probe files at the root never shadow run data.
    dirs = []
    for d in results_dirs:
        p = Path(d)
        sub_runs = sorted(
            x for x in p.iterdir() if x.is_dir() and (list(x.glob("*.json")) or (x / "sizes.txt").exists())
        )
        if sub_runs:
            dirs.extend(sub_runs)
        elif (p / "sizes.txt").exists() or list(p.glob("*.json")):
            dirs.append(p)
    data, stats, sizes_blocks, idle = collect(dirs)
    print(f"collected scenarios: {sorted(data)} from {len(dirs)} run dir(s)")
    sizes = parse_sizes(sizes_blocks)

    for tier in TIERS:
        if any(tier in data.get(s, {}).get("issuerd", {}) or tier in data.get(s, {}).get("keycloak", {}) for s in SCENARIOS_BOTH):
            chart_throughput(data, tier)
            chart_p99(data, tier)
    chart_scaling(data)
    chart_memory(stats)
    chart_disk(sizes)
    chart_image_size(sizes)
    for tier in TIERS:
        chart_agentic(data, tier)

    # machine-readable digest for the doc-writing step
    digest = {"scenarios": {}, "stats": {}, "sizes": sizes, "idle": {}}
    for scen, by_t in data.items():
        digest["scenarios"][scen] = {}
        for tgt, by_tier in by_t.items():
            digest["scenarios"][scen][tgt] = {
                tier: {
                    "rps": rps(s),
                    "p50": metric(s, "http_req_duration", "med"),
                    "p95": p95(s),
                    "p99": p99(s),
                    "max": metric(s, "http_req_duration", "max"),
                    "iters": metric(s, "iterations", "count"),
                    "reqs": metric(s, "http_reqs", "count"),
                    "duration_s": round(s.get("state", {}).get("testRunDurationMs", 0) / 1000, 1),
                    # `errors` is the scenario's own counter (409-skips in
                    # admin_users seed mode are not errors); http_req_failed is
                    # k6's raw non-2xx/3xx rate. Report both — they diverge on
                    # idempotent-retry-heavy runs.
                    "error_rate": metric(s, "errors", "rate"),
                    "http_req_failed": metric(s, "http_req_failed", "rate"),
                }
                for tier, s in by_tier.items()
            }
    for (scen, tgt, tier), f in sorted(stats.items()):
        for container, (peak_cpu, peak_mem, avg_mem) in load_stats(f).items():
            digest["stats"][f"{scen}|{tgt}|{tier}|{container}"] = {
                "peak_cpu_pct": round(peak_cpu, 1),
                "peak_mem_mib": round(peak_mem / (1 << 20), 1),
                "avg_mem_mib": round(avg_mem / (1 << 20), 1),
            }
    for tgt, f in idle.items():
        for container, (peak_cpu, peak_mem, avg_mem) in load_stats(f).items():
            digest["idle"][container] = {
                "cpu_pct": round(peak_cpu, 2),
                "mem_mib": round(peak_mem / (1 << 20), 1),
            }
    (PERF_DIR / "results" / "digest.json").write_text(json.dumps(digest, indent=2))
    print(f"digest -> {PERF_DIR / 'results' / 'digest.json'}")
    print(f"charts -> {OUT_DIR}")


if __name__ == "__main__":
    main()
