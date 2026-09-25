#!/usr/bin/env python3
"""Build shields.io endpoint-badge JSONs from coverage exports.

Reads:
  - cargo llvm-cov `--lcov` export (Rust workspace unit tests)
  - Vitest `json-summary` report (webclientsrc/coverage/coverage-summary.json)

Writes shields.io endpoint JSONs ({"schemaVersion": 1, ...}) that CI publishes
to the `badges` branch; the README badges point at raw.githubusercontent.com
URLs for those files.

Usage:
    python scripts/coverage_badges.py \
        --rust rust-lcov.info \
        --webclient webclientsrc/coverage/coverage-summary.json \
        --outdir badges
"""

import argparse
import json
import os
import sys


def color_for(pct: float) -> str:
    if pct >= 90:
        return 'brightgreen'
    if pct >= 80:
        return 'green'
    if pct >= 70:
        return 'yellowgreen'
    if pct >= 60:
        return 'yellow'
    if pct >= 50:
        return 'orange'
    return 'red'


def rust_line_percent(path: str) -> float:
    """Sum LF/LH (lines found/hit) records of a cargo-llvm-cov lcov export."""
    found = hit = 0
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('LF:'):
                found += int(line[3:])
            elif line.startswith('LH:'):
                hit += int(line[3:])
    if found == 0:
        raise ValueError(f'no line records in {path}')
    return hit / found * 100


def webclient_line_percent(path: str) -> float:
    """Read total line coverage from a Vitest json-summary report."""
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    lines = data['total']['lines']
    if not lines['total']:
        raise ValueError(f'no line records in {path}')
    return float(lines['pct'])


def badge(label: str, pct: float) -> dict:
    return {
        'schemaVersion': 1,
        'label': label,
        'message': f'{pct:.1f}%',
        'color': color_for(pct),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', required=True, help='cargo llvm-cov --lcov export')
    parser.add_argument('--webclient', required=True, help='Vitest coverage-summary.json')
    parser.add_argument('--outdir', required=True, help='output directory for badge JSONs')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    results = {
        'rust': ('coverage: rust', rust_line_percent(args.rust)),
        'webclient': ('coverage: webclient', webclient_line_percent(args.webclient)),
    }
    for name, (label, pct) in results.items():
        out = os.path.join(args.outdir, f'{name}.json')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(badge(label, pct), f, indent=2)
            f.write('\n')
        print(f'{out}: {label} {pct:.1f}% ({color_for(pct)})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
