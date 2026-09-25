#!/usr/bin/env python3
"""Stage and (dry-run) publish the Issuerd workspace crates to crates.io.

Why staging exists: issuerd-core depends on the `flux-rs` proc-macro shim via a
git dependency (see crates/issuerd-core/Cargo.toml), and crates.io rejects any
crate whose manifest references a git dependency. The shim expands to nothing
in normal builds, so the staged copy drops that dependency together with the
`#[flux_rs::...]` attribute lines it enables; the compiled crate is identical.

Steps:
  1. Copy the publishable file set into a temp staging dir (manifests, sources,
     migrations, build scripts, README/LICENSE, root bin + integration tests).
  2. Copy the built web client (webclientsrc/dist) into the staged issuerd-server
     crate as webclient-dist/ so the packaged crate can embed the SPA.
  3. Strip the flux-rs git dependency from the staged issuerd-core manifest and
     the `#[flux_rs::...]` attribute lines from its models.rs.
  4. Run `cargo publish` per crate in dependency order.

Usage:
  python scripts/publish.py                       # dry-run (default, no upload)
  python scripts/publish.py --real                # real publish, pauses between crates
  python scripts/publish.py --real --skip-root    # libraries only, no root binary crate

Auth: set CARGO_REGISTRY_TOKEN (CRATES_TOKEN is accepted as an alias) or run
`cargo login` beforehand. Published versions are immutable — crates.io only
allows yanking, never deleting. New-crate creation is rate-limited on fresh
accounts, so --real pauses between crates (override with --pause SECONDS).
After each upload --real also polls the sparse index until the new version is
actually visible (override the cap with --index-timeout SECONDS): the index
lags the upload by a minute or more, and the next crate's dependency
resolution 404s without it. Interrupted runs are resumable (already-uploaded
crates are skipped).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Dependency order: each crate only depends on crates listed before it.
CRATES = [
    "issuerd-core",
    "issuerd-protocol",
    "issuerd-token",
    "issuerd-cluster",
    "issuerd-storage",
    "issuerd-federation",
    "issuerd-auth-flow",
    "issuerd-admin-api",
    "issuerd-server",
]

ROOT_DIRS = ["src"]


def stage(stage_dir: Path) -> Path:
    """Copy the publishable file set into stage_dir and return its root."""
    root = stage_dir / "workspace"
    root.mkdir(parents=True)

    for name in ["Cargo.toml", "Cargo.lock", "README.md", "build.rs"]:
        src = REPO_ROOT / name
        if src.exists():
            shutil.copy2(src, root / name)
    for lic in REPO_ROOT.glob("LICENSE*"):
        if lic.is_file():
            shutil.copy2(lic, root / lic.name)
    for name in ROOT_DIRS:
        shutil.copytree(REPO_ROOT / name, root / name)

    # Root-package integration tests (skip the heavy conformance/perf stacks).
    tests_dst = root / "tests"
    tests_dst.mkdir()
    for name in ["integration.rs", "integration", "harness"]:
        src = REPO_ROOT / "tests" / name
        if src.is_file():
            shutil.copy2(src, tests_dst / name)
        elif src.is_dir():
            shutil.copytree(src, tests_dst / name)

    for crate in CRATES:
        shutil.copytree(REPO_ROOT / "crates" / crate, root / "crates" / crate)

    # issuerd-server embeds the built web client, which lives outside the crate
    # in the dev workspace; stage a crate-local copy so build.rs finds it in the
    # packaged crate (crates.io builds have no ../../webclientsrc).
    dist = REPO_ROOT / "webclientsrc" / "dist"
    if not dist.is_dir() or not any(dist.iterdir()):
        sys.exit("error: webclientsrc/dist is missing or empty; "
                 "run `npm run build` in webclientsrc/ first")
    shutil.copytree(dist, root / "crates" / "issuerd-server" / "webclient-dist")

    return root


def strip_flux(root: Path) -> None:
    """Remove the flux-rs git dependency and its attribute lines (staging only)."""
    manifest = root / "crates" / "issuerd-core" / "Cargo.toml"
    lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    out, i, removed_dep = [], 0, False
    while i < len(lines):
        if lines[i].startswith("flux-rs = "):
            removed_dep = True
            # Drop the contiguous comment block directly above the dep line.
            while out and out[-1].lstrip().startswith("#"):
                out.pop()
            i += 1
            continue
        out.append(lines[i])
        i += 1
    if not removed_dep:
        sys.exit("error: flux-rs dependency not found in issuerd-core/Cargo.toml")
    manifest.write_text("".join(out), encoding="utf-8")

    models = root / "crates" / "issuerd-core" / "src" / "models.rs"
    lines = models.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [ln for ln in lines if not ln.lstrip().startswith("#[flux_rs::")]
    if len(kept) == len(lines):
        sys.exit("error: no #[flux_rs::...] attributes found in models.rs")
    # Inline attribute inside the struct's field list (not a standalone line).
    content = "".join(kept).replace("#[flux_rs::field(u64[seconds])] ", "")
    if "flux_rs::" in content:
        sys.exit("error: unstripped flux_rs:: reference remains in models.rs")
    models.write_text(content, encoding="utf-8")
    print(f"staged: stripped flux-rs dep + {len(lines) - len(kept)} attribute lines + 1 inline attribute from issuerd-core")


def workspace_version(root: Path) -> str:
    """[workspace.package] version of the staged workspace (no tomllib: the act
    rehearsal images ship python < 3.11)."""
    in_section = False
    for line in (root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("["):
            in_section = line.strip() == "[workspace.package]"
        elif in_section:
            m = re.match(r'version\s*=\s*"([^"]+)"', line.strip())
            if m:
                return m.group(1)
    sys.exit("error: [workspace.package] version not found in the staged Cargo.toml")


def sparse_index_url(name: str) -> str:
    if len(name) == 1:
        layout = f"1/{name}"
    elif len(name) == 2:
        layout = f"2/{name}"
    elif len(name) == 3:
        layout = f"3/{name[0]}/{name}"
    else:
        layout = f"{name[:2]}/{name[2:4]}/{name}"
    return f"https://index.crates.io/{layout}"


def wait_index_visible(name: str, version: str, timeout: int, interval: int = 10) -> bool:
    """Poll the crates.io sparse index until `version` of `name` is listed.

    `cargo publish` returns as soon as the upload lands, but the sparse index —
    what the NEXT crate's dependency resolution reads — lags behind by a minute
    or more, so a fixed sleep is a gamble. Gate on actual visibility instead.
    """
    url = sparse_index_url(name)
    deadline = time.monotonic() + timeout
    while True:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "issuerd-publish (https://github.com/issuerd/issuerd)",
                "Cache-Control": "no-cache",
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                for line in resp.read().decode("utf-8").splitlines():
                    try:
                        if json.loads(line).get("vers") == version:
                            return True
                    except json.JSONDecodeError:
                        continue  # partial read — keep the complete lines
        except OSError:
            pass  # 404 while the crate is new to the index, or a network blip
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def publish_one(crate_dir: Path, name: str, dry_run: bool, env: dict) -> bool:
    """Publish (or dry-run) one crate. Returns False if deferred (see below)."""
    cmd = ["cargo", "publish", "--allow-dirty"]
    if dry_run:
        cmd.append("--dry-run")
    print(f"\n=== {'dry-run' if dry_run else 'PUBLISH'} {name} ===")
    result = subprocess.run(cmd, cwd=crate_dir, env=env, capture_output=True, text=True)
    print(result.stderr or result.stdout)
    if result.returncode == 0:
        return True
    output = result.stderr + result.stdout
    # A retried run hits crates.io's duplicate-version rejection on crates that
    # already went live — treat those as done so the run is resumable.
    if not dry_run and "is already uploaded" in output:
        print(f"skip: {name} is already on crates.io")
        return True
    # Before the first real publish (or right after a version bump), dependents
    # cannot even be packaged: cargo strips path deps and resolves issuerd-*
    # against crates.io, where the crate or the new version does not exist yet.
    # Their own manifest metadata was already validated by the time resolution
    # fails, so treat exactly these failures as deferred.
    if dry_run and ("no matching package named `issuerd-" in output
                    or "failed to select a version for the requirement `issuerd-" in output):
        print(f"deferred: {name} can only be packaged once its issuerd-* deps are live on crates.io")
        return False
    sys.exit(f"error: {'dry-run' if dry_run else 'publish'} failed for {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--real", action="store_true", help="actually publish (default: dry-run)")
    parser.add_argument("--pause", type=int, default=30,
                        help="extra seconds between real publishes (new-crate rate-limit grace)")
    parser.add_argument("--index-timeout", type=int, default=600, metavar="SECONDS",
                        help="max wait for a published version to appear on the sparse index")
    parser.add_argument("--skip-root", action="store_true",
                        help="skip the root issuerd binary crate (its web-client packaging is not crates.io-ready yet)")
    parser.add_argument("--from", dest="from_crate", metavar="CRATE",
                        help="start publishing at CRATE, skipping earlier library crates (for resumed runs)")
    args = parser.parse_args()

    env = dict(os.environ)
    if not env.get("CARGO_REGISTRY_TOKEN") and env.get("CRATES_TOKEN"):
        env["CARGO_REGISTRY_TOKEN"] = env["CRATES_TOKEN"]
    if args.real and not env.get("CARGO_REGISTRY_TOKEN"):
        sys.exit("error: set CARGO_REGISTRY_TOKEN (or CRATES_TOKEN) or run `cargo login` first")

    with tempfile.TemporaryDirectory(prefix="issuerd-publish-") as tmp:
        root = stage(Path(tmp))
        strip_flux(root)

        targets = [(root / "crates" / name, name) for name in CRATES]
        if not args.skip_root:
            targets.append((root, "issuerd"))  # root binary crate, published last
        if args.from_crate:
            names = [n for _, n in targets]
            if args.from_crate not in names:
                sys.exit(f"error: --from crate must be one of: {', '.join(names)}")
            targets = targets[names.index(args.from_crate):]
        deferred = []
        version = workspace_version(root)
        for i, (crate_dir, name) in enumerate(targets):
            if not publish_one(crate_dir, name, dry_run=not args.real, env=env):
                deferred.append(name)
            if args.real and i < len(targets) - 1:
                # The next crate resolves its issuerd-* deps against the sparse
                # index — gate on THIS version being visible there first (the
                # index lags the upload; a plain sleep raced it in v0.1.3),
                # then the fixed rate-limit grace.
                if wait_index_visible(name, version, timeout=args.index_timeout):
                    print(f"index: {name} {version} is visible on the sparse index")
                else:
                    sys.exit(f"error: {name} {version} still not visible in the crates.io index "
                             f"after {args.index_timeout}s — check https://crates.io/crates/{name} "
                             f"and resume with --from {name}")
                print(f"pausing {args.pause}s (rate-limit grace)...")
                time.sleep(args.pause)

    if deferred:
        print("\ndry-run OK; deferred until their issuerd-* deps are live: " + ", ".join(deferred))
    else:
        print("\nall crates " + ("passed dry-run" if not args.real else "PUBLISHED"))


if __name__ == "__main__":
    main()
