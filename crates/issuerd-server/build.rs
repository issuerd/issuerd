// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Build script: detects the built web client and sets cfg flags.
//
// Candidate locations, first populated one wins:
//   - <crate>/webclient-dist    crate-local copy staged by scripts/publish.py,
//                               present in the packaged crates.io crate
//   - <repo>/webclientsrc/dist  development workspace layout
//
// Also embeds the built-in default login theme (themes/issuerd/login.css) so
// container deployments serve `/realms/{realm}/theme/login.css` without a
// mounted themes directory. Candidate locations, first hit wins:
//   - <crate>/builtin-theme/    crate-local copy staged by scripts/publish.py,
//                               present in the packaged crates.io crate
//   - <repo>/themes/            development workspace layout

use std::path::{Path, PathBuf};

const DIST_MISSING: &str =
    "webclientsrc/dist is missing or empty; run `npm run build` in webclientsrc/ first";
const THEME_MISSING: &str =
    "themes/issuerd/login.css is missing; the built-in default login theme cannot be embedded";

fn populated(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => entries.any(|e| e.is_ok()),
        Err(_) => false,
    }
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(webclient_present)");
    println!("cargo:rustc-check-cfg=cfg(builtin_theme_present)");
    println!("cargo:rustc-check-cfg=cfg(coverage)");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let candidates = [
        manifest_dir.join("webclient-dist"),
        manifest_dir.join("..").join("..").join("webclientsrc").join("dist"),
    ];

    if let Some(dist_path) = candidates.iter().find(|p| populated(p)) {
        println!("cargo:rerun-if-changed={}", dist_path.display());
        println!("cargo:rustc-env=ISSUERD_WEB_DIST={}", dist_path.display());
        println!("cargo:rustc-cfg=webclient_present");
    } else {
        println!("cargo:warning={DIST_MISSING}; the web UI will not be embedded");
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("{DIST_MISSING}; release builds must embed the web UI");
        }
    }

    let theme_candidates = [
        manifest_dir.join("builtin-theme").join("issuerd").join("login.css"),
        manifest_dir
            .join("..")
            .join("..")
            .join("themes")
            .join("issuerd")
            .join("login.css"),
    ];

    if let Some(css_path) = theme_candidates.iter().find(|p| p.is_file()) {
        println!("cargo:rerun-if-changed={}", css_path.display());
        println!("cargo:rustc-env=ISSUERD_BUILTIN_LOGIN_CSS={}", css_path.display());
        println!("cargo:rustc-cfg=builtin_theme_present");
    } else {
        println!("cargo:warning={THEME_MISSING}; the default login theme will not be embedded");
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("{THEME_MISSING}; release builds must embed the default login theme");
        }
    }
}
