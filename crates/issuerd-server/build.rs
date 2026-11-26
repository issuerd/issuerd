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
// Also embeds the built-in default login theme (themes/issuerd/login.css plus
// the favicon.svg/favicon-dark.svg tab icons) so container deployments serve
// `/realms/{realm}/theme/{path}` without a mounted themes directory.
// Candidate locations, first hit wins:
//   - <crate>/builtin-theme/    crate-local copy staged by scripts/publish.py,
//                               present in the packaged crates.io crate
//   - <repo>/themes/            development workspace layout

use std::path::{Path, PathBuf};

const DIST_MISSING: &str =
    "webclientsrc/dist is missing or empty; run `npm run build` in webclientsrc/ first";
const THEME_MISSING: &str =
    "themes/issuerd/{login.css,favicon.svg,favicon-dark.svg} are missing; the built-in \
     default login theme cannot be embedded";

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

    for candidate in &candidates {
        println!("cargo:rerun-if-changed={}", candidate.display());
    }

    if let Some(dist_path) = candidates.iter().find(|p| populated(p)) {
        println!("cargo:rustc-env=ISSUERD_WEB_DIST={}", dist_path.display());
        println!("cargo:rustc-cfg=webclient_present");
    } else {
        println!("cargo:warning={DIST_MISSING}; the web UI will not be embedded");
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("{DIST_MISSING}; release builds must embed the web UI");
        }
    }

    let theme_dir_candidates = [
        manifest_dir.join("builtin-theme"),
        manifest_dir.join("..").join("..").join("themes"),
    ];
    let theme_files = ["login.css", "favicon.svg", "favicon-dark.svg"];

    for candidate in &theme_dir_candidates {
        println!("cargo:rerun-if-changed={}", candidate.join("issuerd").display());
    }

    let mut theme_dir: Option<&Path> = None;
    'outer: for candidate in &theme_dir_candidates {
        for file in &theme_files {
            if !candidate.join("issuerd").join(file).is_file() {
                continue 'outer;
            }
        }
        theme_dir = Some(candidate);
        break;
    }

    if let Some(dir) = theme_dir {
        let css_path = dir.join("issuerd").join("login.css");
        println!("cargo:rerun-if-changed={}", css_path.display());
        println!("cargo:rustc-env=ISSUERD_BUILTIN_LOGIN_CSS={}", css_path.display());
        let favicon_path = dir.join("issuerd").join("favicon.svg");
        println!("cargo:rustc-env=ISSUERD_BUILTIN_FAVICON_SVG={}", favicon_path.display());
        let favicon_dark_path = dir.join("issuerd").join("favicon-dark.svg");
        println!(
            "cargo:rustc-env=ISSUERD_BUILTIN_FAVICON_DARK_SVG={}",
            favicon_dark_path.display()
        );
        println!("cargo:rustc-cfg=builtin_theme_present");
    } else {
        println!("cargo:warning={THEME_MISSING}; the default login theme will not be embedded");
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("{THEME_MISSING}; release builds must embed the default login theme");
        }
    }
}
