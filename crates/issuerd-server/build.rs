// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Build script: detects the built web client (webclientsrc/dist) and sets cfg flags.

use std::path::PathBuf;

const DIST_MISSING: &str =
    "webclientsrc/dist is missing or empty; run `npm run build` in webclientsrc/ first";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(webclient_present)");
    println!("cargo:rustc-check-cfg=cfg(coverage)");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist_path = manifest_dir.join("..").join("..").join("webclientsrc").join("dist");

    let dist_populated = match std::fs::read_dir(&dist_path) {
        Ok(mut entries) => entries.any(|e| e.is_ok()),
        Err(_) => false,
    };

    if dist_populated {
        println!("cargo:rerun-if-changed={}", dist_path.display());
        println!("cargo:rustc-cfg=webclient_present");
        return;
    }

    println!("cargo:warning={DIST_MISSING}; the web UI will not be embedded");
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        panic!("{DIST_MISSING}; release builds must embed the web UI");
    }
}
