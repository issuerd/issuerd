// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// QR code rendering for TOTP enrollment (locally generated inline SVG).

//! QR code rendering for TOTP enrollment.
//!
//! Produces an inline SVG string that is embedded directly into
//! server-rendered pages (required-action enrollment) or returned by the
//! account console enrollment endpoint. The output is generated locally from
//! the `otpauth://` URI — no external chart service is ever contacted with the
//! secret.

use issuerd_core::IssuerdError;

/// Render `data` as an SVG QR code with a 4-module quiet-zone border.
///
/// The `qrcodegen` crate ships no SVG serializer, so the path data is built
/// from the module matrix here (one `M x,y h1 v1 h-1 z` square per dark
/// module — the same shape Nayuki's reference demo produces).
pub(crate) fn qr_svg(data: &str) -> Result<String, IssuerdError> {
    const BORDER: i32 = 4;
    let qr = qrcodegen::QrCode::encode_text(data, qrcodegen::QrCodeEcc::Medium)
        .map_err(|e| IssuerdError::ServerError(format!("QR encoding failed: {e}")))?;
    let dimension = qr.size() + BORDER * 2;
    let mut path = String::with_capacity(qr.size() as usize * qr.size() as usize * 14);
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                if !path.is_empty() {
                    path.push(' ');
                }
                path.push_str(&format!("M{},{}h1v1h-1z", x + BORDER, y + BORDER));
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" \
         viewBox=\"0 0 {dimension} {dimension}\" stroke=\"none\">\
         <rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\
         <path d=\"{path}\" fill=\"#000000\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_svg_produces_svg_markup() {
        let input = "otpauth://totp/issuer:alice?secret=ABC&issuer=issuer";
        let svg = qr_svg(input).unwrap();
        assert!(svg.starts_with("<svg"), "expected svg element, got: {svg}");
        assert!(svg.contains("<path d=\"M"), "expected qr modules path");
        // ViewBox must be the module size plus the quiet-zone border on both sides.
        let qr = qrcodegen::QrCode::encode_text(input, qrcodegen::QrCodeEcc::Medium).unwrap();
        let dimension = qr.size() + 8;
        assert!(
            svg.contains(&format!("viewBox=\"0 0 {dimension} {dimension}\"")),
            "expected {dimension}x{dimension} viewBox: {svg}"
        );
    }

    #[test]
    fn qr_svg_rejects_oversized_input() {
        let huge = "x".repeat(10_000);
        assert!(qr_svg(&huge).is_err());
    }
}
