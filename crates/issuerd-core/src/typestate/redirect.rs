// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Redirect-loop prevention types (SafeRedirectTarget).

//! Redirect-loop prevention types.
//!
//! [`SafeRedirectTarget`] is a validated redirect URL that is guaranteed not to
//! point back at the current request path. It is intended to be used for
//! server-side redirects so that a bug cannot accidentally create a redirect
//! loop where a handler redirects to itself.

use crate::IssuerdError;

/// A redirect target that has been checked against the current request path.
///
/// The check is performed at construction time, so any code that holds a
/// `SafeRedirectTarget` knows the redirect will not immediately loop back to
/// the same URL.
#[derive(Debug, Clone)]
pub struct SafeRedirectTarget {
    url: String,
}

impl SafeRedirectTarget {
    /// Create a new safe redirect target.
    ///
    /// `current_path` is the path of the request that is producing the redirect.
    /// `target` is the location to redirect to. The target is rejected if it
    /// is empty or if its path (ignoring the query string) is identical to
    /// `current_path`.
    pub fn new(target: impl Into<String>, current_path: &str) -> Result<Self, IssuerdError> {
        let url = target.into();
        if url.is_empty() {
            return Err(IssuerdError::InvalidRequest("empty redirect target".into()));
        }

        // Strip query string for path comparison.
        let target_path = url.split('?').next().unwrap_or(&url);
        if target_path == current_path {
            return Err(IssuerdError::InvalidRequest(format!(
                "redirect target {url} would loop back to current path {current_path}"
            )));
        }

        Ok(Self { url })
    }

    /// Convert the safe target into the raw URL string.
    pub fn into_url(self) -> String {
        self.url
    }

    /// Borrow the validated URL.
    pub fn as_str(&self) -> &str {
        &self.url
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_redirect_accepts_valid_target() {
        let target = SafeRedirectTarget::new("/realms/master/account", "/login.html").unwrap();
        assert_eq!(target.as_str(), "/realms/master/account");
    }

    #[test]
    fn safe_redirect_allows_login_page_from_auth_endpoint() {
        let target = SafeRedirectTarget::new(
            "/login.html?execution_id=abc&realm=master",
            "/realms/master/protocol/openid-connect/auth",
        )
        .unwrap();
        assert!(target.as_str().contains("execution_id"));
    }

    #[test]
    fn safe_redirect_rejects_self_loop() {
        assert!(SafeRedirectTarget::new(
            "/realms/master/protocol/openid-connect/auth",
            "/realms/master/protocol/openid-connect/auth"
        )
        .is_err());
    }

    #[test]
    fn safe_redirect_rejects_login_page_loop() {
        assert!(SafeRedirectTarget::new("/login.html?realm=master", "/login.html").is_err());
    }

    #[test]
    fn safe_redirect_rejects_empty() {
        assert!(SafeRedirectTarget::new("", "/realms/master/protocol/openid-connect/auth").is_err());
    }
}
