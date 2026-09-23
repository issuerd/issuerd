// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// TypedChallenge: a challenge with its kind proven at the type level.

use std::marker::PhantomData;

use super::ChallengeKind;
use super::{CookieKind, LoginFormKind, OtpFormKind, RedirectKind, WebAuthnKind};
use crate::traits::Challenge;

/// A challenge with its kind proven at the type level.
#[derive(Debug, Clone)]
pub struct TypedChallenge<K: ChallengeKind> {
    inner: Challenge,
    _kind: PhantomData<fn() -> K>,
}

impl TypedChallenge<LoginFormKind> {
    /// Try to cast a generic `Challenge` to a typed login-form challenge.
    pub fn from_challenge(ch: Challenge) -> Option<Self> {
        match &ch {
            Challenge::LoginForm { .. } => Some(Self {
                inner: ch,
                _kind: PhantomData,
            }),
            _ => None,
        }
    }

    /// Return the action URL for this login form.
    pub fn action_url(&self) -> &str {
        match &self.inner {
            Challenge::LoginForm { action_url } => action_url,
            _ => unreachable!(),
        }
    }
}

impl TypedChallenge<OtpFormKind> {
    /// Try to cast a generic `Challenge` to a typed OTP-form challenge.
    pub fn from_challenge(ch: Challenge) -> Option<Self> {
        match &ch {
            Challenge::OtpForm { .. } => Some(Self {
                inner: ch,
                _kind: PhantomData,
            }),
            _ => None,
        }
    }

    /// Return the action URL for this OTP form.
    pub fn action_url(&self) -> &str {
        match &self.inner {
            Challenge::OtpForm { action_url } => action_url,
            _ => unreachable!(),
        }
    }
}

impl TypedChallenge<WebAuthnKind> {
    /// Try to cast a generic `Challenge` to a typed WebAuthn challenge.
    pub fn from_challenge(ch: Challenge) -> Option<Self> {
        match &ch {
            Challenge::WebAuthn { .. } => Some(Self {
                inner: ch,
                _kind: PhantomData,
            }),
            _ => None,
        }
    }

    /// Return the action URL for this WebAuthn challenge.
    pub fn action_url(&self) -> &str {
        match &self.inner {
            Challenge::WebAuthn { action_url, .. } => action_url,
            _ => unreachable!(),
        }
    }

    /// Return the WebAuthn challenge string.
    pub fn challenge(&self) -> &str {
        match &self.inner {
            Challenge::WebAuthn { challenge, .. } => challenge,
            _ => unreachable!(),
        }
    }
}

impl TypedChallenge<RedirectKind> {
    /// Try to cast a generic `Challenge` to a typed redirect challenge.
    pub fn from_challenge(ch: Challenge) -> Option<Self> {
        match &ch {
            Challenge::Redirect { .. } => Some(Self {
                inner: ch,
                _kind: PhantomData,
            }),
            _ => None,
        }
    }

    /// Return the redirect URL.
    pub fn url(&self) -> &str {
        match &self.inner {
            Challenge::Redirect { url } => url,
            _ => unreachable!(),
        }
    }
}

impl TypedChallenge<CookieKind> {
    /// Try to cast a generic `Challenge` to a typed cookie challenge.
    pub fn from_challenge(ch: Challenge) -> Option<Self> {
        match &ch {
            Challenge::Cookie => Some(Self {
                inner: ch,
                _kind: PhantomData,
            }),
            _ => None,
        }
    }
}

impl<K: ChallengeKind> TypedChallenge<K> {
    /// Consume and return the untyped `Challenge`.
    pub fn into_challenge(self) -> Challenge {
        self.inner
    }

    /// Borrow the untyped `Challenge`.
    pub fn as_challenge(&self) -> &Challenge {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_form_challenge_downcast_succeeds() {
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        let typed = TypedChallenge::<LoginFormKind>::from_challenge(ch);
        assert!(typed.is_some());
        assert_eq!(typed.unwrap().action_url(), "/login");
    }

    #[test]
    fn otp_form_challenge_downcast_fails_for_login() {
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        let typed = TypedChallenge::<OtpFormKind>::from_challenge(ch);
        assert!(typed.is_none());
    }

    #[test]
    fn redirect_challenge_url() {
        let ch = Challenge::Redirect {
            url: "https://idp.example.com".to_string(),
        };
        let typed = TypedChallenge::<RedirectKind>::from_challenge(ch).unwrap();
        assert_eq!(typed.url(), "https://idp.example.com");
    }

    #[test]
    fn webauthn_challenge_downcast_and_accessors() {
        let ch = Challenge::WebAuthn {
            action_url: "/webauthn".to_string(),
            challenge: "chal-123".to_string(),
        };
        let typed = TypedChallenge::<WebAuthnKind>::from_challenge(ch).unwrap();
        assert_eq!(typed.action_url(), "/webauthn");
        assert_eq!(typed.challenge(), "chal-123");
    }

    #[test]
    fn webauthn_downcast_fails_for_login_form() {
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        assert!(TypedChallenge::<WebAuthnKind>::from_challenge(ch).is_none());
    }

    #[test]
    fn cookie_challenge_downcast_succeeds() {
        let ch = Challenge::Cookie;
        assert!(TypedChallenge::<CookieKind>::from_challenge(ch).is_some());
    }

    #[test]
    fn cookie_downcast_fails_for_otp_form() {
        let ch = Challenge::OtpForm {
            action_url: "/otp".to_string(),
        };
        assert!(TypedChallenge::<CookieKind>::from_challenge(ch).is_none());
    }

    #[test]
    fn into_challenge_returns_original() {
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        let typed = TypedChallenge::<LoginFormKind>::from_challenge(ch).unwrap();
        match typed.into_challenge() {
            Challenge::LoginForm { action_url } => assert_eq!(action_url, "/login"),
            other => panic!("expected LoginForm, got {:?}", other),
        }
    }

    #[test]
    fn as_challenge_borrows_original() {
        let ch = Challenge::OtpForm {
            action_url: "/otp".to_string(),
        };
        let typed = TypedChallenge::<OtpFormKind>::from_challenge(ch).unwrap();
        match typed.as_challenge() {
            Challenge::OtpForm { action_url } => assert_eq!(action_url, "/otp"),
            other => panic!("expected OtpForm, got {:?}", other),
        }
    }

    /// ```compile_fail
    /// use issuerd_core::typestate::{TypedChallenge, LoginFormKind};
    /// fn f(c: TypedChallenge<LoginFormKind>) {
    ///     let _ = c.url();
    /// }
    /// ```
    #[allow(dead_code)]
    fn compile_fail_url_on_login_form() {}
}
