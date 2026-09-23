// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Sealed challenge-kind markers (login form, OTP, WebAuthn, redirect, cookie).

use super::private;

/// Sealed trait for challenge kinds.
pub trait ChallengeKind: private::Sealed {}

/// Login form challenge.
#[derive(Debug, Clone)]
pub struct LoginFormKind;
impl private::Sealed for LoginFormKind {}
impl ChallengeKind for LoginFormKind {}

/// OTP form challenge.
#[derive(Debug, Clone)]
pub struct OtpFormKind;
impl private::Sealed for OtpFormKind {}
impl ChallengeKind for OtpFormKind {}

/// WebAuthn challenge.
#[derive(Debug, Clone)]
pub struct WebAuthnKind;
impl private::Sealed for WebAuthnKind {}
impl ChallengeKind for WebAuthnKind {}

/// External redirect challenge.
#[derive(Debug, Clone)]
pub struct RedirectKind;
impl private::Sealed for RedirectKind {}
impl ChallengeKind for RedirectKind {}

/// Cookie-based SSO challenge.
#[derive(Debug, Clone)]
pub struct CookieKind;
impl private::Sealed for CookieKind {}
impl ChallengeKind for CookieKind {}
