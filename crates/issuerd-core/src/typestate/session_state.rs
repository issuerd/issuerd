// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Session lifecycle state markers (anonymous, authenticated, authorized, expired).

use super::private;

/// Session lifecycle state marker trait.
pub trait SessionState: private::Sealed {}

/// Session created but not yet authenticated.
#[derive(Debug, Clone)]
pub struct SessionAnonymous;
impl private::Sealed for SessionAnonymous {}
impl SessionState for SessionAnonymous {}

/// User authenticated — session holds proof of auth.
#[derive(Debug, Clone)]
pub struct SessionAuthenticated;
impl private::Sealed for SessionAuthenticated {}
impl SessionState for SessionAuthenticated {}

/// Consent screen required before authorization.
#[derive(Debug, Clone)]
pub struct SessionConsentRequired;
impl private::Sealed for SessionConsentRequired {}
impl SessionState for SessionConsentRequired {}

/// Fully authorized — tokens may be issued.
#[derive(Debug, Clone)]
pub struct SessionAuthorized;
impl private::Sealed for SessionAuthorized {}
impl SessionState for SessionAuthorized {}

/// Terminal state — session has been consumed (token issued).
#[derive(Debug, Clone)]
pub struct SessionExpired;
impl private::Sealed for SessionExpired {}
impl SessionState for SessionExpired {}
