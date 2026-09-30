// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dylint log-hygiene lints for the Issuerd workspace (the "Logging
// Conventions" section of AGENTS.md).

//! Five lints, in one pre-expansion early pass (syntax-only) and one late
//! pass (type-aware, on the expanded `tracing` machinery):
//!
//! Early pass (no name resolution, no `clippy_utils`):
//!
//! - `tracing_error_debug`: an `error`/`err` log field recorded with the `?`
//!   (Debug) sigil — errors are logged as `error = %e` (Display).
//! - `secret_field_in_log`: a structured field named like a secret
//!   (password/token/code/...) in any event macro or `#[instrument(fields)]`.
//! - `session_id_in_log`: a `session_id`/`sid` field at INFO/WARN/ERROR, or
//!   anywhere in `#[instrument(fields)]` (span fields are never allowed).
//! - `instrument_skip_sensitive`: an `#[instrument]`-annotated function whose
//!   sensitive parameters (state/headers/body/params/query/IPs, `*_token`,
//!   `*_secret`, `*_password`, `*_code`, `*_assertion`, `*_key`) are missing
//!   from `skip(...)`/`skip_all`.
//!
//! Late pass (type-aware; `tracing` 0.1.44 expansions all lower field values
//! to `&expr as &dyn tracing::field::Value` casts, with `%`/`?` going through
//! `tracing::field::display`/`debug`):
//!
//! - `secret_typed_value_in_log`: the value's type (after peeling references
//!   and the display/debug wrapper) is in the configurable secret-type list.
//!
//! Event macros are recognized by the last path segment
//! (`trace!`/`debug!`/`info!`/`warn!`/`error!` — the workspace logs
//! exclusively through `tracing`), the attribute by the last segment
//! `instrument`. Pre-expansion is required for the early pass: macro calls
//! and the proc-macro attribute do not survive expansion.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_ast::ast::{self, AssocItem, AssocItemKind, AttrArgs, AttrKind, Item, ItemKind, PatKind};
use rustc_ast::token::TokenKind;
use rustc_ast::tokenstream::{TokenStream, TokenTree};
use rustc_errors::DiagDecorator;
use rustc_hir as hir;
use rustc_hir::def::Res;
use rustc_lint::{EarlyContext, EarlyLintPass, LateContext, LateLintPass, LintContext};
use rustc_middle::ty;
use rustc_span::{Span, Symbol};

dylint_linting::dylint_library!();

rustc_session::declare_lint! {
    /// ### What it does
    /// Checks that error values in `tracing` event macros are recorded with
    /// the `%` (Display) sigil, not the `?` (Debug) sigil.
    ///
    /// ### Why is this bad?
    /// The Issuerd logging convention is `error = %e` (AGENTS.md, "Logging
    /// Conventions"): Display renders the message for operators; `?` renders
    /// the Debug representation, which drifts per error type.
    ///
    /// ### Example
    /// ```rust,ignore
    /// warn!(error = ?e, "request failed");
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// warn!(error = %e, "request failed");
    /// ```
    pub TRACING_ERROR_DEBUG,
    Deny,
    "log errors as `error = %e`, not `error = ?e`"
}

rustc_session::declare_lint! {
    /// ### What it does
    /// Checks that no structured log field — in a `tracing` event macro at
    /// any level, or in `#[instrument(fields(...))]` — is named like a
    /// secret: `password`, `passwd`, `secret`, `client_secret`, `token`,
    /// `access_token`, `refresh_token`, `id_token`, `code`, `authorization`,
    /// `cookie`, `totp`, `otp`, `dpop`, `assertion`, `private_key`. Exact
    /// match always flags; the `<name>_*` prefix form flags except for the
    /// OAuth-vocabulary bases `token`/`code`/`authorization` (whose compounds
    /// are usually not secrets: `token_type`, `token_roles`,
    /// `code_challenge`) and for the metadata suffixes `_hash`/`_len`/
    /// `_count`/`_type`/`_id`.
    ///
    /// ### Why is this bad?
    /// Secrets must never be logged at any level (AGENTS.md, "Logging
    /// Conventions") — log aggregation is not a secret store.
    ///
    /// ### Example
    /// ```rust,ignore
    /// info!(token = %access_token, "issued");
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// info!(client_id = %client_id, "issued a token");
    /// ```
    pub SECRET_FIELD_IN_LOG,
    Deny,
    "secrets must never be logged (no `password`/`token`/`code`/... log fields)"
}

rustc_session::declare_lint! {
    /// ### What it does
    /// Checks that `session_id`/`sid` fields appear only in DEBUG/TRACE
    /// events, and never in `#[instrument(fields(...))]` span fields.
    ///
    /// ### Why is this bad?
    /// Session IDs are DEBUG at most and never span fields (AGENTS.md,
    /// "Logging Conventions"): they are session-fixation aids in aggregate
    /// logs.
    ///
    /// ### Example
    /// ```rust,ignore
    /// info!(session_id = %session.id, "login");
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// debug!(session_id = %session.id, "login");
    /// ```
    pub SESSION_ID_IN_LOG,
    Deny,
    "session IDs are DEBUG at most and never appear in span fields"
}

rustc_session::declare_lint! {
    /// ### What it does
    /// Checks that every sensitive parameter of an `#[instrument]`-annotated
    /// function is covered by `skip(...)` or `skip_all`. Sensitive names:
    /// `state`, `headers`, `body`, `body_bytes`, `params`, `query`, `ip`,
    /// `client_ip`, `peer_ip`, and any binding ending in `_token`,
    /// `_secret`, `_password`, `_code`, `_assertion`, or `_key` (except
    /// `*_pub_key`/`*public_key`).
    ///
    /// ### Why is this bad?
    /// `#[instrument]` records every argument in the span by default; the
    /// Issuerd logging convention requires request state, headers, bodies,
    /// and secret-carrying arguments to be skipped explicitly (AGENTS.md,
    /// "Logging Conventions").
    ///
    /// ### Example
    /// ```rust,ignore
    /// #[instrument(fields(realm = %realm))]
    /// async fn handler(state: &State, body: String) { ... }
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// #[instrument(skip(state, body), fields(realm = %realm))]
    /// async fn handler(state: &State, body: String) { ... }
    /// ```
    pub INSTRUMENT_SKIP_SENSITIVE,
    Deny,
    "sensitive handler arguments must be skipped in #[instrument]"
}

rustc_session::declare_lint! {
    /// ### What it does
    /// Type-aware: checks the TYPE of every value recorded through a
    /// `tracing` field (all sigils lower to `&dyn tracing::field::Value`
    /// casts in the macro expansion) against a configurable list of secret
    /// types (default: the `issuerd_core::models` secret newtypes and
    /// credential/key structs).
    ///
    /// ### Why is this bad?
    /// Secrets must never be logged at any level (AGENTS.md, "Logging
    /// Conventions"). The syntactic `secret_field_in_log` lint only sees the
    /// field NAME; this lint catches secret VALUES under innocuous names
    /// (`info!(details = ?credential, ...)` — `Credential`'s derived Debug
    /// prints the hash bytes).
    ///
    /// ### Example
    /// ```rust,ignore
    /// info!(credentials = ?user.credential, "loaded"); // Credential!
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// info!(credential_id = %credential.id, "loaded");
    /// ```
    pub SECRET_TYPED_VALUE_IN_LOG,
    Deny,
    "secret values must never be logged (type-aware check of tracing field values)"
}

rustc_session::declare_lint_pass!(IssuerdLogHygiene => [
    TRACING_ERROR_DEBUG,
    SECRET_FIELD_IN_LOG,
    SESSION_ID_IN_LOG,
    INSTRUMENT_SKIP_SENSITIVE,
]);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[
        TRACING_ERROR_DEBUG,
        SECRET_FIELD_IN_LOG,
        SESSION_ID_IN_LOG,
        INSTRUMENT_SKIP_SENSITIVE,
        SECRET_TYPED_VALUE_IN_LOG,
    ]);
    // Pre-expansion: the proc-macro attribute `#[instrument]` and the event
    // macro calls are expanded away before the regular early pass runs.
    lint_store.register_pre_expansion_lint_pass(Box::new(|| Box::new(IssuerdLogHygiene)));
    // Type-aware lints run on the expanded tracing machinery (the `&dyn
    // field::Value` casts and `FieldSet` construction only exist there).
    let config = Config::load();
    lint_store.register_late_lint_pass(Box::new(move |_| {
        Box::new(IssuerdLogHygieneLate::new(config.clone()))
    }));
}

/// The sigil between the field name and the value: `?` (Debug) or `%`
/// (Display).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sigil {
    Debug,
    Display,
}

/// A structured field parsed from a `tracing` event macro invocation or from
/// `#[instrument(fields(...))]`.
struct LogField {
    /// The dotted field name as written (`http.status` stays one field).
    name: String,
    name_span: Span,
    sigil: Option<Sigil>,
    #[allow(dead_code)] // kept for future machine-applicable `?` -> `%` suggestions
    sigil_span: Option<Span>,
}

/// The event-macro level (only the five `tracing` level macros are checked).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn from_macro_name(name: &str) -> Option<Self> {
        match name {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }

    /// Session identifiers are DEBUG at most.
    fn allows_session_ids(self) -> bool {
        matches!(self, Level::Trace | Level::Debug)
    }

    fn name(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Secret-shaped field names (AGENTS.md "Secrets — never logged at any
/// level"). Every name is matched exactly; the names in
/// [`SECRET_FIELD_PREFIXABLE`] additionally match as a `<name>_*` prefix.
const SECRET_FIELD_NAMES: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "authorization",
    "cookie",
    "totp",
    "otp",
    "dpop",
    "assertion",
    "private_key",
];

/// The subset of [`SECRET_FIELD_NAMES`] whose `_*` compounds are still
/// secrets (`new_password`, `totp_secret`, ...). `token`, `code`, and
/// `authorization` are deliberately exact-match only: their compounds are
/// OAuth vocabulary for non-secret data (`token_type`, `token_roles`,
/// `code_challenge`, `authorization_details`).
const SECRET_FIELD_PREFIXABLE: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "cookie",
    "totp",
    "otp",
    "dpop",
    "assertion",
    "private_key",
];

/// Field-name suffixes that carry metadata about a secret, never the secret
/// itself (`token_type`, `password_hash`, `code_len`, ... are legal).
const SAFE_FIELD_SUFFIXES: &[&str] = &["_hash", "_len", "_count", "_type", "_id"];

fn is_secret_field(name: &str) -> bool {
    if SAFE_FIELD_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
        return false;
    }
    if SECRET_FIELD_NAMES.contains(&name) {
        return true;
    }
    SECRET_FIELD_PREFIXABLE
        .iter()
        .any(|secret| name.strip_prefix(secret).is_some_and(|rest| rest.starts_with('_')))
}

/// Parameter names that must never be recorded by `#[instrument]` (request
/// state, headers, bodies, query params, client IPs), plus the secret-shaped
/// suffixes.
const SENSITIVE_PARAM_NAMES: &[&str] = &[
    "state",
    "headers",
    "body",
    "body_bytes",
    "params",
    "query",
    "ip",
    "client_ip",
    "peer_ip",
];

const SENSITIVE_PARAM_SUFFIXES: &[&str] = &[
    "_token",
    "_secret",
    "_password",
    "_code",
    "_assertion",
    "_key",
];

fn is_sensitive_param(name: &str) -> bool {
    if SENSITIVE_PARAM_NAMES.contains(&name) {
        return true;
    }
    // Public key material is not sensitive.
    if name.ends_with("_pub_key") || name.ends_with("public_key") {
        return false;
    }
    SENSITIVE_PARAM_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

fn ident_token(tt: &TokenTree) -> Option<(Symbol, Span)> {
    match tt {
        TokenTree::Token(token, _) => match token.kind {
            TokenKind::Ident(sym, _) => Some((sym, token.span)),
            _ => None,
        },
        _ => None,
    }
}

fn ident_at(stream: &TokenStream, i: usize) -> Option<(Symbol, Span)> {
    stream.get(i).and_then(ident_token)
}

fn is_punct(stream: &TokenStream, i: usize, pred: fn(&TokenKind) -> bool) -> bool {
    match stream.get(i) {
        Some(TokenTree::Token(token, _)) => pred(&token.kind),
        _ => false,
    }
}

fn is_comma(stream: &TokenStream, i: usize) -> bool {
    is_punct(stream, i, |kind| matches!(kind, TokenKind::Comma))
}

fn sigil_at(stream: &TokenStream, i: usize) -> Option<(Sigil, Span)> {
    match stream.get(i) {
        Some(TokenTree::Token(token, _)) => match token.kind {
            TokenKind::Question => Some((Sigil::Debug, token.span)),
            TokenKind::Percent => Some((Sigil::Display, token.span)),
            _ => None,
        },
        _ => None,
    }
}

/// Advance past a field value / `target:` expression: everything up to the
/// next top-level comma (delimited groups are single token trees, so commas
/// inside `(...)`/`[...]`/`{...}` are invisible here).
fn skip_value(stream: &TokenStream, mut i: usize) -> usize {
    while i < stream.len() && !is_comma(stream, i) {
        i += 1;
    }
    i
}

/// Parse the structured fields of a `tracing` event macro invocation, or of
/// `#[instrument(fields(...))]`, from a token stream. Parsing stops at the
/// first free-standing literal (the format string); everything after it is
/// message arguments, not fields.
fn parse_fields(tokens: &TokenStream) -> Vec<LogField> {
    let mut fields = Vec::new();
    let mut i = 0;

    // Skip the `target: <expr> ,` / `parent: <expr> ,` prefixes (both may
    // precede the field list).
    loop {
        match ident_at(tokens, i) {
            Some((name, _))
                if (name.as_str() == "target" || name.as_str() == "parent")
                    && is_punct(tokens, i + 1, |kind| matches!(kind, TokenKind::Colon)) =>
            {
                i = skip_value(tokens, i + 2);
                if is_comma(tokens, i) {
                    i += 1;
                }
            }
            _ => break,
        }
    }

    while i < tokens.len() {
        if is_comma(tokens, i) {
            i += 1;
            continue;
        }
        // The message format string (or any other literal in field position)
        // ends the field list.
        if matches!(tokens.get(i), Some(TokenTree::Token(token, _)) if matches!(token.kind, TokenKind::Literal(_)))
        {
            break;
        }
        // Shorthand with a sigil: `?ident` / `%ident`.
        if let Some((sigil, sigil_span)) = sigil_at(tokens, i) {
            if let Some((name, name_span)) = ident_at(tokens, i + 1) {
                fields.push(LogField {
                    name: name.as_str().to_string(),
                    name_span,
                    sigil: Some(sigil),
                    sigil_span: Some(sigil_span),
                });
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // A (possibly dotted) name: `name = value`, or bare shorthand
        // (`debug!(username)` records `username = username`).
        if let Some((first, first_span)) = ident_at(tokens, i) {
            let mut name = first.as_str().to_string();
            let mut j = i + 1;
            while is_punct(tokens, j, |kind| matches!(kind, TokenKind::Dot)) {
                match ident_at(tokens, j + 1) {
                    Some((segment, _)) => {
                        name.push('.');
                        name.push_str(segment.as_str());
                        j += 2;
                    }
                    None => break,
                }
            }
            if is_punct(tokens, j, |kind| matches!(kind, TokenKind::Eq)) {
                let (sigil, sigil_span) = match sigil_at(tokens, j + 1) {
                    Some((sigil, span)) => (Some(sigil), Some(span)),
                    None => (None, None),
                };
                fields.push(LogField {
                    name,
                    name_span: first_span,
                    sigil,
                    sigil_span,
                });
                i = skip_value(tokens, if sigil.is_some() { j + 2 } else { j + 1 });
            } else {
                fields.push(LogField {
                    name,
                    name_span: first_span,
                    sigil: None,
                    sigil_span: None,
                });
                i = j;
            }
            continue;
        }
        // Anything else (a stray group, an unexpected token): skip it.
        i += 1;
    }
    fields
}

impl IssuerdLogHygiene {
    /// Lints 1–3 on the parsed fields of an event macro.
    fn check_event_fields(cx: &EarlyContext<'_>, level: Level, fields: &[LogField]) {
        for field in fields {
            // Dotted names are matched on their last segment.
            let name = field.name.rsplit('.').next().unwrap_or(&field.name);
            if field.sigil == Some(Sigil::Debug) && (name == "error" || name == "err") {
                let name = name.to_string();
                cx.emit_span_lint(
                    TRACING_ERROR_DEBUG,
                    field.name_span,
                    DiagDecorator(move |diag| {
                        diag.primary_message(format!(
                            "log field `{name}` records an error with the `?` (Debug) sigil"
                        ));
                        diag.help(
                            "log errors as `error = %e` (Display); see AGENTS.md \"Logging Conventions\"",
                        );
                    }),
                );
            }
            if is_secret_field(name) {
                let name = name.to_string();
                cx.emit_span_lint(
                    SECRET_FIELD_IN_LOG,
                    field.name_span,
                    DiagDecorator(move |diag| {
                        diag.primary_message(format!("log field `{name}` is named like a secret"));
                        diag.help("secrets must never be logged at any level; remove the field");
                    }),
                );
            }
            if !level.allows_session_ids() && (name == "session_id" || name == "sid") {
                let name = name.to_string();
                cx.emit_span_lint(
                    SESSION_ID_IN_LOG,
                    field.name_span,
                    DiagDecorator(move |diag| {
                        diag.primary_message(format!(
                            "log field `{name}` records a session identifier at {} level",
                            level.name(),
                        ));
                        diag.help(
                            "session IDs are DEBUG at most; lower the event level or drop the field",
                        );
                    }),
                );
            }
        }
    }

    /// Lints 2–4 on an `#[instrument]` attribute plus the function's
    /// parameters. `attrs` are the attributes of the item the attribute
    /// decorates.
    fn check_fn(cx: &EarlyContext<'_>, attrs: &[ast::Attribute], params: &[ast::Param]) {
        for attr in attrs {
            let AttrKind::Normal(normal) = &attr.kind else {
                continue;
            };
            let Some(segment) = normal.item.path.segments.last() else {
                continue;
            };
            if segment.ident.name.as_str() != "instrument" {
                continue;
            }

            let mut skip_all = false;
            let mut skipped: Vec<String> = Vec::new();
            let mut span_fields: Vec<LogField> = Vec::new();
            if let AttrArgs::Delimited(args) = &normal.item.args {
                let tokens = &args.tokens;
                let mut i = 0;
                while i < tokens.len() {
                    if let Some((name, _)) = ident_at(tokens, i) {
                        match name.as_str() {
                            "skip" => {
                                if let Some(TokenTree::Delimited(_, _, _, stream)) =
                                    tokens.get(i + 1)
                                {
                                    for j in 0..stream.len() {
                                        if let Some((sym, _)) = ident_at(stream, j) {
                                            skipped.push(sym.as_str().to_string());
                                        }
                                    }
                                    i += 1;
                                }
                            }
                            "skip_all" => skip_all = true,
                            "fields" => {
                                if let Some(TokenTree::Delimited(_, _, _, stream)) =
                                    tokens.get(i + 1)
                                {
                                    span_fields = parse_fields(stream);
                                    i += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    i += 1;
                }
            }

            // Span fields: secrets and session identifiers are never allowed.
            for field in &span_fields {
                let name = field.name.rsplit('.').next().unwrap_or(&field.name);
                if is_secret_field(name) {
                    let name = name.to_string();
                    cx.emit_span_lint(
                        SECRET_FIELD_IN_LOG,
                        field.name_span,
                        DiagDecorator(move |diag| {
                            diag.primary_message(format!(
                                "span field `{name}` is named like a secret"
                            ));
                            diag.help(
                                "secrets must never be logged at any level; remove the field",
                            );
                        }),
                    );
                }
                if name == "session_id" || name == "sid" {
                    let name = name.to_string();
                    cx.emit_span_lint(
                        SESSION_ID_IN_LOG,
                        field.name_span,
                        DiagDecorator(move |diag| {
                            diag.primary_message(format!(
                                "span field `{name}` records a session identifier"
                            ));
                            diag.help("session IDs never appear in span fields; drop the field");
                        }),
                    );
                }
            }

            // Skip completeness.
            if skip_all {
                continue;
            }
            for param in params {
                let mut bindings = Vec::new();
                binding_idents(&param.pat, &mut bindings);
                for (name, span) in bindings {
                    if is_sensitive_param(&name) && !skipped.iter().any(|skip| skip == &name) {
                        cx.emit_span_lint(
                            INSTRUMENT_SKIP_SENSITIVE,
                            span,
                            DiagDecorator(move |diag| {
                                diag.primary_message(format!(
                                    "`#[instrument]` records the sensitive argument `{name}`"
                                ));
                                diag.help(format!(
                                    "add `{name}` to the skip list, e.g. `skip(.., {name})`, or use `skip_all`"
                                ));
                            }),
                        );
                    }
                }
            }
        }
    }
}

/// Collect every binding identifier of a parameter pattern (plain `name`,
/// destructuring `State(state)`, `Path((realm, id))`, ...).
fn binding_idents(pat: &ast::Pat, out: &mut Vec<(String, Span)>) {
    match &pat.kind {
        PatKind::Ident(_, ident, sub) => {
            out.push((ident.name.as_str().to_string(), ident.span));
            if let Some(sub) = sub {
                binding_idents(sub, out);
            }
        }
        PatKind::TupleStruct(_, _, pats)
        | PatKind::Tuple(pats)
        | PatKind::Or(pats)
        | PatKind::Slice(pats) => {
            for pat in pats {
                binding_idents(pat, out);
            }
        }
        PatKind::Struct(_, _, fields, _) => {
            for field in fields {
                binding_idents(&field.pat, out);
            }
        }
        PatKind::Ref(pat, _, _)
        | PatKind::Deref(pat)
        | PatKind::Paren(pat)
        | PatKind::Guard(pat, _) => {
            binding_idents(pat, out);
        }
        _ => {}
    }
}

impl EarlyLintPass for IssuerdLogHygiene {
    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &ast::MacCall) {
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.name) else {
            return;
        };
        let Some(level) = Level::from_macro_name(name.as_str()) else {
            return;
        };
        let fields = parse_fields(&mac.args.tokens);
        Self::check_event_fields(cx, level, &fields);
    }

    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &Item) {
        if let ItemKind::Fn(fun) = &item.kind {
            Self::check_fn(cx, &item.attrs, &fun.sig.decl.inputs);
        }
    }

    fn check_impl_item(&mut self, cx: &EarlyContext<'_>, item: &AssocItem) {
        if let AssocItemKind::Fn(fun) = &item.kind {
            Self::check_fn(cx, &item.attrs, &fun.sig.decl.inputs);
        }
    }

    fn check_trait_item(&mut self, cx: &EarlyContext<'_>, item: &AssocItem) {
        if let AssocItemKind::Fn(fun) = &item.kind {
            Self::check_fn(cx, &item.attrs, &fun.sig.decl.inputs);
        }
    }
}

// ---------------------------------------------------------------------------
// Type-aware lints (late pass, on the expanded tracing machinery)
// ---------------------------------------------------------------------------
//
// Ground truth from tracing 0.1.44's macro expansion (verified against
// `-Zunpretty=hir-tree` dumps):
//
// * Every field value becomes an entry of the `&[...]` array handed to
//   `FieldSet::value_set_all`: `Option::Some(&<expr> as &dyn
//   tracing::field::Value)`. The `%`/`?` sigils wrap the value in
//   `tracing::field::display(&x)` / `debug(&x)` first (the fns resolve to
//   `tracing_core::field::*`). The user's value expression keeps its
//   original (non-expansion) span.
// * A message, when present, is prepended as the FIRST value entry —
//   `format_args!(...)`, whose type is `core::fmt::Arguments` — while the
//   matching `"message"` name is a bare literal in the field set (no
//   `FieldName::new` call).
// * The field names live in the callsite statics, one
//   `FieldName::new("...")` per user field, in field order.
// * The event's level appears as a `$crate::Level::WARN` path expression
//   (type `tracing_core::metadata::Level`); events end in
//   `Event::dispatch`, spans in `Span::new`/`Span::child_of`.

/// Lint configuration (workspace-root `dylint.toml`, `[issuerd_log_hygiene]`
/// table; every key optional, these are the defaults).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
struct Config {
    /// Full def paths of ADTs whose values must never be logged.
    secret_types: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            secret_types: [
                "issuerd_core::models::Password",
                "issuerd_core::models::ClientSecret",
                "issuerd_core::models::RefreshToken",
                "issuerd_core::models::Assertion",
                "issuerd_core::models::AuthorizationCode",
                "issuerd_core::models::Credential",
                "issuerd_core::models::StoredSigningKey",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        }
    }
}

impl Config {
    fn load() -> Self {
        dylint_linting::config_or_default(env!("CARGO_PKG_NAME"))
    }
}

rustc_session::impl_lint_pass!(IssuerdLogHygieneLate => [SECRET_TYPED_VALUE_IN_LOG]);

struct IssuerdLogHygieneLate {
    config: Config,
}

impl IssuerdLogHygieneLate {
    fn new(config: Config) -> Self {
        Self { config }
    }

    /// `expr` casts to `&dyn tracing::field::Value`: run lint A immediately
    /// and return nothing (lint B's positional pairing collects through
    /// [`Self::check_value_set_array`] instead).
    fn check_value_cast(&mut self, cx: &LateContext<'_>, expr: &hir::Expr<'_>) {
        let hir::ExprKind::Cast(inner, _) = &expr.kind else {
            return;
        };
        let ty = cx.typeck_results().expr_ty(expr);
        if !is_dyn_tracing_value(cx, ty) {
            return;
        }
        let Some(value) = unwrap_field_value(cx, inner) else {
            return;
        };
        let value_ty = cx.typeck_results().expr_ty(value).peel_refs();
        if let ty::TyKind::Adt(adt, _) = value_ty.kind() {
            let path = canonical_path(cx.tcx, adt.did());
            if self.config.secret_types.iter().any(|secret| *secret == path) {
                cx.emit_span_lint(
                    SECRET_TYPED_VALUE_IN_LOG,
                    value.span,
                    DiagDecorator(move |diag| {
                        diag.primary_message(format!(
                            "value of secret type `{path}` recorded in a log field"
                        ));
                        diag.help(
                            "secret values must never be logged; log an identifier, hash, or length instead",
                        );
                    }),
                );
            }
        }
    }
}

impl<'tcx> LateLintPass<'tcx> for IssuerdLogHygieneLate {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx hir::Expr<'tcx>) {
        self.check_value_cast(cx, expr);
    }
}

/// The canonical `crate::module::Item` path of `did`, built from the
/// definition path — unlike `tcx.def_path_str`, which renders
/// re-export-preferred trimmed paths (`tracing::Value` instead of
/// `tracing_core::field::Value`, `std::fmt::Arguments` instead of
/// `core::fmt::Arguments`) and omits the crate name for local items.
fn canonical_path(tcx: ty::TyCtxt<'_>, did: rustc_span::def_id::DefId) -> String {
    let def_path = tcx.def_path(did);
    let mut path = tcx.crate_name(did.krate).to_string();
    for part in &def_path.data {
        path.push_str("::");
        path.push_str(&part.data.to_string());
    }
    path
}

/// Is `ty` `&dyn tracing::field::Value` (the trait lives in tracing_core)?
fn is_dyn_tracing_value(cx: &LateContext<'_>, ty: ty::Ty<'_>) -> bool {
    let ty::TyKind::Ref(_, inner, _) = ty.kind() else {
        return false;
    };
    let ty::TyKind::Dynamic(preds, ..) = inner.kind() else {
        return false;
    };
    let Some(principal) = preds.principal() else {
        return false;
    };
    canonical_path(cx.tcx, principal.def_id()) == "tracing_core::field::Value"
}

/// Unwrap a `&dyn Value` cast's inner `&<expr>` to the user's value
/// expression, removing the `%`/`?` wrapper (`display(&x)`/`debug(&x)`).
fn unwrap_field_value<'cx, 'tcx>(
    cx: &LateContext<'cx>,
    cast_inner: &'tcx hir::Expr<'tcx>,
) -> Option<&'tcx hir::Expr<'tcx>> {
    let hir::ExprKind::AddrOf(_, _, pointee) = &cast_inner.kind else {
        return None;
    };
    if let hir::ExprKind::Call(func, [arg]) = &pointee.kind {
        if let hir::ExprKind::Path(hir::QPath::Resolved(_, path)) = &func.kind
            && let Res::Def(_, did) = path.res
            && matches!(
                canonical_path(cx.tcx, did).as_str(),
                "tracing_core::field::display" | "tracing_core::field::debug"
            )
        {
            // display(&x) / debug(&x) — the argument is `&x`.
            if let hir::ExprKind::AddrOf(_, _, value) = &arg.kind {
                return Some(value);
            }
            return Some(arg);
        }
    }
    Some(pointee)
}

impl Level {}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}

// The type-aware lints need the real `tracing` macros (the `&dyn
// field::Value` cast shapes only exist post-expansion), so their tests are
// example targets — `ui_test_example` recovers the `--extern`/`--L` flags
// from a real `cargo rustc` build, giving the test crate the lint crate's
// dev-dependencies. `dylint_toml` points the configurable lists at the
// example-local stub types.
#[test]
fn ui_secret_typed_value_in_log() {
    dylint_testing::ui::Test::example(env!("CARGO_PKG_NAME"), "secret_typed_value_in_log")
        .dylint_toml(
            r#"
                [issuerd_log_hygiene]
                secret_types = [
                    "secret_typed_value_in_log::models::Password",
                    "secret_typed_value_in_log::models::Credential",
                ]
            "#,
        )
        .run();
}
