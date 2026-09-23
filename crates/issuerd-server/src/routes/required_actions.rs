// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Required-action continuation: server-rendered pages for post-login required actions.

//! Required-action continuation.
//!
//! When authentication succeeds but the flow result carries required actions
//! (temporary password, unverified email, admin-assigned actions, ...), the
//! user is redirected here before any authorization code or token is minted.
//! Each action renders a minimal server-side page; submissions are routed
//! through the registered [`issuerd_core::RequiredAction::process`]
//! implementations so password-policy and storage logic stay in
//! `issuerd-auth-flow`. Completing the last action finishes the login via
//! [`super::login_api::complete_login`] with the original `auth_time`.
//!
//! State lives in the distributed cache under
//! `pending_actions:{realm}:{execution}` (10-minute TTL), so any cluster node
//! can render the next step. POSTs require the per-flow correlation cookie
//! minted when the continuation starts (login-CSRF protection, same model as
//! the password login POST).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use tracing::{debug, error, info, warn};

use issuerd_core::typestate::{ActionsPending, TypedFlowResult};
use issuerd_core::{
    AuthContext, EventType, IssuerdError, Realm, RealmId, RequiredActionResult, User,
};

use crate::email::{html_escape, render_verify_email_localized, VERIFY_EMAIL_LINK_TTL_SECS};
use crate::middleware::proxy_ip::ClientIp;
use crate::state::ServerState;

use super::login_api::LoginResponse;
use super::oidc::{emit_oidc_event, flow_cookie_header, has_flow_cookie, PendingAuthData};

/// Cache TTL for a paused required-action continuation (matches the pending
/// auth entry TTL).
const PENDING_ACTIONS_TTL_SECS: u64 = 600;

/// Cache key for a paused required-action continuation.
pub(crate) fn pending_actions_cache_key(realm_id: &RealmId, execution: &str) -> String {
    format!("pending_actions:{}:{}", realm_id.0, execution)
}

/// Cache key for a single-use verify-email token.
fn verify_email_cache_key(realm_id: &RealmId, token: &str) -> String {
    format!("verify-email:{}:{}", realm_id.0, token)
}

fn action_required_tag() -> String {
    "action_required".to_string()
}

/// State of a paused login that is working through its required actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingActionsData {
    /// The original authorization request; replayed by
    /// [`super::login_api::complete_login`] once the last action clears.
    pub pending: PendingAuthData,
    pub user_id: String,
    pub session_id: String,
    pub auth_time: chrono::DateTime<chrono::Utc>,
    /// Action ids still to complete, in evaluation order.
    pub remaining_actions: Vec<String>,
    /// VERIFY_EMAIL: set once the message has been sent so re-rendering the
    /// page does not send it again.
    #[serde(default)]
    pub email_sent: bool,
    /// One-shot error banner carried across a POST→redirect (PRG pattern).
    #[serde(default)]
    pub error: Option<String>,
    /// CONFIGURE_TOTP enrollment secret (base32), generated on first page
    /// render and carried here — never persisted to storage; the credential
    /// is created only after the user proves control with a valid code.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Execute-actions continuation: admin-chosen page to send the
    /// browser to once every action clears. `Some` marks the continuation as
    /// *not* backed by an OIDC login — [`finish_continuation`] redirects there
    /// instead of completing a login.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Typestate marker for cache round-trips.
    #[serde(default = "action_required_tag")]
    pub _typestate_tag: String,
}

/// Percent-encode a realm name for safe embedding in a URL path segment.
pub(crate) fn url_path_segment(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes()).collect()
}

fn continuation_url(realm_name: &str, execution: &str) -> String {
    format!("/realms/{}/login/required-action/{execution}", url_path_segment(realm_name))
}

/// Start the required-action continuation: store the paused state and
/// redirect the browser to the first action page.
///
/// Called from both login completion points (password login POST and the
/// authorize endpoint's SSO/cookie path) when the flow succeeded with
/// `result.required_actions` non-empty.
pub(crate) async fn begin_actions_continuation(
    state: &Arc<ServerState>,
    realm_name: &str,
    pending: PendingAuthData,
    result: TypedFlowResult<ActionsPending>,
    is_browser_form: bool,
) -> Response {
    debug!(
        realm = %pending.realm_id,
        user_id = %result.user_id,
        actions = ?result.required_actions,
        "authentication succeeded with required actions pending"
    );
    let realm_id = match RealmId::new(pending.realm_id.clone()) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
    };
    let flow_id = issuerd_core::utils::generate_id();
    let entry = PendingActionsData {
        user_id: result.user_id.0.clone(),
        session_id: result.session_id.0.clone(),
        auth_time: result.auth_time,
        remaining_actions: result.required_actions.clone(),
        pending,
        email_sent: false,
        error: None,
        totp_secret: None,
        redirect_uri: None,
        _typestate_tag: action_required_tag(),
    };
    dispatch_actions_continuation(state, realm_name, &realm_id, &flow_id, entry, is_browser_form)
        .await
}

/// Store the paused continuation and redirect the browser to its first action
/// page (or, for SPA logins, answer with the continuation URL).
///
/// Split from [`begin_actions_continuation`] so the execute-actions endpoint
/// can dispatch a hand-built entry carrying a `redirect_uri`.
pub(crate) async fn dispatch_actions_continuation(
    state: &Arc<ServerState>,
    realm_name: &str,
    realm_id: &RealmId,
    flow_id: &str,
    entry: PendingActionsData,
    is_browser_form: bool,
) -> Response {
    let state_param = entry.pending.state.clone();
    // Serialization cannot fail: every field is a plain String/Option/Vec.
    let bytes = serde_json::to_vec(&entry).unwrap();
    let _ = state
        .cache
        .set(
            &pending_actions_cache_key(realm_id, flow_id),
            bytes,
            Some(Duration::from_secs(PENDING_ACTIONS_TTL_SECS)),
        )
        .await;

    let url = continuation_url(realm_name, flow_id);
    let cookie = flow_cookie_header(flow_id);
    if is_browser_form {
        let mut resp = Redirect::to(&url).into_response();
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
        }
        resp
    } else {
        // SPA login: the client navigates to `redirect_uri` itself.
        (
            [(axum::http::header::SET_COOKIE, cookie)],
            axum::Json(LoginResponse {
                redirect_uri: url,
                code: None,
                id_token: None,
                state: state_param,
            }),
        )
            .into_response()
    }
}

async fn store_entry(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    execution: &str,
    entry: &PendingActionsData,
) {
    let bytes = serde_json::to_vec(entry).unwrap();
    let _ = state
        .cache
        .set(
            &pending_actions_cache_key(realm_id, execution),
            bytes,
            Some(Duration::from_secs(PENDING_ACTIONS_TTL_SECS)),
        )
        .await;
}

// ---------------------------------------------------------------------------
// HTML pages (minimal, server-rendered; every dynamic value is escaped)
// ---------------------------------------------------------------------------

const PAGE_CSS: &str = "\
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;}\
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:32px 40px;\
width:100%;max-width:420px;box-sizing:border-box;}\
h1{font-size:20px;margin:0 0 8px 0;}\
p{font-size:14px;line-height:1.5;color:#334155;}\
label{display:block;font-size:13px;font-weight:bold;margin:16px 0 4px 0;}\
input[type=text],input[type=password],input[type=email]{width:100%;box-sizing:border-box;\
padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px;}\
button{margin-top:20px;width:100%;padding:10px 0;background:#2563eb;color:#fff;border:0;\
border-radius:6px;font-size:14px;font-weight:bold;cursor:pointer;}\
button.secondary{background:#e2e8f0;color:#0f172a;}\
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;border-radius:6px;\
padding:10px 12px;font-size:13px;margin:12px 0;}\
.checkbox{display:flex;align-items:flex-start;gap:8px;margin-top:16px;font-size:13px;}\
.checkbox input{margin-top:2px;}\
.otp-row{display:flex;gap:8px;margin-top:4px;}\
.otp-row .otp-digit{flex:1 1 0;min-width:0;height:52px;padding:0;text-align:center;\
font-size:22px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;outline:none;}\
.otp-row .otp-digit:focus{border-color:#2563eb;box-shadow:0 0 0 2px rgba(37,99,235,.25);}\
";

pub(crate) fn page(title: &str, body: &str) -> Html<String> {
    let mut html = String::with_capacity(PAGE_CSS.len() + title.len() + body.len() + 256);
    html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>");
    html.push_str(&html_escape(title));
    html.push_str("</title><style>");
    html.push_str(PAGE_CSS);
    html.push_str("</style></head><body><main class=\"card\">");
    html.push_str(body);
    html.push_str("</main></body></html>");
    Html(html)
}

pub(crate) fn error_banner(error: Option<&str>) -> String {
    match error {
        Some(e) => format!("<p class=\"error\">{}</p>", html_escape(e)),
        None => String::new(),
    }
}

pub(crate) fn error_response(status: StatusCode, msg: &str) -> Response {
    (
        status,
        page(
            "Sign-in error",
            &format!("<h1>Sign-in error</h1><p class=\"error\">{}</p>", html_escape(msg)),
        ),
    )
        .into_response()
}

/// Render the OTP second-factor challenge page. The form re-POSTs
/// to the login endpoint with the hidden browser flow id and the one-time
/// code; a wrong code re-renders this page with the error banner.
pub(crate) fn otp_challenge_page(realm_name: &str, flow_id: &str, error: Option<&str>) -> Response {
    let mut action = url::form_urlencoded::Serializer::new(String::new());
    action.append_pair("realm", realm_name);
    let action = format!("/api/v1/auth/login?{}", action.finish());
    let banner = error_banner(error);
    let flow_id = html_escape(flow_id);
    let body = format!(
        "<h1>Two-factor authentication</h1>\
         <p>Enter the one-time code from your authenticator app to continue.</p>\
         {banner}\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"execution_id\" value=\"{flow_id}\">\
         <label for=\"otp\">One-time code</label>\
         <input type=\"text\" id=\"otp\" name=\"otp\" inputmode=\"numeric\" pattern=\"[0-9]*\" \
         autocomplete=\"one-time-code\" autofocus required>\
         <button type=\"submit\">Sign in</button>\
         </form>"
    );
    page("Two-factor authentication", &body).into_response()
}

/// Inline script for the email-code challenge page. Keeps the digit boxes in
/// sync with the hidden `otp` field the form actually submits: typing
/// advances focus, Backspace retreats, and paste or iOS one-time-code
/// autofill (which drops the whole code into the first box in a single
/// `input` event) is distributed across the boxes. A complete code submits
/// the form immediately. Self-contained: no external resources.
const EMAIL_CODE_CHALLENGE_SCRIPT: &str = r#"(function(){
var boxes=Array.prototype.slice.call(document.querySelectorAll(".otp-digit"));
var hidden=document.getElementById("otp-value");
var form=document.getElementById("code-form");
hidden.disabled=false;
function digits(s){return s.replace(/[^0-9]/g,"");}
function sync(){
hidden.value=boxes.map(function(b){return b.value;}).join("");
if(boxes.every(function(b){return /^[0-9]$/.test(b.value);})){form.submit();}}
function distribute(start,str){
var d=digits(str);
for(var i=0;i<d.length&&start+i<boxes.length;i++){boxes[start+i].value=d.charAt(i);}
boxes[Math.min(start+d.length,boxes.length-1)].focus();
sync();}
boxes.forEach(function(box,i){
box.addEventListener("input",function(){
var d=digits(box.value);
if(d.length>1){distribute(i,d);return;}
box.value=d;
if(d&&i<boxes.length-1){boxes[i+1].focus();}
sync();});
box.addEventListener("keydown",function(e){
if(e.key==="Backspace"&&!box.value&&i>0){
boxes[i-1].focus();boxes[i-1].value="";sync();e.preventDefault();}});
box.addEventListener("paste",function(e){
e.preventDefault();
distribute(i,(e.clipboardData||window.clipboardData).getData("text"));});
box.addEventListener("focus",function(){box.select();});
});
})();
"#;

/// Render the email-code challenge page (passwordless login). The first form
/// re-POSTs to the login endpoint with the hidden browser flow id and the
/// one-time code; a wrong code re-renders this page with the error banner.
/// The code is entered into `code_length` individual outlined digit boxes
/// wired by [`EMAIL_CODE_CHALLENGE_SCRIPT`] into the hidden `otp` field; the
/// first box carries `autocomplete="one-time-code"` so iOS offers the code
/// it parsed from the incoming mail (iOS 17+) or SMS in the QuickType bar.
/// Without JavaScript the `<noscript>` fallback renders the classic single
/// input (the hidden `otp` field stays disabled and is not submitted).
/// The second form posts `resend=1` to mail a fresh code. `masked_email` is
/// the partially hidden destination address; `None` when the entered address
/// resolved to no account (the page then stays deliberately vague).
pub(crate) fn email_code_challenge_page(
    realm_name: &str,
    flow_id: &str,
    masked_email: Option<&str>,
    error: Option<&str>,
    code_length: usize,
) -> Response {
    let mut action = url::form_urlencoded::Serializer::new(String::new());
    action.append_pair("realm", realm_name);
    let action = format!("/api/v1/auth/login?{}", action.finish());
    let banner = error_banner(error);
    let flow_id = html_escape(flow_id);
    let lead = match masked_email {
        Some(masked) => {
            format!(
                "We sent a {code_length}-digit code to <strong>{}</strong>.",
                html_escape(masked)
            )
        }
        None => format!("Enter the {code_length}-digit code we sent to your email address."),
    };
    let mut boxes = String::with_capacity(code_length * 160);
    for i in 1..=code_length {
        let first = if i == 1 {
            " id=\"otp\" autocomplete=\"one-time-code\" autofocus"
        } else {
            ""
        };
        boxes.push_str(&format!(
            "<input type=\"text\" class=\"otp-digit\"{first} inputmode=\"numeric\" \
             pattern=\"[0-9]*\" aria-label=\"Code digit {i}\">"
        ));
    }
    let body = format!(
        "<h1>Check your email</h1>\
         <p>{lead}</p>\
         {banner}\
         <form method=\"post\" action=\"{action}\" id=\"code-form\">\
         <input type=\"hidden\" name=\"execution_id\" value=\"{flow_id}\">\
         <input type=\"hidden\" name=\"otp\" id=\"otp-value\" disabled>\
         <label for=\"otp\">One-time code</label>\
         <div class=\"otp-row\">{boxes}</div>\
         <noscript><style>.otp-row{{display:none}}</style>\
         <input type=\"text\" name=\"otp\" inputmode=\"numeric\" pattern=\"[0-9]*\" \
         autocomplete=\"one-time-code\" required></noscript>\
         <button type=\"submit\">Sign in</button>\
         </form>\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"execution_id\" value=\"{flow_id}\">\
         <input type=\"hidden\" name=\"resend\" value=\"1\">\
         <button type=\"submit\" class=\"secondary\">Resend code</button>\
         </form>\
         <script>{EMAIL_CODE_CHALLENGE_SCRIPT}</script>"
    );
    page("Check your email", &body).into_response()
}

/// Inline script for the WebAuthn challenge page. Drives
/// `navigator.credentials.get` with the embedded request options and
/// auto-submits the assertion as a hidden form field back to the login
/// endpoint. `__OPTIONS__` is replaced with the options JSON (every `<`
/// escaped as a JSON unicode escape so the payload can never break out of
/// the script element). Self-contained: no external resources.
const WEBAUTHN_CHALLENGE_SCRIPT: &str = r#"const options=__OPTIONS__;
function b64d(s){const b=atob(s.replace(/-/g,"+").replace(/_/g,"/"));
const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
function b64e(buf){const a=new Uint8Array(buf);let s="";
for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);
return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
async function run(){
const st=document.getElementById("status");
st.textContent="Waiting for your passkey\u2026";
document.getElementById("retry").style.display="none";
try{
const pk=options;
pk.challenge=b64d(pk.challenge);
if(pk.allowCredentials){for(const c of pk.allowCredentials){c.id=b64d(c.id);}}
const cred=await navigator.credentials.get({publicKey:pk});
const assertion={id:cred.id,rawId:b64e(cred.rawId),type:cred.type,response:{
authenticatorData:b64e(cred.response.authenticatorData),
clientDataJSON:b64e(cred.response.clientDataJSON),
signature:b64e(cred.response.signature),
userHandle:cred.response.userHandle?b64e(cred.response.userHandle):null}};
document.getElementById("webauthn_assertion").value=JSON.stringify(assertion);
document.getElementById("waform").submit();
}catch(e){
st.textContent="Passkey authentication failed: "+(e&&e.message?e.message:e);
document.getElementById("retry").style.display="block";
}}
run();
"#;

/// Render the WebAuthn second-factor challenge page. The inline
/// script runs the ceremony immediately; a rejected assertion re-renders
/// this page with fresh options and the error banner, and client-side
/// failures surface a "Try again" button that re-runs the ceremony.
pub(crate) fn webauthn_challenge_page(
    realm_name: &str,
    flow_id: &str,
    options_json: &str,
    error: Option<&str>,
) -> Response {
    let mut action = url::form_urlencoded::Serializer::new(String::new());
    action.append_pair("realm", realm_name);
    let action = format!("/api/v1/auth/login?{}", action.finish());
    let banner = error_banner(error);
    let flow_id = html_escape(flow_id);
    // Escape `<` inside the embedded JSON so a crafted value can never close
    // the script element (a JSON unicode escape remains valid JSON).
    let options = options_json.replace('<', "\\u003c");
    let script = WEBAUTHN_CHALLENGE_SCRIPT.replace("__OPTIONS__", &options);
    let body = format!(
        "<h1>Sign in with your passkey</h1>\
         <p id=\"status\">Use your passkey to continue.</p>\
         {banner}\
         <form id=\"waform\" method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"execution_id\" value=\"{flow_id}\">\
         <input type=\"hidden\" id=\"webauthn_assertion\" name=\"webauthn_assertion\" value=\"\">\
         </form>\
         <button id=\"retry\" class=\"secondary\" style=\"display:none\" \
         onclick=\"run();return false;\">Try again</button>\
         <script>{script}</script>"
    );
    page("Sign in with your passkey", &body).into_response()
}

/// Render the CONFIGURE_TOTP enrollment page: QR code + manual setup key +
/// verification form. `secret_b32` is the pending enrollment secret carried
/// in the continuation entry (never persisted until a code verifies).
fn render_configure_totp_page(
    realm_name: &str,
    execution: &str,
    realm: &Realm,
    user: &User,
    secret_b32: &str,
    error: Option<&str>,
) -> Response {
    let url = continuation_url(realm_name, execution);
    let banner = error_banner(error);
    let issuer = realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str());
    let otpauth = issuerd_auth_flow::totp::otpauth_url(
        issuer,
        user.username.as_str(),
        secret_b32,
        &realm.otp_policy,
    );
    // Locally generated SVG — contains only qrcodegen-produced markup.
    let qr = crate::qr::qr_svg(&otpauth).unwrap_or_default();
    // Group the base32 secret in chunks of 4 for readability.
    let grouped = secret_b32
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    let secret = html_escape(&grouped);
    let otpauth_link = html_escape(&otpauth);
    let body = format!(
        "<h1>Configure authenticator app</h1>\
         <p>Scan the QR code with your authenticator app (or enter the setup key \
         manually), then enter the one-time code it shows to finish setup.</p>\
         {banner}\
         <div style=\"text-align:center;margin:12px 0;\">{qr}</div>\
         <p style=\"text-align:center;\"><code style=\"font-size:16px;\
         letter-spacing:1px;\">{secret}</code></p>\
         <p style=\"word-break:break-all;\"><a href=\"{otpauth_link}\">\
         Open in authenticator app</a></p>\
         <form method=\"post\" action=\"{url}\">\
         <label for=\"totp_code\">One-time code</label>\
         <input type=\"text\" id=\"totp_code\" name=\"totp_code\" inputmode=\"numeric\" \
         autocomplete=\"one-time-code\" required>\
         <button type=\"submit\">Finish setup</button>\
         </form>"
    );
    page("Configure authenticator app", &body).into_response()
}

fn render_action_page(
    realm_name: &str,
    execution: &str,
    action: &str,
    error: Option<&str>,
    prefill: Option<&User>,
) -> Response {
    let url = continuation_url(realm_name, execution);
    let banner = error_banner(error);
    let body = match action {
        "UPDATE_PASSWORD" => format!(
            "<h1>Update your password</h1>\
             <p>You must set a new password before you can continue.</p>\
             {banner}\
             <form method=\"post\" action=\"{url}\">\
             <label for=\"new_password\">New password</label>\
             <input type=\"password\" id=\"new_password\" name=\"new_password\" \
             autocomplete=\"new-password\" required>\
             <label for=\"confirm_password\">Confirm password</label>\
             <input type=\"password\" id=\"confirm_password\" name=\"confirm_password\" \
             autocomplete=\"new-password\" required>\
             <button type=\"submit\">Update password</button>\
             </form>"
        ),
        "UPDATE_PROFILE" => {
            let (email, first, last) = match prefill {
                Some(u) => (
                    u.email.as_ref().map(|e| e.as_str()).unwrap_or(""),
                    u.first_name.as_ref().map(|n| n.as_str()).unwrap_or(""),
                    u.last_name.as_ref().map(|n| n.as_str()).unwrap_or(""),
                ),
                None => ("", "", ""),
            };
            format!(
                "<h1>Update your profile</h1>\
                 <p>Please review your account details before you continue.</p>\
                 {banner}\
                 <form method=\"post\" action=\"{url}\">\
                 <label for=\"email\">Email</label>\
                 <input type=\"email\" id=\"email\" name=\"email\" value=\"{}\">\
                 <label for=\"first_name\">First name</label>\
                 <input type=\"text\" id=\"first_name\" name=\"first_name\" value=\"{}\">\
                 <label for=\"last_name\">Last name</label>\
                 <input type=\"text\" id=\"last_name\" name=\"last_name\" value=\"{}\">\
                 <button type=\"submit\">Save</button>\
                 </form>",
                html_escape(email),
                html_escape(first),
                html_escape(last)
            )
        }
        "TERMS_AND_CONDITIONS" => format!(
            "<h1>Terms and conditions</h1>\
             <p>You must accept the terms and conditions to continue.</p>\
             {banner}\
             <form method=\"post\" action=\"{url}\">\
             <label class=\"checkbox\" for=\"terms_accepted\">\
             <input type=\"checkbox\" id=\"terms_accepted\" name=\"terms_accepted\" value=\"true\">\
             <span>I accept the terms and conditions of this service.</span></label>\
             <button type=\"submit\">Continue</button>\
             </form>"
        ),
        "VERIFY_EMAIL" => format!(
            "<h1>Verify your email address</h1>\
             <p>We sent you an email with a verification link. Open the link to \
             verify your address, then continue here.</p>\
             {banner}\
             <form method=\"post\" action=\"{url}\">\
             <button type=\"submit\">I have verified &mdash; continue</button>\
             </form>\
             <form method=\"post\" action=\"{url}\">\
             <input type=\"hidden\" name=\"resend\" value=\"true\">\
             <button type=\"submit\" class=\"secondary\">Resend email</button>\
             </form>"
        ),
        // Unknown actions are skipped before rendering; this is unreachable.
        other => format!("<h1>Unsupported action</h1><p>{}</p>", html_escape(other)),
    };
    let title = match action {
        "UPDATE_PASSWORD" => "Update password",
        "UPDATE_PROFILE" => "Update profile",
        "TERMS_AND_CONDITIONS" => "Terms and conditions",
        "VERIFY_EMAIL" => "Verify email",
        _ => "Action required",
    };
    page(title, &body).into_response()
}

// ---------------------------------------------------------------------------
// Verify-email sending
// ---------------------------------------------------------------------------

/// Send the verification email and store its single-use token
/// (`verify-email:{realm}:{token}` → user id, 24 h TTL).
///
/// `execution` is the paused required-action continuation the link should
/// resume; pass `None` when there is no login in flight (self-registration)
/// and the link then renders a plain "continue to login" page instead.
/// `login_execution` is the paused browser-login flow a registration was
/// started from: the standalone success page then points "continue to
/// sign-in" back into that flow, so the user lands on the originating app
/// rather than the account console.
pub(crate) async fn send_verification_email(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    user: &User,
    execution: Option<&str>,
    login_execution: Option<&str>,
) -> Result<(), IssuerdError> {
    let email = user.email.as_ref().ok_or_else(|| {
        IssuerdError::InvalidRequest("no email address on file for this account".to_string())
    })?;
    let token = issuerd_core::utils::generate_id();
    state
        .cache
        .set(
            &verify_email_cache_key(&realm.id, &token),
            user.id.0.clone().into_bytes(),
            Some(Duration::from_secs(VERIFY_EMAIL_LINK_TTL_SECS as u64)),
        )
        .await?;
    let issuer = state.config.issuer_url.trim_end_matches('/');
    let mut link = format!(
        "{issuer}/realms/{}/login/verify-email?token={token}",
        url_path_segment(realm_name)
    );
    if let Some(execution) = execution {
        link.push_str("&execution=");
        link.push_str(&url_path_segment(execution));
    }
    if let Some(login_execution) = login_execution {
        link.push_str("&login_execution=");
        link.push_str(&url_path_segment(login_execution));
    }
    let realm_display =
        realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str());
    let user_display =
        user.first_name.as_ref().map(|n| n.as_str()).unwrap_or(user.username.as_str());
    let locale = crate::i18n::user_locale(realm, user);
    let bundle = crate::i18n::message_bundle(
        Some(state.config.themes.dir.as_path()),
        realm.email_theme.as_ref().map(|t| t.as_str()),
        &locale,
    );
    let rendered = render_verify_email_localized(
        realm_display,
        user_display,
        &link,
        VERIFY_EMAIL_LINK_TTL_SECS / 60,
        &bundle,
    );
    state
        .email_sender
        .send(realm, email.as_str(), &rendered.subject, &rendered.text, Some(rendered.html))
        .await
}

/// Remove a completed action assignment from the user record so it does not
/// re-trigger at the next login. Best-effort: the continuation list is the
/// source of truth for the in-flight flow.
async fn clear_action_assignment(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: &issuerd_core::UserId,
    action: &str,
) {
    if let Ok(Some(mut user)) = state.storage.get_user(realm_id, user_id).await {
        if user.required_actions.iter().any(|a| a == action) {
            user.required_actions.retain(|a| a != action);
            let _ = state.storage.update_user(realm_id, &user).await;
            issuerd_cluster::invalidate::invalidate_user_claims(
                state.cache.as_ref(),
                realm_id,
                user_id,
            )
            .await;
        }
    }
}

/// Emit an audit event for a completed action (password/profile/email).
async fn emit_action_event(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    entry: &PendingActionsData,
    action: &str,
) {
    let event_name = match action {
        "UPDATE_PASSWORD" => Some("update_password"),
        "UPDATE_PROFILE" => Some("update_profile"),
        "VERIFY_EMAIL" => Some("verify_email"),
        _ => None,
    };
    let Some(name) = event_name else { return };
    let ip = entry.pending.ip_address.unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let user_id = issuerd_core::UserId::new(entry.user_id.clone()).ok();
    let mut details = HashMap::new();
    details.insert("action".to_string(), action.to_string());
    emit_oidc_event(
        state,
        realm_id,
        EventType::Custom(name.to_string()),
        &ip,
        None,
        user_id,
        None,
        None,
        details,
    )
    .await;
}

/// Map form fields to the parameter keys the action's `process()` expects,
/// filtering out anything else the browser submitted.
fn form_params(action: &str, form: &HashMap<String, String>) -> HashMap<String, Vec<String>> {
    let keys: &[&str] = match action {
        "UPDATE_PASSWORD" => &["new_password", "confirm_password"],
        "UPDATE_PROFILE" => &["first_name", "last_name", "email"],
        "TERMS_AND_CONDITIONS" => &["terms_accepted"],
        "CONFIGURE_TOTP" => &["totp_code"],
        _ => &[],
    };
    keys.iter()
        .filter_map(|k| form.get(*k).map(|v| (k.to_string(), vec![v.clone()])))
        .collect()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET `/realms/{realm}/login/required-action/{execution}` — render the page
/// for the next pending action, or complete the login when none remain.
///
/// When the request does not carry the flow correlation cookie (the user
/// opened the verification link in a different browser or device than the
/// one that started the login), the cookie is re-minted on the response so
/// the follow-up POST from this browser is accepted. This does not weaken
/// the login-CSRF protection: the cookie is `SameSite=Lax`, so a cross-site
/// POST never carries it — only a browser that navigated to the continuation
/// URL (i.e. possesses the execution id) can submit.
pub async fn required_action_page(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, execution)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let mint_cookie = !has_flow_cookie(&headers, &execution);
    let mut resp = required_action_page_inner(state, realm_name, execution.clone()).await;
    if mint_cookie {
        if let Ok(v) = HeaderValue::from_str(&flow_cookie_header(&execution)) {
            resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
        }
    }
    resp
}

async fn required_action_page_inner(
    state: Arc<ServerState>,
    realm_name: String,
    execution: String,
) -> Response {
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    let realm_id = realm.id.clone();
    let key = pending_actions_cache_key(&realm_id, &execution);
    let entry: Option<PendingActionsData> = match state.cache.get(&key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    };
    let mut entry = match entry {
        Some(e) if e.pending.realm_id == realm_id.0 => e,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Your sign-in session has expired. Please go back and sign in again.",
            );
        }
    };

    // Work through the remaining list: completed/unknown actions are dropped
    // until a renderable action is found or the login can finish.
    loop {
        let Some(action) = entry.remaining_actions.first().cloned() else {
            return finish_continuation(&state, &realm_id, &entry).await;
        };
        match action.as_str() {
            "VERIFY_EMAIL" => {
                let user_id = match issuerd_core::UserId::new(entry.user_id.clone()) {
                    Ok(id) => id,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid session."),
                };
                let user = match state.storage.get_user(&realm_id, &user_id).await {
                    Ok(Some(u)) => u,
                    _ => return error_response(StatusCode::BAD_REQUEST, "Account not found."),
                };
                if user.email_verified {
                    // Verified via the email link (possibly in another tab).
                    entry.remaining_actions.remove(0);
                    store_entry(&state, &realm_id, &execution, &entry).await;
                    continue;
                }
                if !entry.email_sent {
                    match send_verification_email(
                        &state,
                        &realm,
                        &realm_name,
                        &user,
                        Some(&execution),
                        None,
                    )
                    .await
                    {
                        Ok(()) => {
                            entry.email_sent = true;
                            entry.error = None;
                        }
                        Err(e) => {
                            error!(realm = %realm_id, error = %e, "failed to send verification email");
                            entry.error = Some(format!(
                                "Could not send the verification email: {e}. \
                                 Try resending, or contact your administrator."
                            ));
                        }
                    }
                    store_entry(&state, &realm_id, &execution, &entry).await;
                }
                return render_action_page(
                    &realm_name,
                    &execution,
                    "VERIFY_EMAIL",
                    entry.error.as_deref(),
                    None,
                );
            }
            "UPDATE_PASSWORD" | "TERMS_AND_CONDITIONS" => {
                let error = entry.error.take();
                store_entry(&state, &realm_id, &execution, &entry).await;
                return render_action_page(
                    &realm_name,
                    &execution,
                    &action,
                    error.as_deref(),
                    None,
                );
            }
            "UPDATE_PROFILE" => {
                let user_id = match issuerd_core::UserId::new(entry.user_id.clone()) {
                    Ok(id) => id,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid session."),
                };
                let user = state.storage.get_user(&realm_id, &user_id).await.ok().flatten();
                let error = entry.error.take();
                store_entry(&state, &realm_id, &execution, &entry).await;
                return render_action_page(
                    &realm_name,
                    &execution,
                    &action,
                    error.as_deref(),
                    user.as_ref(),
                );
            }
            "CONFIGURE_TOTP" => {
                let user_id = match issuerd_core::UserId::new(entry.user_id.clone()) {
                    Ok(id) => id,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid session."),
                };
                let user = match state.storage.get_user(&realm_id, &user_id).await {
                    Ok(Some(u)) => u,
                    _ => return error_response(StatusCode::BAD_REQUEST, "Account not found."),
                };
                // First render of the enrollment page mints the pending
                // secret; re-renders (and failed codes) reuse it.
                if entry.totp_secret.is_none() {
                    entry.totp_secret = Some(issuerd_auth_flow::totp::generate_secret());
                }
                let secret = entry.totp_secret.clone().unwrap_or_default();
                let error = entry.error.take();
                store_entry(&state, &realm_id, &execution, &entry).await;
                return render_configure_totp_page(
                    &realm_name,
                    &execution,
                    &realm,
                    &user,
                    &secret,
                    error.as_deref(),
                );
            }
            other => {
                // Unknown action ids: never block the login on a page this
                // server cannot render.
                warn!(action = other, "skipping unsupported required action");
                entry.remaining_actions.remove(0);
                store_entry(&state, &realm_id, &execution, &entry).await;
            }
        }
    }
}

/// POST `/realms/{realm}/login/required-action/{execution}` — process one
/// action submission, then redirect back to GET (Post/Redirect/Get).
pub async fn required_action_submit(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, execution)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The continuation POST must carry the correlation cookie minted when the
    // continuation started (login-CSRF protection).
    if !has_flow_cookie(&headers, &execution) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid or expired sign-in flow.");
    }
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    let realm_id = realm.id.clone();

    // Consume the entry atomically; it is re-stored below unless the login
    // completes.
    let key = pending_actions_cache_key(&realm_id, &execution);
    let entry: Option<PendingActionsData> = match state.cache.get_and_delete(&key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    };
    let mut entry = match entry {
        Some(e) if e.pending.realm_id == realm_id.0 => e,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Your sign-in session has expired. Please go back and sign in again.",
            );
        }
    };
    let redirect_back = || Redirect::to(&continuation_url(&realm_name, &execution)).into_response();

    let Some(action) = entry.remaining_actions.first().cloned() else {
        return finish_continuation(&state, &realm_id, &entry).await;
    };

    let form: HashMap<String, String> = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    // VERIFY_EMAIL has no real form input: "resend" re-sends the mail,
    // anything else just re-checks the verification state via `process`.
    if action == "VERIFY_EMAIL" && form.get("resend").is_some_and(|v| v == "true") {
        let user_id = issuerd_core::UserId::new(entry.user_id.clone());
        let user = match &user_id {
            Ok(id) => state.storage.get_user(&realm_id, id).await.ok().flatten(),
            Err(_) => None,
        };
        entry.error = match user {
            Some(u) => {
                match send_verification_email(
                    &state,
                    &realm,
                    &realm_name,
                    &u,
                    Some(&execution),
                    None,
                )
                .await
                {
                    Ok(()) => {
                        entry.email_sent = true;
                        None
                    }
                    Err(e) => Some(format!("Could not resend the verification email: {e}")),
                }
            }
            None => Some("Account not found.".to_string()),
        };
        store_entry(&state, &realm_id, &execution, &entry).await;
        return redirect_back();
    }

    let user_id = match issuerd_core::UserId::new(entry.user_id.clone()) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid session."),
    };
    let action_impl = match state.plugin_registry.get_required_action(&action).await {
        Ok(Some(a)) => a,
        _ => {
            warn!(action = %action, "required action not registered; skipping");
            entry.remaining_actions.remove(0);
            store_entry(&state, &realm_id, &execution, &entry).await;
            return redirect_back();
        }
    };

    let mut ctx = AuthContext {
        realm_id: realm_id.clone(),
        client_id: None,
        user_id: Some(user_id.clone()),
        session_id: None,
        ip_address: entry.pending.ip_address,
        parameters: form_params(&action, &form),
        attributes: HashMap::new(),
        current_challenge: None,
    };
    // CONFIGURE_TOTP: hand the pending enrollment secret (carried in the
    // continuation entry, never persisted) to the action's process().
    if action == "CONFIGURE_TOTP" {
        if let Some(ref secret) = entry.totp_secret {
            ctx.attributes.insert("totp_secret".to_string(), secret.clone());
        }
    }

    match action_impl.process(&mut ctx).await {
        RequiredActionResult::Success => {
            emit_action_event(&state, &realm_id, &entry, &action).await;
            clear_action_assignment(&state, &realm_id, &user_id, &action).await;
            entry.remaining_actions.remove(0);
            entry.error = None;
            // Hygiene: a consumed enrollment secret must not linger in the
            // continuation entry.
            entry.totp_secret = None;
        }
        RequiredActionResult::Challenge(_) => {
            // Missing/invalid form input (or email not yet verified).
            if action == "TERMS_AND_CONDITIONS" {
                entry.error =
                    Some("You must accept the terms and conditions to continue.".to_string());
            }
        }
        RequiredActionResult::Failure(e) => {
            entry.error = Some(e.to_string());
        }
    }

    if entry.remaining_actions.is_empty() {
        return finish_continuation(&state, &realm_id, &entry).await;
    }
    store_entry(&state, &realm_id, &execution, &entry).await;
    redirect_back()
}

/// GET `/realms/{realm}/login/verify-email?token=...[&execution=...]` — the
/// link target from the verification email. Single-use token; marks the
/// email verified and drops VERIFY_EMAIL from the paused continuation.
///
/// The `execution` parameter is optional: links sent during a login carry it
/// (and resume that continuation), links sent after self-registration do not
/// (there is no login in flight) and render a plain "continue to login" page.
pub async fn verify_email_handler(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(token) = query.get("token") else {
        return error_response(StatusCode::BAD_REQUEST, "Invalid verification link.");
    };
    let execution = query.get("execution");
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    let realm_id = realm.id.clone();

    let token_key = verify_email_cache_key(&realm_id, token);
    let user_id_bytes = match state.cache.get_and_delete(&token_key).await {
        Ok(Some(b)) => b,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "This verification link is invalid or has expired. \
                 Sign in again to request a new one.",
            );
        }
    };
    let user_id = match String::from_utf8(user_id_bytes)
        .ok()
        .and_then(|s| issuerd_core::UserId::new(s).ok())
    {
        Some(id) => id,
        None => return error_response(StatusCode::BAD_REQUEST, "Invalid verification token."),
    };

    let user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(mut u)) => {
            u.email_verified = true;
            u.required_actions.retain(|a| a != "VERIFY_EMAIL");
            match state.storage.update_user(&realm_id, &u).await {
                Ok(()) => {
                    issuerd_cluster::invalidate::invalidate_user_claims(
                        state.cache.as_ref(),
                        &realm_id,
                        &user_id,
                    )
                    .await;
                    Some(u)
                }
                Err(e) => {
                    error!(realm = %realm_id, user_id = %user_id, error = %e,
                        "verify-email: failed to persist verified flag");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Could not verify the email address. Please try again.",
                    );
                }
            }
        }
        _ => None,
    };
    if user.is_none() {
        return error_response(StatusCode::BAD_REQUEST, "Account not found.");
    }

    // No required-action continuation in flight (self-registration): render
    // the plain success page. A registration started from an app's login flow
    // threads that paused execution here (`login_execution` on the link), so
    // "continue to sign-in" returns the user to that flow — and the app —
    // instead of the account console.
    let Some(execution) = execution else {
        info!(realm = %realm_id, user_id = %user_id, "email verified via link");
        let mut login_url = url::form_urlencoded::Serializer::new(String::new());
        login_url.append_pair("realm", &realm_name);
        if let Some(login_execution) = query.get("login_execution") {
            login_url.append_pair("execution_id", login_execution);
        }
        let login_url = login_url.finish();
        return page(
            "Email verified",
            &format!(
                "<h1>Email address verified</h1>\
                 <p>Your email address has been verified successfully. \
                 You can now sign in to your account.</p>\
                 <p><a href=\"/login.html?{login_url}\">Continue to sign-in</a></p>"
            ),
        )
        .into_response();
    };

    // Drop VERIFY_EMAIL from the paused continuation (if it is still there),
    // so the continuation page advances by itself on the next render.
    let entry_key = pending_actions_cache_key(&realm_id, execution);
    if let Ok(Some(bytes)) = state.cache.get(&entry_key).await {
        if let Ok(mut entry) = serde_json::from_slice::<PendingActionsData>(&bytes) {
            if entry.remaining_actions.iter().any(|a| a == "VERIFY_EMAIL") {
                entry.remaining_actions.retain(|a| a != "VERIFY_EMAIL");
                let ip = entry.pending.ip_address.unwrap_or_else(|| "127.0.0.1".parse().unwrap());
                let mut details = HashMap::new();
                details.insert("action".to_string(), "VERIFY_EMAIL".to_string());
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::Custom("verify_email".to_string()),
                    &ip,
                    None,
                    Some(user_id.clone()),
                    None,
                    None,
                    details,
                )
                .await;
                store_entry(&state, &realm_id, execution, &entry).await;
            }
        }
    }
    info!(realm = %realm_id, user_id = %user_id, "email verified via link");

    // Deliberately no automatic redirect into the continuation: the link may
    // be opened on a different device than the login, and auto-completing
    // would issue tokens on the wrong browser. The user clicks through.
    let continue_url = continuation_url(&realm_name, execution);
    page(
        "Email verified",
        &format!(
            "<h1>Email address verified</h1>\
             <p>Your email address has been verified successfully.</p>\
             <form method=\"get\" action=\"{continue_url}\">\
             <button type=\"submit\">Continue sign-in</button>\
             </form>"
        ),
    )
    .into_response()
}

// ---------------------------------------------------------------------------
// Execute-actions continuation
// ---------------------------------------------------------------------------

/// Cache key for the execute-actions continuation entry written by the admin
/// API (`execute-actions-email`). Keyed by realm **name**, matching the
/// login-route keying convention (and the admin side's cache write).
fn execute_actions_cache_key(realm_name: &str, jti: &str) -> String {
    format!("execute-actions:{realm_name}:{jti}")
}

/// Error shown when the execute-actions token fails verification (bad
/// signature, wrong purpose/realm, or expired).
const INVALID_ACTIONS_LINK: &str = "This account setup link is invalid or has expired.";

/// Error shown when the token verifies but its continuation entry is gone
/// (already consumed or TTL-expired).
const USED_ACTIONS_LINK: &str = "This account setup link has already been used or has expired.";

/// GET `/realms/{realm}/login/execute-actions?token=...` — the link target
/// from the admin's execute-actions email.
///
/// The signed action token (purpose `execute-actions`) proves the link; the
/// cache entry keyed by its `jti` carries the action list and the optional
/// post-completion redirect. The actions are merged into the user's required
/// actions, then the standard required-action continuation
/// (`/login/required-action/{execution}`) takes over exactly as after a
/// login with pending actions. The `jti` entry is single-use: it is consumed
/// only after the continuation has been dispatched.
///
/// No event is emitted here — same as the reset-credentials link target; the
/// continuation itself emits the per-action events (`update_password`, ...).
pub async fn execute_actions_handler(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
) -> Response {
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    let realm_id = realm.id.clone();

    let Some(token) = query.get("token") else {
        return error_response(StatusCode::BAD_REQUEST, INVALID_ACTIONS_LINK);
    };
    let claims = match issuerd_token::action_tokens::verify_action_token(
        state.crypto.as_ref(),
        token,
        issuerd_core::ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
        &realm_id,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_ACTIONS_LINK),
    };

    // Single-use: the continuation entry must still be pending in the cache.
    // It is consumed below, after the continuation has been dispatched.
    let jti_key = execute_actions_cache_key(realm.name.as_str(), &claims.jti);
    let continuation: Option<issuerd_admin_api::user_actions::ExecuteActionsContinuation> =
        match state.cache.get(&jti_key).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        };
    let Some(continuation) = continuation else {
        return error_response(StatusCode::BAD_REQUEST, USED_ACTIONS_LINK);
    };

    let user_id = match issuerd_core::UserId::new(claims.sub.clone()) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_ACTIONS_LINK),
    };
    let mut user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return error_response(StatusCode::BAD_REQUEST, "This account is no longer available.")
        }
    };

    // Merge the requested actions into the user's required actions so they
    // survive the continuation (and any concurrent login).
    let mut changed = false;
    for action in &continuation.actions {
        if !user.required_actions.contains(action) {
            user.required_actions.push(action.clone());
            changed = true;
        }
    }
    if changed {
        if let Err(e) = state.storage.update_user(&realm_id, &user).await {
            error!(realm = %realm_id, user_id = %user_id, error = %e, "execute-actions: user update failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start the account setup. Please contact your administrator.",
            );
        }
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user_id)
        .await;

    // Build the paused continuation exactly like the login-success path does,
    // except there is no OIDC login in flight: the synthetic pending entry is
    // inert (never replayed — `finish_continuation` short-circuits on
    // `redirect_uri`), and the browser lands on the admin-chosen redirect (or
    // the account console, Keycloak's default) once the actions clear.
    let pending = PendingAuthData {
        realm_id: realm_id.0.clone(),
        client_id: "account-console".to_string(),
        redirect_uri: String::new(),
        scope: Vec::new(),
        state: None,
        nonce: None,
        response_type: String::new(),
        code_challenge: None,
        code_challenge_method: None,
        ip_address: Some(ip),
        execution_id: issuerd_core::FlowStageId::new("execute-actions").unwrap(),
        acr_values: Vec::new(),
        claims: None,
        _typestate_tag: action_required_tag(),
        attempt_count: 0,
        remember_me: false,
        user_id: Some(user_id.0.clone()),
        prompt_consent: false,
        locale: None,
        response_mode: None,
        authorization_details: None,
    };
    let entry = PendingActionsData {
        pending,
        user_id: user_id.0.clone(),
        session_id: issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap().0,
        auth_time: chrono::Utc::now(),
        remaining_actions: continuation.actions.clone(),
        email_sent: false,
        error: None,
        totp_secret: None,
        redirect_uri: Some(
            continuation
                .redirect_uri
                .unwrap_or_else(|| format!("/realms/{}/account/", url_path_segment(&realm_name))),
        ),
        _typestate_tag: action_required_tag(),
    };

    let flow_id = issuerd_core::utils::generate_id();
    let response =
        dispatch_actions_continuation(&state, &realm_name, &realm_id, &flow_id, entry, true).await;

    // Dispatch complete — consume the jti atomically. A concurrent replay of
    // the same link loses the race here; unwind the just-stored continuation
    // so only one of them is usable.
    match state.cache.get_and_delete(&jti_key).await {
        Ok(Some(_)) => {}
        _ => {
            let _ = state.cache.delete(&pending_actions_cache_key(&realm_id, &flow_id)).await;
            return error_response(StatusCode::BAD_REQUEST, USED_ACTIONS_LINK);
        }
    }

    info!(realm = %realm_id, user_id = %user_id, "execute-actions continuation started");
    response
}

/// All actions cleared: finish the login with the original `auth_time`.
///
/// Execute-actions continuations (`redirect_uri` set) are not
/// backed by an OIDC login: the browser is sent to the admin-chosen target
/// instead of completing a code/token issuance.
async fn finish_continuation(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    entry: &PendingActionsData,
) -> Response {
    if let Some(ref redirect_uri) = entry.redirect_uri {
        return Redirect::to(redirect_uri).into_response();
    }
    let (user_id, session_id) = match (
        issuerd_core::UserId::new(entry.user_id.clone()),
        issuerd_core::SessionId::new(entry.session_id.clone()),
    ) {
        (Ok(u), Ok(s)) => (u, s),
        _ => return error_response(StatusCode::BAD_REQUEST, "Invalid session."),
    };
    // Typestate proof: the actions list is empty here, so the result can be
    // cleared while preserving the original authentication time.
    let _cleared = issuerd_core::typestate::TypedFlowResult::new_cleared_at(
        user_id.clone(),
        session_id.clone(),
        entry.auth_time,
    );
    super::login_api::complete_login(
        state,
        realm_id,
        &entry.pending,
        &user_id,
        &session_id,
        entry.auth_time,
        true,
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
    use chrono::Utc;
    use issuerd_core::{
        Credential, CredentialId, CredentialType, DisplayName, Email, UserId, Username,
    };

    fn test_user(realm_id: &RealmId, username: &str, actions: &[&str]) -> User {
        User {
            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new(username).unwrap(),
            email: Some(Email::new(format!("{username}@example.com")).unwrap()),
            email_verified: false,
            first_name: Some(DisplayName::new(username).unwrap()),
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: actions.iter().map(|s| s.to_string()).collect(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn temp_password_cred() -> Credential {
        use argon2::{password_hash::SaltString, PasswordHasher};
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password(b"Temp1234!", &salt)
            .unwrap()
            .to_string();
        Credential {
            id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id", "temporary": true}),
            priority: 1,
        }
    }

    fn test_pending(realm_id: &RealmId) -> PendingAuthData {
        PendingAuthData {
            realm_id: realm_id.0.clone(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("state-1".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: issuerd_core::FlowStageId::new("username-password").unwrap(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "challenged".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        }
    }

    fn pending_result(user: &User, actions: &[&str]) -> TypedFlowResult<ActionsPending> {
        TypedFlowResult::new_pending(
            user.id.clone(),
            issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            actions.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn flow_cookie_name_of(response: &Response) -> String {
        response
            .headers()
            .get(SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("flow cookie must be set")
            .split('=')
            .next()
            .unwrap()
            .to_string()
    }

    fn execution_from_location(response: &Response) -> String {
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("redirect location")
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    async fn body_string(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn test_state() -> Arc<ServerState> {
        Arc::new(ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap())
    }

    #[derive(Default)]
    struct RecordingSender {
        sent: std::sync::Mutex<Vec<(String, String, String, Option<String>)>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::EmailSender for RecordingSender {
        async fn send(
            &self,
            _realm: &Realm,
            to: &str,
            subject: &str,
            text_body: &str,
            html_body: Option<String>,
        ) -> Result<(), IssuerdError> {
            self.sent.lock().unwrap().push((
                to.to_string(),
                subject.to_string(),
                text_body.to_string(),
                html_body,
            ));
            Ok(())
        }
    }

    #[test]
    fn cache_keys_are_scoped() {
        let realm = RealmId::new("master").unwrap();
        assert_eq!(pending_actions_cache_key(&realm, "exec-1"), "pending_actions:master:exec-1");
        assert_eq!(verify_email_cache_key(&realm, "tok"), "verify-email:master:tok");
    }

    #[tokio::test]
    async fn webauthn_challenge_page_escapes_script_breakout() {
        let options =
            r#"{"challenge":"Y2Fi","rpId":"localhost","x":"</script><script>alert(1)</script>"}"#;
        let response = webauthn_challenge_page("master", "flow-123", options, None);
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(
            body.contains("\\u003c/script>"),
            "embedded JSON must escape `<` so the script element cannot be closed early"
        );
        assert!(!body.contains("</script><script>alert(1)</script>"));
    }

    #[tokio::test]
    async fn webauthn_challenge_page_embeds_flow_id_and_error() {
        let options = r#"{"challenge":"Y2Fi","rpId":"localhost"}"#;
        let response =
            webauthn_challenge_page("master", "flow-456", options, Some("Passkey failed."));
        let body = body_string(response).await;
        assert!(body.contains("value=\"flow-456\""));
        assert!(body.contains("name=\"webauthn_assertion\""));
        assert!(body.contains("Passkey failed."));
    }

    #[tokio::test]
    async fn email_code_challenge_page_renders_one_box_per_digit() {
        let response = email_code_challenge_page("master", "flow-789", Some("a***@b.c"), None, 6);
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert_eq!(body.matches("class=\"otp-digit\"").count(), 6);
        // iOS one-time-code autofill hooks the first box; the joined value is
        // submitted via the hidden `otp` field.
        assert!(body.contains("id=\"otp\" autocomplete=\"one-time-code\" autofocus"));
        assert!(body.contains("name=\"otp\" id=\"otp-value\" disabled"));
        assert!(body.contains("value=\"flow-789\""));
        assert!(body.contains("We sent a 6-digit code to <strong>a***@b.c</strong>."));
    }

    #[tokio::test]
    async fn email_code_challenge_page_honors_realm_code_length() {
        let response = email_code_challenge_page("master", "flow-1", None, None, 8);
        let body = body_string(response).await;
        assert_eq!(body.matches("class=\"otp-digit\"").count(), 8);
        assert!(body.contains("Enter the 8-digit code we sent"));
    }

    #[tokio::test]
    async fn email_code_challenge_page_keeps_noscript_single_input() {
        let response = email_code_challenge_page(
            "master",
            "flow-2",
            None,
            Some("Invalid or expired code."),
            6,
        );
        let body = body_string(response).await;
        // Without JS the digit boxes never reach the hidden field; the
        // noscript fallback submits a classic single `otp` input instead.
        assert!(body.contains("<noscript>"));
        assert!(body.contains("Invalid or expired code."));
        let noscript = body.split("<noscript>").nth(1).unwrap();
        assert!(noscript.contains("name=\"otp\""));
    }

    #[test]
    fn form_params_filter_per_action() {
        let mut form = HashMap::new();
        form.insert("new_password".to_string(), "a".to_string());
        form.insert("confirm_password".to_string(), "a".to_string());
        form.insert("csrf".to_string(), "x".to_string());
        let params = form_params("UPDATE_PASSWORD", &form);
        assert_eq!(params.len(), 2);
        assert!(!params.contains_key("csrf"));
        assert!(form_params("VERIFY_EMAIL", &form).is_empty());
        assert!(
            form_params("TERMS_AND_CONDITIONS", &form).is_empty(),
            "terms checkbox absent means no params"
        );
    }

    #[tokio::test]
    async fn begin_continuation_stores_entry_and_redirects_with_cookie() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "dave", &["UPDATE_PASSWORD"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["UPDATE_PASSWORD"]),
            true,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let execution = execution_from_location(&resp);
        assert_eq!(flow_cookie_name_of(&resp), format!("issuerd_flow_{execution}"));

        let bytes = state
            .cache
            .get(&pending_actions_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .unwrap();
        let entry: PendingActionsData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entry.remaining_actions, vec!["UPDATE_PASSWORD"]);
        assert_eq!(entry.user_id, user.id.0);
        assert_eq!(entry._typestate_tag, "action_required");
    }

    #[tokio::test]
    async fn begin_continuation_json_variant_returns_continuation_url() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "erin", &["UPDATE_PROFILE"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["UPDATE_PROFILE"]),
            false,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(SET_COOKIE));
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let redirect = json["redirect_uri"].as_str().unwrap();
        assert!(redirect.starts_with("/realms/master/login/required-action/"));
        assert_eq!(json["state"], "state-1");
    }

    #[tokio::test]
    async fn get_page_without_entry_returns_400() {
        let state = test_state().await;
        let resp = required_action_page(
            State(state),
            Path(("master".to_string(), "no-such-execution".to_string())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("expired"));
    }

    #[tokio::test]
    async fn update_password_continuation_completes_login() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "frank", &["UPDATE_PASSWORD"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();
        state
            .storage
            .create_credential(&realm_id, &user.id, &temp_password_cred())
            .await
            .unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["UPDATE_PASSWORD"]),
            true,
        )
        .await;
        let execution = execution_from_location(&resp);
        let cookie_name = flow_cookie_name_of(&resp);

        // GET renders the password form.
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("Update your password"));

        // POST with mismatched passwords → back to the page with an error.
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, format!("{cookie_name}=1").parse().unwrap());
        let resp = required_action_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            headers.clone(),
            Bytes::from("new_password=N0wPassword!&confirm_password=different"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
        )
        .await;
        assert!(body_string(resp).await.contains("do not match"));

        // POST with matching passwords → login completes with a code redirect.
        let resp = required_action_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            headers,
            Bytes::from("new_password=N0wPassword!&confirm_password=N0wPassword!"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location =
            resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).unwrap().to_string();
        assert!(
            location.starts_with("http://localhost/callback?"),
            "unexpected redirect: {location}"
        );
        assert!(location.contains("code="));
        assert!(location.contains("state=state-1"));
        assert!(resp.headers().contains_key(SET_COOKIE), "SSO cookie must be set");

        // The assignment is cleared and the password credential is no longer temporary.
        let user = state.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert!(user.required_actions.is_empty());
        let creds = state
            .storage
            .get_credentials(&realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        assert!(creds[0].credential_data.get("temporary").is_none());

        // The continuation entry is consumed: a replay expires the flow.
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution)),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_email_roundtrip_sends_mail_and_completes() {
        let mut state =
            ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap();
        let recorder = Arc::new(RecordingSender::default());
        state.email_sender = recorder.clone();
        let state = Arc::new(state);

        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "grace", &["VERIFY_EMAIL"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["VERIFY_EMAIL"]),
            true,
        )
        .await;
        let execution = execution_from_location(&resp);

        // First render sends the mail exactly once.
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Verify your email address"));
        {
            let sent = recorder.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, "grace@example.com");
            assert_eq!(sent[0].1, "Verify your email address");
            let html = sent[0].3.as_ref().unwrap();
            assert!(html.contains("urn:schemas-microsoft-com:vml"));
            assert!(html.contains("/realms/master/login/verify-email?token="));
        }
        // Re-render does not resend.
        let _ = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(recorder.sent.lock().unwrap().len(), 1);

        // Fish the token out of the cache (single-use, 24 h TTL).
        let keys = state.cache.scan_keys("verify-email:master:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        let token = keys[0].rsplit(':').next().unwrap().to_string();

        // Click the link: email verified, action dropped from the continuation.
        let mut query = HashMap::new();
        query.insert("token".to_string(), token.clone());
        query.insert("execution".to_string(), execution.clone());
        let resp =
            verify_email_handler(State(state.clone()), Path("master".to_string()), Query(query))
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("Email address verified"));

        let user = state.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert!(user.email_verified);
        assert!(user.required_actions.is_empty());

        // Token is single-use.
        let mut query = HashMap::new();
        query.insert("token".to_string(), token);
        query.insert("execution".to_string(), execution.clone());
        let resp =
            verify_email_handler(State(state.clone()), Path("master".to_string()), Query(query))
                .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // The continuation now advances straight into login completion.
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution)),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location =
            resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).unwrap().to_string();
        assert!(location.contains("code="), "unexpected redirect: {location}");
    }

    #[tokio::test]
    async fn post_without_flow_cookie_is_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "heidi", &["TERMS_AND_CONDITIONS"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["TERMS_AND_CONDITIONS"]),
            true,
        )
        .await;
        let execution = execution_from_location(&resp);
        let cookie_name = flow_cookie_name_of(&resp);

        // POST without the correlation cookie → rejected, entry untouched.
        let resp = required_action_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
            Bytes::from("terms_accepted=true"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(state
            .cache
            .get(&pending_actions_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .is_some());

        // With the cookie, accepting terms completes the login.
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, format!("{cookie_name}=1").parse().unwrap());
        let resp = required_action_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            headers,
            Bytes::from("terms_accepted=true"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let user = state.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert_eq!(
            user.attributes.get("terms_accepted").map(|v| v.as_slice()),
            Some(&["true".to_string()][..])
        );
        assert!(user.required_actions.is_empty());
    }

    #[tokio::test]
    async fn get_page_mints_flow_cookie_when_missing() {
        // Cross-browser continuation: the email link was opened in a browser
        // that never saw the login start, so the correlation cookie is absent.
        // The GET must re-mint it, or the follow-up POST from that browser is
        // rejected with "Invalid or expired sign-in flow.".
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "ivan", &["TERMS_AND_CONDITIONS"]);
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let resp = begin_actions_continuation(
            &state,
            "master",
            test_pending(&realm_id),
            pending_result(&user, &["TERMS_AND_CONDITIONS"]),
            true,
        )
        .await;
        let execution = execution_from_location(&resp);

        // GET without the cookie renders the page AND re-mints the cookie.
        let resp = required_action_page(
            State(state.clone()),
            Path(("master".to_string(), execution.clone())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie_name = flow_cookie_name_of(&resp);

        // The POST from that browser is now accepted and completes the login.
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, format!("{cookie_name}=1").parse().unwrap());
        let resp = required_action_submit(
            State(state.clone()),
            Path(("master".to_string(), execution)),
            headers,
            Bytes::from("terms_accepted=true"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    // -- execute-actions continuation ----------------------------------------

    /// Mint a real execute-actions action token and store the continuation
    /// entry exactly like the admin API's `execute-actions-email` does.
    async fn execute_actions_link(
        state: &Arc<ServerState>,
        realm_id: &RealmId,
        user: &User,
        actions: &[&str],
        redirect_uri: Option<&str>,
    ) -> (String, String) {
        let claims = issuerd_token::action_tokens::action_token_claims(
            &user.id,
            realm_id,
            issuerd_core::ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
            3600,
        );
        let jti = claims.jti.clone();
        let token =
            issuerd_token::action_tokens::issue_action_token(state.crypto.as_ref(), &claims)
                .await
                .unwrap();
        let continuation = issuerd_admin_api::user_actions::ExecuteActionsContinuation {
            user_id: user.id.to_string(),
            actions: actions.iter().map(|s| s.to_string()).collect(),
            redirect_uri: redirect_uri.map(str::to_string),
        };
        state
            .cache
            .set(
                &execute_actions_cache_key("master", &jti),
                serde_json::to_vec(&continuation).unwrap(),
                Some(Duration::from_secs(3600)),
            )
            .await
            .unwrap();
        (token, jti)
    }

    async fn call_execute_actions(state: &Arc<ServerState>, token: &str) -> Response {
        let mut query = HashMap::new();
        query.insert("token".to_string(), token.to_string());
        execute_actions_handler(
            State(state.clone()),
            Path("master".to_string()),
            Query(query),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
        )
        .await
    }

    #[tokio::test]
    async fn execute_actions_happy_path_dispatches_continuation() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "ivan", &[]);
        state.storage.create_user(&realm_id, &user).await.unwrap();
        let (token, jti) = execute_actions_link(
            &state,
            &realm_id,
            &user,
            &["UPDATE_PASSWORD"],
            Some("http://example.com/done"),
        )
        .await;

        let resp = call_execute_actions(&state, &token).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location =
            resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).unwrap().to_string();
        assert!(
            location.starts_with("/realms/master/login/required-action/"),
            "unexpected redirect: {location}"
        );
        assert!(resp.headers().contains_key(SET_COOKIE), "flow cookie must be set");
        let execution = execution_from_location(&resp);

        // The stored continuation carries the actions and the admin's redirect.
        let bytes = state
            .cache
            .get(&pending_actions_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .unwrap();
        let entry: PendingActionsData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entry.remaining_actions, vec!["UPDATE_PASSWORD"]);
        assert_eq!(entry.user_id, user.id.0);
        assert_eq!(entry.redirect_uri.as_deref(), Some("http://example.com/done"));

        // The actions were merged onto the user ...
        let user = state.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert_eq!(user.required_actions, vec!["UPDATE_PASSWORD".to_string()]);

        // ... and the link is single-use.
        assert!(state
            .cache
            .get(&execute_actions_cache_key("master", &jti))
            .await
            .unwrap()
            .is_none());
        let replay = call_execute_actions(&state, &token).await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(replay).await.contains("already been used"));
    }

    #[tokio::test]
    async fn execute_actions_preserves_admin_action_order() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "mia", &[]);
        state.storage.create_user(&realm_id, &user).await.unwrap();
        let (token, _jti) = execute_actions_link(
            &state,
            &realm_id,
            &user,
            &["VERIFY_EMAIL", "UPDATE_PROFILE", "UPDATE_PASSWORD"],
            None,
        )
        .await;

        let resp = call_execute_actions(&state, &token).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let execution = execution_from_location(&resp);

        // The dispatched continuation runs the actions in the exact order of
        // the admin request body.
        let bytes = state
            .cache
            .get(&pending_actions_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .unwrap();
        let entry: PendingActionsData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            entry.remaining_actions,
            vec!["VERIFY_EMAIL", "UPDATE_PROFILE", "UPDATE_PASSWORD"]
        );

        // The merge into the user's required actions preserves that order too.
        let user = state.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert_eq!(
            user.required_actions,
            vec![
                "VERIFY_EMAIL".to_string(),
                "UPDATE_PROFILE".to_string(),
                "UPDATE_PASSWORD".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn execute_actions_rejects_invalid_token() {
        let state = test_state().await;
        let resp = call_execute_actions(&state, "not-a-token").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("invalid or has expired"));
    }

    #[tokio::test]
    async fn execute_actions_rejects_missing_continuation_entry() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "judy", &[]);
        state.storage.create_user(&realm_id, &user).await.unwrap();
        // A well-formed, correctly signed token whose jti has no cache entry
        // (TTL-expired, or never issued by the admin API).
        let claims = issuerd_token::action_tokens::action_token_claims(
            &user.id,
            &realm_id,
            issuerd_core::ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
            3600,
        );
        let token =
            issuerd_token::action_tokens::issue_action_token(state.crypto.as_ref(), &claims)
                .await
                .unwrap();
        let resp = call_execute_actions(&state, &token).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("already been used"));
    }

    #[tokio::test]
    async fn execute_actions_rejects_disabled_user_without_consuming_entry() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let mut user = test_user(&realm_id, "karl", &[]);
        user.enabled = false;
        state.storage.create_user(&realm_id, &user).await.unwrap();
        let (token, jti) =
            execute_actions_link(&state, &realm_id, &user, &["UPDATE_PASSWORD"], None).await;

        let resp = call_execute_actions(&state, &token).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("no longer available"));
        // The entry survives: only a dispatched continuation consumes it.
        assert!(state
            .cache
            .get(&execute_actions_cache_key("master", &jti))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn execute_actions_defaults_redirect_to_account_console() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user = test_user(&realm_id, "lisa", &[]);
        state.storage.create_user(&realm_id, &user).await.unwrap();
        let (token, _jti) =
            execute_actions_link(&state, &realm_id, &user, &["VERIFY_EMAIL"], None).await;

        let resp = call_execute_actions(&state, &token).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let execution = execution_from_location(&resp);
        let bytes = state
            .cache
            .get(&pending_actions_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .unwrap();
        let entry: PendingActionsData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entry.redirect_uri.as_deref(), Some("/realms/master/account/"));
    }

    #[tokio::test]
    async fn finish_continuation_with_redirect_uri_skips_login_completion() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let entry = PendingActionsData {
            pending: test_pending(&realm_id),
            user_id: "user-1".to_string(),
            session_id: issuerd_core::utils::generate_id(),
            auth_time: Utc::now(),
            remaining_actions: vec![],
            email_sent: false,
            error: None,
            totp_secret: None,
            redirect_uri: Some("https://app.example.com/after".to_string()),
            _typestate_tag: action_required_tag(),
        };
        let resp = finish_continuation(&state, &realm_id, &entry).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location =
            resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).unwrap().to_string();
        assert_eq!(location, "https://app.example.com/after");
    }
}
