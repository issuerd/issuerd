// edition:2024
// `instrument_skip_sensitive`: sensitive parameters of an
// `#[instrument]`-annotated function must be in `skip(...)`/`skip_all`.

#![feature(register_tool)]
#![register_tool(tracing)]
#![allow(dead_code)]

struct State;
struct Headers;
struct Wrapper(State);

// Violations.
#[tracing::instrument]
async fn no_skip(state: &State) {}

#[tracing::instrument]
async fn no_skip_two(headers: Headers, body: String) {}

#[tracing::instrument(skip(state))]
async fn missing_token_skip(state: &State, access_token: &str) {}

#[tracing::instrument]
async fn destructured(Wrapper(state): Wrapper) {}

struct Svc;
impl Svc {
    #[tracing::instrument(skip(self))]
    async fn method(&self, headers: &Headers) {}
}

trait Store {
    #[tracing::instrument]
    fn fetch(query: &str);
}

#[tracing::instrument]
async fn key_arg(signing_key: &[u8]) {}

// OK.
#[tracing::instrument(skip(state))]
async fn ok_skip(state: &State, other: u8) {
    let _ = other;
}

#[tracing::instrument(skip_all)]
async fn ok_skip_all(headers: Headers, body: String) {}

#[tracing::instrument(skip(access_token, refresh_token))]
async fn ok_tokens(access_token: &str, refresh_token: &str, public_key: &str, jwt_pub_key: &[u8]) {}

#[tracing::instrument(skip(client_ip), fields(realm = "r"))]
async fn ok_ip(client_ip: std::net::IpAddr) {}

#[tracing::instrument(err)]
async fn no_sensitive_params(attempt: u8) {}

fn main() {}
