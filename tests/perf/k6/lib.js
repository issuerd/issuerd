// SPDX-License-Identifier: Apache-2.0
// Shared helpers for the tests/perf k6 scenarios. Hermetic: no remote imports
// (the perf network has no internet access), everything is local code.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { fail, sleep } from 'k6';

export const TARGETS = {
  issuerd: { base: 'http://issuerd:8080', realm: 'perf' },
  keycloak: { base: 'http://keycloak:8080', realm: 'perf' },
};

export const SERVICE = { id: 'perf-service', secret: 'perf-secret-9f8e7d6c5b4a' };
export const PUBLIC_CLIENT = 'perf-public';
export const PASSWORD = 'Perf-Pass-123!';
export const REDIRECT_URI = 'http://app.local/callback';
export const NUM_USERS = Number(__ENV.NUM_USERS || 1000);

export function target() {
  const t = TARGETS[__ENV.TARGET || 'issuerd'];
  if (!t) fail(`unknown TARGET "${__ENV.TARGET}" (issuerd|keycloak)`);
  return t;
}

export function urls(t) {
  const oidc = `${t.base}/realms/${t.realm}/protocol/openid-connect`;
  return {
    discovery: `${t.base}/realms/${t.realm}/.well-known/openid-configuration`,
    auth: `${oidc}/auth`,
    token: `${oidc}/token`,
    userinfo: `${oidc}/userinfo`,
    introspect: `${oidc}/token/introspect`,
    cibaAuth: `${oidc}/ext/ciba/auth`,
    cibaApprove: `${oidc}/ext/ciba/approve`,
    adminToken: `${t.base}/realms/master/protocol/openid-connect/token`,
    adminUsers: `${t.base}/admin/realms/${t.realm}/users`,
  };
}

export function username(i) {
  // user0001..userNNNN, matching gen_kc_realm.py and the seeding scenario.
  return `user${String((i % NUM_USERS) + 1).padStart(4, '0')}`;
}

// ---------------------------------------------------------------------------
// base64url / crypto primitives
// k6's goja runtime has no TextEncoder — encoding.b64encode accepts strings
// (UTF-8), and k6/crypto sha256 takes string input directly. strToBytes covers
// the one place WebCrypto needs an ArrayBuffer (JWT signing input is always
// ASCII: base64url header.payload).
// ---------------------------------------------------------------------------

import { sha256 } from 'k6/crypto';

function urlsafe(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlBytes(bytes) {
  // Pass the ArrayBuffer: k6 encodes strings as UTF-8 text, which would
  // double-encode bytes > 127 (binary signature material).
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return urlsafe(encoding.b64encode(buf));
}

export function b64urlStr(s) {
  return urlsafe(encoding.b64encode(s));
}

function strToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) throw new Error('non-ASCII character in signing input');
    out[i] = c;
  }
  return out;
}

function uuidHex() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function derEcdsaToRaw(sig, size) {
  // WebCrypto ECDSA signatures come as either DER SEQUENCE { INTEGER r,
  // INTEGER s } or (k6's Go-backed implementation) already the fixed-width
  // r || s concatenation JWS needs. Handle both.
  const b = new Uint8Array(sig);
  if (b.length === size * 2) return b;
  let i = 0;
  if (b[i++] !== 0x30) throw new Error(`bad DER sequence (len=${b.length}, b0=${b[0]})`);
  let len = b[i++];
  if (len & 0x80) i += len & 0x7f;
  const readInt = () => {
    if (b[i++] !== 0x02) throw new Error('bad DER integer');
    const n = b[i++];
    let v = b.slice(i, i + n);
    i += n;
    while (v.length > size && v[0] === 0) v = v.slice(1);
    if (v.length > size) throw new Error('DER integer too long');
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

export async function sha256b64url(s) {
  return urlsafe(sha256(s, 'base64'));
}

export async function pkcePair() {
  const verifier = b64urlBytes(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: await sha256b64url(verifier) };
}

// ---------------------------------------------------------------------------
// DPoP (RFC 9449) proof minting — ES256 via k6 WebCrypto.
// ---------------------------------------------------------------------------

export class DpopKey {
  static async create() {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    return new DpopKey(kp, { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
  }

  constructor(kp, pub) {
    this.kp = kp;
    this.pub = pub;
  }

  // ath: access token to bind (only when presenting a token, e.g. userinfo)
  async proof(method, url, ath) {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: this.pub };
    const payload = { jti: uuidHex(), htm: method, htu: url, iat: Math.floor(Date.now() / 1000) };
    if (ath) payload.ath = await sha256b64url(ath);
    const data = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(payload))}`;
    const sigDer = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.kp.privateKey,
      strToBytes(data)
    );
    return `${data}.${b64urlBytes(derEcdsaToRaw(sigDer, 32))}`;
  }
}

// ---------------------------------------------------------------------------
// Browser login flows (authorization code). Issuerd uses its SPA JSON login
// API; Keycloak uses the classic HTML form. Both end at a `code`.
// ---------------------------------------------------------------------------

export async function loginGetCode(t, user, pass) {
  const u = urls(t);
  const pkce = await pkcePair();
  const authUrl =
    `${u.auth}?response_type=code&client_id=${PUBLIC_CLIENT}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid&state=perf` +
    `&code_challenge=${pkce.challenge}&code_challenge_method=S256`;

  let code = null;
  let cookies = null;
  if (t === TARGETS.issuerd) {
    const r1 = http.get(authUrl, { redirects: 0 });
    if (r1.status !== 303) return { code: null, pkce, stage: `auth=${r1.status}` };
    const m = /[?&]execution_id=([^&]+)/.exec(r1.headers.Location || '');
    if (!m) return { code: null, pkce, stage: 'no-execution-id' };
    const execId = m[1];
    const r2 = http.post(
      `${t.base}/api/v1/auth/login?realm=${t.realm}`,
      JSON.stringify({ execution_id: execId, username: user, password: pass }),
      {
        headers: {
          'Content-Type': 'application/json',
          Cookie: `issuerd_flow_${execId}=1`,
        },
        redirects: 0,
      }
    );
    if (r2.status !== 200) return { code: null, pkce, stage: `login=${r2.status}` };
    code = r2.json('code');
    cookies = r2.cookies;
  } else {
    // Keycloak: 200 HTML login form → POST action → 302 with ?code=
    const r1 = http.get(authUrl, { redirects: 0 });
    if (r1.status !== 200) return { code: null, pkce, stage: `auth=${r1.status}` };
    const m = /action="([^"]+)"/.exec(r1.body);
    if (!m) return { code: null, pkce, stage: 'no-form' };
    const action = m[1].replace(/&amp;/g, '&');
    const r2 = http.post(action, { username: user, password: pass }, { redirects: 0 });
    if (r2.status !== 302) return { code: null, pkce, stage: `login=${r2.status}` };
    const cm = /[?&]code=([^&]+)/.exec(r2.headers.Location || '');
    code = cm ? cm[1] : null;
    cookies = r2.cookies;
  }
  return { code, pkce, cookies, stage: code ? 'ok' : 'no-code' };
}

export function exchangeCode(t, code, pkce) {
  return http.post(urls(t).token, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: PUBLIC_CLIENT,
    code_verifier: pkce.verifier,
  });
}

// ---------------------------------------------------------------------------
// CIBA (poll mode) — shared by ciba.js and smoke.js.
// ---------------------------------------------------------------------------

// Poll the CIBA grant until tokens are issued. preDelaySecs paces the first
// poll: on Keycloak the ad-simulator's approval lands right around bc-auth
// completion (the auth session is only visible to KC's callback once the
// request commits), so the first poll is delayed by a fixed, disclosed
// modeled device-approval latency (see ciba.js) — polling earlier just burns
// one authorization_pending round plus the 5s slow_down-safe interval wait.
// Issuerd approves synchronously via ext/ciba/approve before polling, so it
// passes 0. authorization_pending is retried after the server-advertised
// interval (spec-compliant — polling earlier risks slow_down, which both
// servers enforce) and should be rare; anything else (slow_down,
// expired_token, access_denied) is returned to the caller as-is.
export function pollCiba(u, authReqId, intervalSecs, preDelaySecs) {
  const wait = Math.max(Number(intervalSecs) || 5, 1);
  if (preDelaySecs) sleep(preDelaySecs);
  let res = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt > 0) sleep(wait);
    res = http.post(u.token, {
      grant_type: 'urn:openid:params:grant-type:ciba',
      auth_req_id: authReqId,
      client_id: SERVICE.id,
      client_secret: SERVICE.secret,
    });
    if (res.status === 200) return res;
    let err = null;
    try {
      err = res.json('error');
    } catch (_) {
      return res; // non-JSON error body — surface it
    }
    if (err !== 'authorization_pending') return res;
  }
  return res;
}

// ---------------------------------------------------------------------------
// Admin API (seeding / events config)
// ---------------------------------------------------------------------------

export function adminToken(t) {
  const res = http.post(urls(t).adminToken, {
    grant_type: 'password',
    client_id: 'admin-cli',
    username: 'admin',
    password: 'admin',
  });
  if (res.status !== 200) fail(`admin token failed: ${res.status} ${res.body}`);
  return res.json('access_token');
}

export function bearerHeaders(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

export function basicAuthHeader(id, secret) {
  return { Authorization: `Basic ${encoding.b64encode(`${id}:${secret}`)}` };
}

// ---------------------------------------------------------------------------
// Result export — writes the full k6 summary JSON to the bind-mounted results
// dir. No jslib textSummary import (would need internet): stdout gets a small
// hand-rolled digest.
// ---------------------------------------------------------------------------

// The default k6 JSON summary carries only p(90)/p(95) — PERFORMANCE.md quotes
// p99, so every scenario opts into the extended set.
export const TREND_STATS = ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'];

// LOG_ERRORS=1 prints failing responses (status + body) for debugging.
export function logErr(tag, res) {
  if (__ENV.LOG_ERRORS === '1' && res.status >= 400) {
    console.error(`${tag}: ${res.status} ${res.body}`);
  }
}

export function makeSummary(name) {
  return function (data) {
    const tgt = __ENV.TARGET || 'issuerd';
    const tier = __ENV.TIER || 'medium';
    const runDir = __ENV.RUN_DIR || '/results';
    const m = data.metrics;
    const row = (key) => {
      const met = m[key];
      if (!met) return `${key}: n/a`;
      const v = met.values;
      if (v.rate !== undefined) return `${key}: rate=${v.rate.toFixed(2)}`;
      return `${key}: avg=${(v.avg || 0).toFixed(1)}ms p95=${(v['p(95)'] || 0).toFixed(1)}ms p99=${(v['p(99)'] || 0).toFixed(1)}ms max=${(v.max || 0).toFixed(0)}ms`;
    };
    const lines = [
      '',
      `=== ${name} target=${tgt} tier=${tier} ===`,
      row('http_reqs'),
      row('http_req_duration'),
      row('errors'),
      row('iterations'),
      '',
    ];
    return {
      [`${runDir}/${name}_${tgt}_${tier}.json`]: JSON.stringify(data),
      stdout: lines.join('\n'),
    };
  };
}
