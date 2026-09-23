// SPDX-License-Identifier: Apache-2.0
// Scenario (both targets): DPoP-bound token issuance + DPoP userinfo.
// RFC 9449 proofs are minted in k6 via WebCrypto (ES256): fresh single-use
// jti per proof, exact htm/htu, ath when presenting the bound token.
//   dpop_token:    client_credentials + DPoP proof → token_type "DPoP" + cnf.jkt
//   dpop_userinfo: password-grant DPoP-bound token per VU, then userinfo with
//                  Authorization: DPoP + proof carrying ath — measures the
//                  validation path with proof verification on every request.
// Keycloak 26.7 supports DPoP by default and binds tokens whenever a valid
// proof is presented; no client attribute is set (forcing it would break the
// proof-less scenarios sharing perf-service).
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');
const tokenMs = new Trend('dpop_token_ms', true);
const userinfoMs = new Trend('dpop_userinfo_ms', true);

export const options = {
  scenarios: {
    dpop_token: {
      executor: 'constant-vus',
      exec: 'dpopToken',
      vus: Number(__ENV.VUS || 30),
      duration: __ENV.DURATION || '60s',
    },
    dpop_userinfo: {
      executor: 'constant-vus',
      exec: 'dpopUserinfo',
      vus: Number(__ENV.VUS || 30),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);

// Per-VU lazy state (each VU has its own JS runtime).
let key = null;
let boundToken = null;

async function getKey() {
  if (!key) key = await lib.DpopKey.create();
  return key;
}

async function getBoundToken(k) {
  if (!boundToken) {
    const proof = await k.proof('POST', u.token);
    const res = http.post(
      u.token,
      {
        grant_type: 'password',
        client_id: lib.SERVICE.id,
        client_secret: lib.SERVICE.secret,
        username: 'perfuser',
        password: lib.PASSWORD,
        scope: 'openid profile',
      },
      { headers: { DPoP: proof } }
    );
    if (res.status !== 200) throw new Error(`bound token failed: ${res.status} ${res.body}`);
    boundToken = res.json('access_token');
  }
  return boundToken;
}

export async function dpopToken() {
  const k = await getKey();
  const proof = await k.proof('POST', u.token);
  const start = Date.now();
  const res = http.post(
    u.token,
    {
      grant_type: 'client_credentials',
      client_id: lib.SERVICE.id,
      client_secret: lib.SERVICE.secret,
      scope: 'openid profile',
    },
    { headers: { DPoP: proof } }
  );
  tokenMs.add(Date.now() - start);
  errors.add(
    !check(res, {
      'dpop token 200': (r) => r.status === 200,
      'token_type DPoP': (r) => r.json('token_type') === 'DPoP',
    })
  );
}

export async function dpopUserinfo() {
  const k = await getKey();
  const token = await getBoundToken(k);
  const proof = await k.proof('GET', u.userinfo, token);
  const start = Date.now();
  const res = http.get(u.userinfo, {
    headers: { Authorization: `DPoP ${token}`, DPoP: proof },
  });
  userinfoMs.add(Date.now() - start);
  errors.add(!check(res, { 'dpop userinfo 200': (r) => r.status === 200 }));
}

export const handleSummary = lib.makeSummary('dpop');
