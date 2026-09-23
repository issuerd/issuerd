// SPDX-License-Identifier: Apache-2.0
// Scenario (both targets): full CIBA poll-mode cycle per iteration —
//   POST ext/ciba/auth      (confidential client, login_hint=perfuser)
//   approve                 (issuerd: POST ext/ciba/approve with perfuser's
//                            SSO session cookie; keycloak: performed inline by
//                            the ad-simulator container via KC's CIBA HTTP
//                            auth channel + callback during the bc-auth call)
//   POST /token             (grant_type urn:openid:params:grant-type:ciba)
// Issuerd setup() performs one browser login as perfuser to capture the SSO
// session cookie; each VU plants it into its own cookie jar and reuses it
// (the approval identity is the same user for the whole run). Keycloak needs
// no setup — approvals are server-to-server.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');
const cycleMs = new Trend('ciba_cycle_ms', true);

export const options = {
  scenarios: {
    main: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 10),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);
const isIc = t === lib.TARGETS.issuerd;
// Keycloak: fixed modeled device-approval latency before the first poll (see
// lib.pollCiba). Disclosed in docs/PERFORMANCE.md; issuerd's approval is a
// measured synchronous request instead, so it polls immediately.
const CIBA_PRE_POLL_DELAY_S = isIc ? 0 : 0.2;

export async function setup() {
  if (!isIc) return { cookieName: null, cookieValue: null };
  const { code, cookies, stage } = await lib.loginGetCode(t, 'perfuser', lib.PASSWORD);
  if (!code) throw new Error(`CIBA setup login failed at ${stage}`);
  const sess = Object.entries(cookies || {}).find(([name]) => name.startsWith('issuerd_session'));
  if (!sess) throw new Error(`no issuerd_session* cookie after login (got: ${Object.keys(cookies || {})})`);
  return { cookieName: sess[0], cookieValue: sess[1][0].value };
}

export default function (data) {
  if (isIc) {
    const jar = http.cookieJar();
    jar.set(t.base, data.cookieName, data.cookieValue, { path: '/' });
  }

  const start = Date.now();

  const auth = http.post(u.cibaAuth, {
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    login_hint: 'perfuser',
    scope: 'openid',
    binding_message: 'perf-run',
  });
  if (!check(auth, { 'ciba auth 200': (r) => r.status === 200 })) {
    errors.add(1);
    return;
  }
  const authReqId = auth.json('auth_req_id');

  if (isIc) {
    const approve = http.post(u.cibaApprove, { auth_req_id: authReqId, action: 'approve' });
    if (!check(approve, { 'ciba approve 200': (r) => r.status === 200 })) {
      errors.add(1);
      return;
    }
  }

  const poll = lib.pollCiba(u, authReqId, auth.json('interval'), CIBA_PRE_POLL_DELAY_S);
  cycleMs.add(Date.now() - start);
  errors.add(
    !check(poll, {
      'ciba poll 200': (r) => r.status === 200,
      'ciba token': (r) => !!r.json('access_token'),
    })
  );
}

export const handleSummary = lib.makeSummary('ciba');
