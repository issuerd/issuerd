// SPDX-License-Identifier: Apache-2.0
// End-to-end smoke test for the perf stack — validates every request shape the
// scenarios rely on before any measurement run. Exits non-zero on failure.
//   k6 run /scripts/smoke.js                  → Issuerd (all checks)
//   TARGET=keycloak k6 run /scripts/smoke.js  → Keycloak (all checks)
import http from 'k6/http';
import { fail } from 'k6';
import * as lib from './lib.js';

export const options = { vus: 1, iterations: 1 };

const t = lib.target();
const u = lib.urls(t);
const isIc = t === lib.TARGETS.issuerd;

function step(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) fail(`${name} failed`);
}

export default async function () {
  // 1. Discovery
  let res = http.get(u.discovery);
  step('discovery', res.status === 200 && res.json('issuer'), `issuer=${res.json('issuer')}`);

  // 2. client_credentials
  res = http.post(u.token, {
    grant_type: 'client_credentials',
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    scope: 'openid profile',
  });
  step('client_credentials', res.status === 200 && !!res.json('access_token'), `status=${res.status}`);

  // 3. Password grant (perfuser)
  res = http.post(u.token, {
    grant_type: 'password',
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    username: 'perfuser',
    password: lib.PASSWORD,
    scope: 'openid profile',
  });
  const accessToken = res.json('access_token');
  step('password_grant', res.status === 200 && !!accessToken, `status=${res.status}`);

  // 4. userinfo
  res = http.get(u.userinfo, lib.bearerHeaders(accessToken));
  step('userinfo', res.status === 200 && !!res.json('sub'), `status=${res.status} sub=${res.json('sub')}`);

  // 5. introspect
  res = http.post(
    u.introspect,
    { token: accessToken },
    { headers: lib.basicAuthHeader(lib.SERVICE.id, lib.SERVICE.secret) }
  );
  step('introspect', res.status === 200 && res.json('active') === true, `status=${res.status}`);

  // 6. Full auth-code flow
  const { code, pkce, stage } = await lib.loginGetCode(t, 'perfuser', lib.PASSWORD);
  step('auth_code_login', !!code, `stage=${stage}`);
  res = lib.exchangeCode(t, code, pkce);
  step('auth_code_exchange', res.status === 200 && !!res.json('access_token'), `status=${res.status}`);

  // 7. Admin API: token + create user with password + ROPC with it
  const adminToken = lib.adminToken(t);
  const uname = `smoke${Date.now()}`;
  res = http.post(
    u.adminUsers,
    JSON.stringify({
      username: uname,
      enabled: true,
      email: `${uname}@example.com`,
      emailVerified: true,
      firstName: 'Smoke',
      lastName: 'User',
      credentials: [{ type: 'password', value: lib.PASSWORD, temporary: false }],
    }),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` } }
  );
  step('admin_create_user', res.status === 201, `status=${res.status}`);
  res = http.post(u.token, {
    grant_type: 'password',
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    username: uname,
    password: lib.PASSWORD,
    scope: 'openid',
  });
  step('created_user_can_login', res.status === 200 && !!res.json('access_token'), `status=${res.status} body=${res.body}`);

  // 8. DPoP: bound client_credentials token + DPoP userinfo (both targets)
  const key = await lib.DpopKey.create();
  const proof = await key.proof('POST', u.token);
  res = http.post(
    u.token,
    {
      grant_type: 'client_credentials',
      client_id: lib.SERVICE.id,
      client_secret: lib.SERVICE.secret,
      scope: 'openid profile',
    },
    { headers: { DPoP: proof } }
  );
  const dpopType = res.json('token_type');
  step('dpop_token', res.status === 200 && dpopType === 'DPoP', `status=${res.status} token_type=${dpopType}`);

  const boundProof = await key.proof('POST', u.token);
  res = http.post(
    u.token,
    {
      grant_type: 'password',
      client_id: lib.SERVICE.id,
      client_secret: lib.SERVICE.secret,
      username: 'perfuser',
      password: lib.PASSWORD,
      scope: 'openid profile',
    },
    { headers: { DPoP: boundProof } }
  );
  const boundToken = res.json('access_token');
  const uiProof = await key.proof('GET', u.userinfo, boundToken);
  res = http.get(u.userinfo, { headers: { Authorization: `DPoP ${boundToken}`, DPoP: uiProof } });
  step('dpop_userinfo', res.status === 200, `status=${res.status}`);

  // 9. CIBA full cycle. Issuerd approves via perfuser's SSO session cookie on
  // ext/ciba/approve; Keycloak approval is performed by the ad-simulator
  // container (CIBA HTTP auth channel + callback), so no login is needed.
  let sessName = null;
  let sessValue = null;
  if (isIc) {
    http.cookieJar().clear(t.base);
    const login = await lib.loginGetCode(t, 'perfuser', lib.PASSWORD);
    step('ciba_login', !!login.code, `stage=${login.stage}`);
    const sess = Object.entries(login.cookies || {}).find(([name]) => name.startsWith('issuerd_session'));
    step('ciba_sso_cookie', !!sess, sess ? sess[0] : 'none found');
    sessName = sess[0];
    sessValue = sess[1][0].value;
    http.cookieJar().set(t.base, sessName, sessValue, { path: '/' });
  }

  res = http.post(u.cibaAuth, {
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    login_hint: 'perfuser',
    scope: 'openid',
    binding_message: 'smoke',
  });
  const authReqId = res.json('auth_req_id');
  const cibaInterval = res.json('interval');
  step('ciba_auth', res.status === 200 && !!authReqId, `status=${res.status}`);

  if (isIc) {
    res = http.post(u.cibaApprove, { auth_req_id: authReqId, action: 'approve' });
    step('ciba_approve', res.status === 200, `status=${res.status} body=${res.body}`);
  }

  res = lib.pollCiba(u, authReqId, cibaInterval, isIc ? 0 : 0.2);
  step('ciba_poll', res.status === 200 && !!res.json('access_token'), `status=${res.status}`);

  console.log('ALL SMOKE CHECKS PASSED');
}
