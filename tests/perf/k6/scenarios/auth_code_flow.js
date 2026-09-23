// SPDX-License-Identifier: Apache-2.0
// Scenario: full authorization-code browser flow per iteration (fresh SSO
// state, real credential check): GET /auth → login POST → code → token
// exchange. Issuerd: SPA JSON login API; Keycloak: HTML form. PKCE S256 on
// both.
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');
const flowMs = new Trend('flow_ms', true);

export const options = {
  scenarios: {
    main: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 15),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);

export default async function () {
  // Force a real login every iteration (no SSO reuse).
  http.cookieJar().clear(t.base);
  const start = Date.now();
  const user = lib.username(__VU * 100000 + __ITER);
  const { code, pkce, stage } = await lib.loginGetCode(t, user, lib.PASSWORD);
  if (!code) {
    errors.add(1);
    console.error(`flow failed at ${stage}`);
    return;
  }
  const res = lib.exchangeCode(t, code, pkce);
  lib.logErr('auth_code_flow', res);
  flowMs.add(Date.now() - start);
  errors.add(
    !check(res, {
      'code exchange 200': (r) => r.status === 200,
      'access token': (r) => !!r.json('access_token'),
    })
  );
}

export const handleSummary = lib.makeSummary('auth_code_flow');
