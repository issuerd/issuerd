// SPDX-License-Identifier: Apache-2.0
// Scenario: GET /userinfo with a Bearer token — the token validation path
// (signature verify + claim assembly). Token is fetched once in setup().
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');

export const options = {
  scenarios: {
    main: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 100),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);

export function setup() {
  const res = http.post(u.token, {
    grant_type: 'password',
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    username: 'perfuser',
    password: lib.PASSWORD,
    scope: 'openid profile',
  });
  if (res.status !== 200) throw new Error(`setup token failed: ${res.status} ${res.body}`);
  return { token: res.json('access_token') };
}

export default function (data) {
  const res = http.get(u.userinfo, lib.bearerHeaders(data.token));
  errors.add(!check(res, { 'userinfo 200': (r) => r.status === 200 }));
}

export const handleSummary = lib.makeSummary('userinfo');
