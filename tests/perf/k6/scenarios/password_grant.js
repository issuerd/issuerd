// SPDX-License-Identifier: Apache-2.0
// Scenario: POST /token grant_type=password (ROPC) with a rotating pool of
// distinct users — password-hash-bound on both servers (Argon2id on both:
// Issuerd m=19,456 KiB/t=2/p=1, Keycloak 26.7 m=7,168 KiB/t=5/p=1 — each
// server's out-of-box default). Each grant also persists user +
// client session rows and login events.
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');

export const options = {
  scenarios: {
    main: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 20),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);

export default function () {
  const user = lib.username(__VU * 100000 + __ITER);
  const res = http.post(u.token, {
    grant_type: 'password',
    client_id: lib.SERVICE.id,
    client_secret: lib.SERVICE.secret,
    username: user,
    password: lib.PASSWORD,
    scope: 'openid profile',
  });
  lib.logErr('password_grant', res);
  errors.add(
    !check(res, {
      'ropc 200': (r) => r.status === 200,
      'ropc token': (r) => !!r.json('access_token'),
    })
  );
}

export const handleSummary = lib.makeSummary('password_grant');
