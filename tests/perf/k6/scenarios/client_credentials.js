// SPDX-License-Identifier: Apache-2.0
// Scenario: POST /token grant_type=client_credentials — raw token issuance
// path (JWT signing + client auth, no password hashing, no session rows).
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import * as lib from '../lib.js';

const errors = new Rate('errors');

export const options = {
  scenarios: {
    main: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 50),
      duration: __ENV.DURATION || '60s',
    },
  },
  summaryTrendStats: lib.TREND_STATS,
  thresholds: { errors: ['rate<0.01'] },
};

const t = lib.target();
const u = lib.urls(t);
const BODY = {
  grant_type: 'client_credentials',
  client_id: lib.SERVICE.id,
  client_secret: lib.SERVICE.secret,
  scope: 'openid profile',
};

export default function () {
  const res = http.post(u.token, BODY);
  errors.add(
    !check(res, {
      'cc 200': (r) => r.status === 200,
      'cc token': (r) => !!r.json('access_token'),
    })
  );
}

export const handleSummary = lib.makeSummary('client_credentials');
