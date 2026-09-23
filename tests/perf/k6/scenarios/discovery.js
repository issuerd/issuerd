// SPDX-License-Identifier: Apache-2.0
// Scenario: GET /.well-known/openid-configuration (static-ish JSON, realm cached).
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

export default function () {
  const res = http.get(u.discovery);
  errors.add(!check(res, { 'discovery 200': (r) => r.status === 200 }));
}

export const handleSummary = lib.makeSummary('discovery');
