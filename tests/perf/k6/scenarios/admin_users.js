// SPDX-License-Identifier: Apache-2.0
// Scenario: Admin API user provisioning — POST /admin/realms/perf/users.
// Two modes:
//   MODE=rate (default): constant-vus for DURATION — measures provisioning
//                        throughput/latency (each create hashes the password).
//   MODE=seed: per-vu-iterations, VUS VUs × ceil(SEED_N/VUS) iterations each —
//                        deterministic per-VU __ITER so NAMING=pool produces
//                        exactly user0001..user{SEED_N} with no gaps or
//                        collisions (existing users → 409, skipped silently).
// Usernames: {PREFIX}{vu}_{iter} — PREFIX must differ per seed round.
// WITH_PASSWORD=false creates users without credentials (fast bulk seeding).
// The admin token is refreshed automatically on 401 (KC master tokens are
// short-lived; long seeding runs outlive them).
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import { fail } from 'k6';
import * as lib from '../lib.js';

const errors = new Rate('errors');

const MODE = __ENV.MODE || 'rate';
export const options =
  MODE === 'seed'
    ? {
        scenarios: {
          main: {
            executor: 'per-vu-iterations',
            vus: Number(__ENV.VUS || 20),
            iterations: Math.ceil(Number(__ENV.SEED_N || 1000) / Number(__ENV.VUS || 20)),
            maxDuration: __ENV.MAX_DURATION || '3h',
          },
        },
        summaryTrendStats: lib.TREND_STATS,
        thresholds: { errors: ['rate<0.01'] },
      }
    : {
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
const PREFIX = __ENV.PREFIX || 's';
const WITH_PASSWORD = (__ENV.WITH_PASSWORD || 'true') === 'true';
const VUS = Number(__ENV.VUS || 20);
const SEED_N = Number(__ENV.SEED_N || 1000);
// NAMING=pool: deterministic user0001..userNNNN (matches lib.username() used
// by the load scenarios); otherwise unique {PREFIX}{vu}_{iter} names.
const POOL_NAMING = (__ENV.NAMING || '') === 'pool';
const PER_VU = Math.ceil(SEED_N / VUS);

let token = null;

function ensureToken() {
  if (!token) token = lib.adminToken(t);
  return token;
}

export function setup() {
  return { token: lib.adminToken(t) };
}

export default function (data) {
  token = token || data.token;
  if (POOL_NAMING && (__VU - 1) * PER_VU + __ITER + 1 > SEED_N) return; // overhang VU
  const name = POOL_NAMING
    ? `user${String((__VU - 1) * PER_VU + __ITER + 1).padStart(4, '0')}`
    : `${PREFIX}${__VU}_${__ITER}`;
  const body = {
    username: name,
    enabled: true,
    emailVerified: true,
    email: `${name}@example.com`,
    firstName: 'Perf',
    lastName: 'User',
  };
  if (WITH_PASSWORD) {
    body.credentials = [{ type: 'password', value: lib.PASSWORD, temporary: false }];
  }
  let res = http.post(u.adminUsers, JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) {
    token = lib.adminToken(t);
    res = http.post(u.adminUsers, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
  }
  if (res.status === 409) return; // re-run collision — not a failure
  errors.add(!check(res, { 'create 201': (r) => r.status === 201 }));
}

export const handleSummary = lib.makeSummary('admin_users');
