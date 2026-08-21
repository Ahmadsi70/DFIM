// DFIM Endurance Test — 1-hour sustained 500 VUs
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const hLatency = new Trend('health_latency');
const fLatency = new Trend('fleet_latency');
const errors = new Rate('errors');
const BASE = 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '1m', target: 100 },
    { duration: '1m', target: 500 },
    { duration: '56m', target: 500 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    errors: ['rate<0.02'],
  },
};

export default function() {
  const paths = ['/health', '/v1/fleet/summary', '/v1/assets', '/v1/policies'];
  const path = paths[__ITER % paths.length];

  const t0 = Date.now();
  const r = http.get(`${BASE}${path}`);
  const el = Date.now() - t0;

  if (path === '/health') hLatency.add(el);
  else fLatency.add(el);

  const ok = check(r, { 'status_ok': (r) => r.status === 200 });
  if (!ok) errors.add(1);

  sleep(0.5 + Math.random() * 0.5);
}
