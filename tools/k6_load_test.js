// DFIM API Load Test — k6 World-Class Benchmark
// Escalating load: 50 → 1000 VUs, all endpoints, 5 min sustained

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const healthLatency = new Trend('health_latency');
const fleetLatency = new Trend('fleet_latency');
const assetsLatency = new Trend('assets_latency');
const enrollLatency = new Trend('enroll_latency');
const verifyLatency = new Trend('verify_latency');
const telemetryLatency = new Trend('telemetry_latency');
const errorRate = new Rate('errors');

const BASE = 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '30s', target: 50 },   // warm-up
    { duration: '1m',  target: 200 },  // ramp
    { duration: '2m',  target: 500 },  // steady load
    { duration: '1m',  target: 1000 }, // peak
    { duration: '30s', target: 0 },    // cool-down
  ],
  thresholds: {
    'health_latency': ['p(50)<5', 'p(99)<50'],
    'fleet_latency':  ['p(50)<10', 'p(99)<100'],
    'errors':         ['rate<0.01'],
  },
};

export default function() {
  group('health', () => {
    const t0 = Date.now();
    const r = http.get(`${BASE}/health`);
    healthLatency.add(Date.now() - t0);
    check(r, { 'status 200': (r) => r.status === 200 }) || errorRate.add(1);
  });

  sleep(Math.random() * 0.5);

  group('fleet', () => {
    const t0 = Date.now();
    const r = http.get(`${BASE}/v1/fleet/summary`);
    fleetLatency.add(Date.now() - t0);
    check(r, { 'status 200': (r) => r.status === 200 }) || errorRate.add(1);
  });

  sleep(Math.random() * 0.5);

  group('assets', () => {
    const t0 = Date.now();
    const r = http.get(`${BASE}/v1/assets`);
    assetsLatency.add(Date.now() - t0);
    check(r, { 'status 200': (r) => r.status === 200 }) || errorRate.add(1);
  });

  sleep(Math.random() * 0.3);

  // Enroll a new asset (creates load)
  const vuId = __VU;
  const iterId = __ITER;
  const assetId = `perf-${vuId}-${iterId}`;
  
  group('enroll', () => {
    const t0 = Date.now();
    const payload = JSON.stringify({
      asset_id: assetId,
      display_name: `Bench Asset ${vuId}`,
      asset_kind: 'benchmark',
      host_name: `node-${vuId % 10}`,
    });
    const r = http.post(`${BASE}/v1/assets/enroll`, payload, {
      headers: { 'Content-Type': 'application/json' },
    });
    enrollLatency.add(Date.now() - t0);
    check(r, { 'created': (r) => r.status === 201 || r.status === 409 }) || errorRate.add(1);
  });

  // Verify it
  sleep(Math.random() * 0.2);
  group('verify', () => {
    const t0 = Date.now();
    const r = http.put(`${BASE}/v1/assets/${assetId}/verify`, '{}', {
      headers: { 'Content-Type': 'application/json' },
    });
    verifyLatency.add(Date.now() - t0);
    check(r, { 'status 200': (r) => r.status === 200 }) || errorRate.add(1);
  });

  sleep(Math.random() * 0.2);

  // Telemetry ingest
  group('telemetry', () => {
    const t0 = Date.now();
    const events = JSON.stringify([{
      event_id: `evt-${vuId}-${iterId}`,
      event_type: 'dfim.benchmark.test',
      asset_id: assetId,
      outcome: 'success',
      timestamp: new Date().toISOString(),
      details: {},
    }]);
    const r = http.post(`${BASE}/v1/telemetry/ingest`, events, {
      headers: { 'Content-Type': 'application/json' },
    });
    telemetryLatency.add(Date.now() - t0);
    check(r, { 'ingested': (r) => r.status === 200 }) || errorRate.add(1);
  });

  sleep(Math.random() * 0.3);
}
