// k6 Load Test Script for SecureOps360
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 100 },  // Ramp to 100
    { duration: '2m', target: 100 },   // Stay at 100
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // 95% of requests under 2s
    http_req_failed: ['rate<0.1'],     // Error rate under 10%
    errors: ['rate<0.1'],
  },
};

const API_ENDPOINT = __ENV.API_ENDPOINT || 'https://your-api-endpoint.amazonaws.com/dev';

const testEvents = [
  {
    source: 'load-test',
    actor: { type: 'user', id: 'loadtest@example.com', ip: '203.0.113.1' },
    action: 'TestAction',
    resource: { type: 'api', id: 'load-test-resource' },
    severity_hint: 1,
    payload: { test: true, timestamp: new Date().toISOString() }
  },
  {
    source: 'load-test',
    actor: { type: 'user', id: 'admin@example.com', ip: '198.51.100.1' },
    action: 'AdminAction',
    resource: { type: 'database', id: 'test-db' },
    severity_hint: 3,
    payload: { test: true, action: 'admin_test' }
  }
];

export default function() {
  // Select random test event
  const event = testEvents[Math.floor(Math.random() * testEvents.length)];
  
  // Add unique event ID
  event.event_id = `load-test-${Date.now()}-${Math.random()}`;
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };
  
  // Health check (20% of requests)
  if (Math.random() < 0.2) {
    const healthResponse = http.get(`${API_ENDPOINT}/health`, params);
    const healthSuccess = check(healthResponse, {
      'health status is 200': (r) => r.status === 200,
    });
    errorRate.add(!healthSuccess);
  }
  
  // Event ingestion (80% of requests)
  const response = http.post(`${API_ENDPOINT}/ingest/events`, JSON.stringify(event), params);
  
  const success = check(response, {
    'status is 200 or 207': (r) => r.status === 200 || r.status === 207,
    'response time < 2000ms': (r) => r.timings.duration < 2000,
    'response has processed field': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.hasOwnProperty('processed');
      } catch {
        return false;
      }
    },
  });
  
  errorRate.add(!success);
  
  sleep(Math.random() * 2 + 1); // Random sleep 1-3 seconds
}
