import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createLeadHandler } from '../src/router.js';
import { SlidingWindowLimiter } from '../src/rate-limiter.js';

test('rejects non-POST methods with 405 and Allow header', async () => {
  const handler = createLeadHandler({ env: { WHATSAPP_NUMBER: '15551234567' } });
  const res = await handler({ httpMethod: 'GET' });
  assert.equal(res.statusCode, 405);
  assert.equal(res.headers.Allow, 'POST');
});

test('returns 503 when WHATSAPP_NUMBER env var is missing or malformed', async () => {
  const handler = createLeadHandler({ env: { WHATSAPP_NUMBER: 'invalid-phone' } });
  const res = await handler({ httpMethod: 'POST', body: '{}' });
  assert.equal(res.statusCode, 503);
});

test('validates JSON payload and email format', async () => {
  const handler = createLeadHandler({ env: { WHATSAPP_NUMBER: '15551234567' } });

  const badJson = await handler({ httpMethod: 'POST', body: '{broken' });
  assert.equal(badJson.statusCode, 400);

  const badEmail = await handler({
    httpMethod: 'POST',
    body: JSON.stringify({ name: 'Ana', email: 'not-an-email' }),
  });
  assert.equal(badEmail.statusCode, 400);
});

test('enforces sliding-window rate limiting per IP', async () => {
  let clock = 1000;
  const limiter = new SlidingWindowLimiter({ maxRequests: 2, windowMs: 10000, now: () => clock });
  const handler = createLeadHandler({ env: { WHATSAPP_NUMBER: '15551234567' }, limiter });

  const req = {
    httpMethod: 'POST',
    headers: { 'x-forwarded-for': '203.0.113.10' },
    body: JSON.stringify({ topic: 'salesforce', message: 'API integration inquiry' }),
  };

  assert.equal((await handler(req)).statusCode, 200);
  assert.equal((await handler(req)).statusCode, 200);

  const throttled = await handler(req);
  assert.equal(throttled.statusCode, 429);
  assert.ok(Number(throttled.headers['Retry-After']) >= 1);

  clock += 11000;
  assert.equal((await handler(req)).statusCode, 200);
});

test('verifies HMAC-SHA256 signature when signing secret is enabled', async () => {
  const secret = 'test-signing-key';
  const body = JSON.stringify({ name: 'Carlos', topic: 'web', message: 'Landing rebuild' });
  const sig = crypto.createHmac('sha256', secret).update(body).digest('hex');

  const handler = createLeadHandler({
    env: { WHATSAPP_NUMBER: '15551234567', WEBHOOK_SIGNING_SECRET: secret },
  });

  const rejected = await handler({
    httpMethod: 'POST',
    headers: { 'x-webhook-signature': 'sha256=deadbeef' },
    body,
  });
  assert.equal(rejected.statusCode, 401);

  const accepted = await handler({
    httpMethod: 'POST',
    headers: { 'x-webhook-signature': `sha256=${sig}` },
    body,
  });
  assert.equal(accepted.statusCode, 200);
  const parsed = JSON.parse(accepted.body);
  assert.equal(parsed.topic, 'web');
  assert.ok(parsed.redirectUrl.startsWith('https://wa.me/15551234567?text='));
});
