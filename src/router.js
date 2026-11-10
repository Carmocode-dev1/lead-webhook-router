import crypto from 'node:crypto';
import { validateLeadPayload } from './validator.js';
import { SlidingWindowLimiter } from './rate-limiter.js';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store, private',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Content-Type': 'application/json; charset=utf-8',
};

function getHeader(headers = {}, target) {
  const lower = target.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return v;
    }
  }
  return undefined;
}

export function verifyHmacSignature(rawBody, signatureHeader, secret) {
  if (!secret) {
    return true;
  }
  if (!signatureHeader || typeof signatureHeader !== 'string') {
    return false;
  }
  const provided = signatureHeader.replace(/^sha256=/i, '').trim();
  const expected = crypto
    .createHmac('sha256', secret)
    .update(typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody || {}))
    .digest('hex');

  const bufA = Buffer.from(provided, 'utf8');
  const bufB = Buffer.from(expected, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export function createLeadHandler({ env = process.env, limiter = new SlidingWindowLimiter() } = {}) {
  return async function handleRequest(event = {}) {
    if (event.httpMethod !== 'POST') {
      return {
        statusCode: 405,
        headers: { ...SECURITY_HEADERS, Allow: 'POST' },
        body: JSON.stringify({ error: 'Method not allowed.' }),
      };
    }

    const clientIp =
      getHeader(event.headers, 'x-nf-client-connection-ip') ||
      getHeader(event.headers, 'x-forwarded-for')?.split(',')[0]?.trim() ||
      'unknown';

    const rate = limiter.check(clientIp);
    if (!rate.allowed) {
      return {
        statusCode: 429,
        headers: { ...SECURITY_HEADERS, 'Retry-After': String(rate.retryAfterSec) },
        body: JSON.stringify({ error: 'Too many requests. Please wait before retrying.' }),
      };
    }

    const signingSecret = env.WEBHOOK_SIGNING_SECRET || '';
    if (signingSecret) {
      const sig = getHeader(event.headers, 'x-webhook-signature');
      if (!verifyHmacSignature(event.body || '', sig, signingSecret)) {
        return {
          statusCode: 401,
          headers: SECURITY_HEADERS,
          body: JSON.stringify({ error: 'Invalid webhook signature.' }),
        };
      }
    }

    const phone = env.WHATSAPP_NUMBER || '';
    if (!/^[1-9]\d{7,14}$/.test(phone)) {
      return {
        statusCode: 503,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({ error: 'Contact channel is temporarily unavailable. Use email instead.' }),
      };
    }

    const parsed = validateLeadPayload(event.body || '{}');
    if (!parsed.ok) {
      return {
        statusCode: 400,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({ error: parsed.error }),
      };
    }

    const { name, topic, message } = parsed.value;
    const summaryText = message
      ? `Hello, I am ${name} (${topic}). ${message}`
      : `Hello, I am ${name} and would like to discuss a ${topic} project.`;

    const redirectUrl = `https://wa.me/${phone}?text=${encodeURIComponent(summaryText)}`;
    const mode = getHeader(event.headers, 'accept') || '';

    if (mode.includes('text/html')) {
      return {
        statusCode: 303,
        headers: { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8', Location: redirectUrl },
        body: '',
      };
    }

    return {
      statusCode: 200,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({
        status: 'routed',
        topic,
        redirectUrl,
        remainingQuota: rate.remaining,
      }),
    };
  };
}
