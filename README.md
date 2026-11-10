# Serverless Lead & Contact Router

Lightweight Node.js serverless handler designed for static sites and CRM intake flows where phone numbers, webhook secrets, and destination targets must remain out of client-side code.

## Security & Reliability Controls

- **Environment-only secrets:** Destination phone numbers and signing keys live strictly in runtime environment variables, never in client HTML/JS or git history.
- **No-cache / no-index headers:** Every response enforces `Cache-Control: no-store, private`, `X-Robots-Tag: noindex, nofollow, noarchive`, and `Referrer-Policy: no-referrer`.
- **HMAC-SHA256 verification:** Optional webhook signature validation (`X-Webhook-Signature`) using `crypto.timingSafeEqual` for server-to-server CRM calls.
- **Sliding-window rate limiting:** Prevents abuse per client IP using injectable clock state for deterministic unit tests.
- **Input sanitization:** Strips control characters, enforces length limits, and validates allowed topics before generating redirects or CRM payloads.

## Layout

```
src/validator.js      Payload parsing and control-character sanitization
src/rate-limiter.js   Sliding-window rate limiter with pruning
src/router.js         Serverless HTTP handler (Netlify / AWS Lambda event shape)
tests/router.test.mjs Automated integration tests using node:test
```

## Running Tests

```bash
npm test
```
