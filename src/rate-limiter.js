export class SlidingWindowLimiter {
  constructor({ maxRequests = 5, windowMs = 60_000, now = () => Date.now() } = {}) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.now = now;
    this.buckets = new Map();
  }

  check(key) {
    const id = String(key || 'anonymous');
    const currentTime = this.now();
    const cutoff = currentTime - this.windowMs;

    const existing = this.buckets.get(id) || [];
    const active = existing.filter((ts) => ts > cutoff);

    if (active.length >= this.maxRequests) {
      const oldest = active[0];
      const retryAfterSec = Math.max(1, Math.ceil((oldest + this.windowMs - currentTime) / 1000));
      this.buckets.set(id, active);
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    active.push(currentTime);
    this.buckets.set(id, active);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - active.length),
      retryAfterSec: 0,
    };
  }
}
