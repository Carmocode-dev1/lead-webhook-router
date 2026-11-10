const ALLOWED_TOPICS = new Set([
  'web',
  'apps',
  'salesforce',
  'automation',
  'seo',
  'security',
  'general',
]);

export function sanitizeText(value, maxLength = 240) {
  if (typeof value !== 'string') {
    return '';
  }
  return value
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

export function validateLeadPayload(rawBody) {
  let data = rawBody;
  if (typeof rawBody === 'string') {
    if (!rawBody.trim()) {
      data = {};
    } else {
      try {
        data = JSON.parse(rawBody);
      } catch {
        return { ok: false, error: 'Invalid JSON payload.' };
      }
    }
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { ok: false, error: 'Payload must be a JSON object.' };
  }

  const name = sanitizeText(data.name || 'Visitor', 80);
  const topicRaw = sanitizeText(data.topic || 'general', 32).toLowerCase();
  const topic = ALLOWED_TOPICS.has(topicRaw) ? topicRaw : 'general';
  const message = sanitizeText(data.message || '', 300);
  const email = sanitizeText(data.email || '', 120);

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: 'Invalid email format.' };
  }

  return {
    ok: true,
    value: {
      name: name || 'Visitor',
      topic,
      message,
      email,
    },
  };
}
