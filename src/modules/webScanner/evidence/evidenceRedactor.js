/**
 * CyberShield Web Security Scanner - Evidence Sanitizer & Redactor
 * Automatically sanitizes sensitive tokens, passwords, cookies, and secrets
 * before storing in logs, database models, or rendering in UI.
 */

const SENSITIVE_PARAM_NAMES = [
  'password', 'passwd', 'pass', 'secret', 'token', 'access_token', 'refresh_token',
  'jwt', 'api_key', 'apikey', 'auth', 'authorization', 'credit_card', 'cc_number',
  'cvv', 'session', 'session_id', 'phpsessid', 'jsessionid', 'connect.sid'
];

/**
 * Mask a string showing at most 3 prefix characters and masking the rest
 */
export function maskValue(val) {
  if (!val || typeof val !== 'string') return '********';
  const trimmed = val.trim();
  if (trimmed.length <= 4) return '********';
  return trimmed.substring(0, 3) + '*'.repeat(Math.min(trimmed.length - 3, 16));
}

/**
 * Mask raw Set-Cookie header strings
 * e.g. "session_id=abc123xyz456; Path=/; Secure; HttpOnly"
 * -> "session_id=abc***; Path=/; Secure; HttpOnly"
 */
export function maskCookieHeader(cookieStr) {
  if (!cookieStr || typeof cookieStr !== 'string') return cookieStr;
  return cookieStr.replace(/^([^=]+)=([^;]+)(.*)$/, (match, name, val, rest) => {
    return `${name}=${maskValue(val)}${rest}`;
  });
}

/**
 * Recursively sanitize objects (headers, query params, form inputs)
 */
export function sanitizeEvidence(data) {
  if (!data) return data;
  if (typeof data === 'string') return data;
  if (Array.isArray(data)) return data.map(sanitizeEvidence);
  if (typeof data !== 'object') return data;

  const sanitized = {};
  for (const [key, val] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = SENSITIVE_PARAM_NAMES.some(s => lowerKey.includes(s));

    if (isSensitive && typeof val === 'string') {
      sanitized[key] = maskValue(val);
    } else if (lowerKey === 'authorization' && typeof val === 'string') {
      const parts = val.split(' ');
      sanitized[key] = parts.length > 1 ? `${parts[0]} ${maskValue(parts[1])}` : maskValue(val);
    } else if (lowerKey === 'set-cookie') {
      if (Array.isArray(val)) {
        sanitized[key] = val.map(c => maskCookieHeader(c));
      } else {
        sanitized[key] = maskCookieHeader(String(val));
      }
    } else if (typeof val === 'object' && val !== null) {
      sanitized[key] = sanitizeEvidence(val);
    } else {
      sanitized[key] = val;
    }
  }

  return sanitized;
}
