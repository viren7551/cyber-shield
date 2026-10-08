import { maskValue } from '../evidence/evidenceRedactor.js';

/**
 * CyberShield Web Security Scanner - Cookie Security Analyzer
 * Audits cookies for Secure, HttpOnly, SameSite, Domain scope, and Expiration flags.
 */

// Common session and authentication cookie name patterns
const AUTH_COOKIE_PATTERNS = [
  /sess/i, /token/i, /auth/i, /jwt/i, /login/i, /id/i, /connect\.sid/i,
  /phpsessid/i, /jsessionid/i, /asp\.net_sessionid/i, /laravel_session/i
];

/**
 * Parse an individual Set-Cookie header string into structured attributes
 */
export function parseCookie(rawCookie) {
  if (!rawCookie || typeof rawCookie !== 'string') return null;

  const parts = rawCookie.split(';').map(p => p.trim());
  if (parts.length === 0 || !parts[0].includes('=')) return null;

  const firstEq = parts[0].indexOf('=');
  const name = parts[0].substring(0, firstEq).trim();
  const rawValue = parts[0].substring(firstEq + 1).trim();

  let secure = false;
  let httpOnly = false;
  let sameSite = 'Missing';
  let domain = null;
  let path = null;
  let expires = null;
  let maxAge = null;

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const lower = part.toLowerCase();

    if (lower === 'secure') {
      secure = true;
    } else if (lower === 'httponly') {
      httpOnly = true;
    } else if (lower.startsWith('samesite=')) {
      sameSite = part.split('=')[1].trim();
    } else if (lower.startsWith('domain=')) {
      domain = part.split('=')[1].trim();
    } else if (lower.startsWith('path=')) {
      path = part.split('=')[1].trim();
    } else if (lower.startsWith('expires=')) {
      expires = part.substring(part.indexOf('=') + 1).trim();
    } else if (lower.startsWith('max-age=')) {
      maxAge = parseInt(part.split('=')[1].trim(), 10);
    }
  }

  const isSessionCookie = !expires && maxAge === null;
  const isAuthLike = AUTH_COOKIE_PATTERNS.some(pat => pat.test(name));

  return {
    name,
    maskedValue: maskValue(rawValue),
    secure,
    httpOnly,
    sameSite,
    domain,
    path: path || '/',
    expires,
    maxAge,
    isSessionCookie,
    isAuthLike,
    rawHeader: `${name}=${maskValue(rawValue)}; ${parts.slice(1).join('; ')}`
  };
}

/**
 * Analyze an array or single Set-Cookie header
 * @param {Array<string>|string} rawSetCookies
 * @param {string} targetUrl
 */
export function analyzeCookies(rawSetCookies, targetUrl) {
  const findings = [];
  const cookiesList = [];

  if (!rawSetCookies) return { cookies: [], findings: [] };

  const rawArray = Array.isArray(rawSetCookies) ? rawSetCookies : [rawSetCookies];
  const isHttps = targetUrl.startsWith('https://');

  for (const raw of rawArray) {
    const parsed = parseCookie(raw);
    if (!parsed) continue;

    cookiesList.push(parsed);

    // 1. Missing Secure flag on HTTPS
    if (isHttps && !parsed.secure) {
      findings.push({
        ruleId: 'SEC_COOKIE_MISSING_SECURE',
        title: `Cookie "${parsed.name}" Missing "Secure" Flag`,
        severity: parsed.isAuthLike ? 'Medium' : 'Low',
        confidence: 'High',
        category: 'Cookie Security',
        url: targetUrl,
        description: `The cookie "${parsed.name}" was set over HTTPS without the "Secure" attribute. The browser may transmit this cookie over unencrypted HTTP connections.`,
        impact: 'If a user navigates to an HTTP link or an active adversary performs SSL-stripping, the cookie is transmitted in cleartext and can be intercepted.',
        evidence: { cookie: parsed.name, observed: parsed.rawHeader },
        recommendation: `Add the "Secure" flag to Set-Cookie header for "${parsed.name}".`,
        cwe: 'CWE-614',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://owasp.org/www-community/controls/SecureFlag']
      });
    }

    // 2. Missing HttpOnly flag on sensitive/session cookies
    if (!parsed.httpOnly) {
      const isHighPriority = parsed.isAuthLike;
      findings.push({
        ruleId: 'SEC_COOKIE_MISSING_HTTPONLY',
        title: `Cookie "${parsed.name}" Missing "HttpOnly" Flag`,
        severity: isHighPriority ? 'Medium' : 'Low',
        confidence: isHighPriority ? 'High' : 'Medium',
        category: 'Cookie Security',
        url: targetUrl,
        description: `The cookie "${parsed.name}" does not specify the "HttpOnly" attribute, making it readable by client-side JavaScript via document.cookie.`,
        impact: 'If an XSS vulnerability exists on any page on this domain, an attacker can steal this cookie and hijack the session.',
        evidence: { cookie: parsed.name, observed: parsed.rawHeader },
        recommendation: `Add "; HttpOnly" to the Set-Cookie definition for "${parsed.name}".`,
        cwe: 'CWE-1004',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://owasp.org/www-community/HttpOnly']
      });
    }

    // 3. SameSite analysis
    const sameSiteLower = parsed.sameSite.toLowerCase();
    if (sameSiteLower === 'missing') {
      findings.push({
        ruleId: 'SEC_COOKIE_MISSING_SAMESITE',
        title: `Cookie "${parsed.name}" Missing "SameSite" Attribute`,
        severity: 'Low',
        confidence: 'High',
        category: 'Cookie Security',
        url: targetUrl,
        description: `The cookie "${parsed.name}" does not define an explicit SameSite attribute (Lax, Strict, or None).`,
        impact: 'Leaving SameSite unspecified relies on browser defaults and increases risk of Cross-Site Request Forgery (CSRF).',
        evidence: { cookie: parsed.name, observed: parsed.rawHeader },
        recommendation: `Set SameSite=Lax (for top-level navigations) or SameSite=Strict for sensitive session cookies.`,
        cwe: 'CWE-1275',
        owasp: 'A01:2021 - Broken Access Control',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite']
      });
    } else if (sameSiteLower === 'none' && !parsed.secure) {
      findings.push({
        ruleId: 'SEC_COOKIE_SAMESITE_NONE_WITHOUT_SECURE',
        title: `Cookie "${parsed.name}" Has SameSite=None Without Secure`,
        severity: 'Medium',
        confidence: 'High',
        category: 'Cookie Security',
        url: targetUrl,
        description: `The cookie "${parsed.name}" sets SameSite=None without the Secure attribute. Modern browsers will reject this cookie entirely.`,
        impact: 'Cookie may be rejected by user agents or transmitted over plaintext channels in third-party contexts.',
        evidence: { cookie: parsed.name, observed: parsed.rawHeader },
        recommendation: 'Cookies with SameSite=None must always include the Secure attribute.',
        cwe: 'CWE-614',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://web.dev/samesite-cookies-explained/']
      });
    }

    // 4. Overly broad domain scope
    if (parsed.domain && (parsed.domain.startsWith('.') || parsed.domain.split('.').length <= 2)) {
      findings.push({
        ruleId: 'SEC_COOKIE_OVERLY_BROAD_DOMAIN',
        title: `Cookie "${parsed.name}" Has Overly Broad Domain Scope`,
        severity: 'Low',
        confidence: 'Medium',
        category: 'Cookie Security',
        url: targetUrl,
        description: `The cookie specifies domain="${parsed.domain}", sharing it across all subdomains.`,
        impact: 'If any subordinate domain is compromised, the attacker can access or overwrite this cookie.',
        evidence: { cookie: parsed.name, domain: parsed.domain },
        recommendation: 'Omit the Domain attribute to restrict the cookie strictly to the host that issued it.',
        cwe: 'CWE-565',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html']
      });
    }
  }

  return { cookies: cookiesList, findings };
}
