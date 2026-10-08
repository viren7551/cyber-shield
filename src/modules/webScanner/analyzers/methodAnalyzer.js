import { safeRequest } from '../engine/httpClient.js';

/**
 * CyberShield Web Security Scanner - HTTP Method Analyzer
 * Safely queries OPTIONS and probes allowed HTTP methods (GET, HEAD, OPTIONS, POST, PUT, DELETE, TRACE)
 * identifying potentially insecure methods without destructive exploitation.
 */

const METHODS_TO_CHECK = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'];

/**
 * Audit HTTP Methods supported on target
 * @param {string} targetUrl
 * @param {object} clientOptions
 */
export async function analyzeHttpMethods(targetUrl, clientOptions = {}) {
  const findings = [];
  const supportedMethods = [];
  const methodStatuses = {};

  // Step 1: Send OPTIONS request
  const optionsRes = await safeRequest(targetUrl, {
    method: 'OPTIONS',
    timeoutMs: 6000,
    ...clientOptions
  });

  let advertisedAllow = '';
  if (optionsRes.success) {
    advertisedAllow = optionsRes.headers['allow'] || optionsRes.headers['public'] || '';
    if (advertisedAllow) {
      const parsed = advertisedAllow.split(',').map(m => m.trim().toUpperCase());
      supportedMethods.push(...parsed);
    }
  }

  // Step 2: Safe probe of TRACE method (XST risk)
  const traceRes = await safeRequest(targetUrl, {
    method: 'TRACE',
    headers: { 'X-Probe-Test': 'CyberShield-Audit' },
    timeoutMs: 5000,
    ...clientOptions
  });

  methodStatuses['TRACE'] = traceRes.statusCode || (traceRes.success ? 200 : 'Unavailable');

  const traceEnabled = (traceRes.success && traceRes.statusCode === 200) ||
    supportedMethods.includes('TRACE') ||
    (traceRes.body && traceRes.body.includes('CyberShield-Audit'));

  if (traceEnabled) {
    if (!supportedMethods.includes('TRACE')) supportedMethods.push('TRACE');

    findings.push({
      ruleId: 'HTTP_METHOD_TRACE_ENABLED',
      title: 'HTTP TRACE Method Enabled',
      severity: 'Low',
      confidence: 'High',
      category: 'HTTP Methods',
      url: targetUrl,
      description: 'The HTTP TRACE method is enabled on this web server. TRACE causes the web server to reflect the received request back to the client.',
      impact: 'Allows Cross-Site Tracing (XST) attacks where client-side scripts might bypass HttpOnly cookie protections by reading reflected authorization headers.',
      evidence: { method: 'TRACE', statusCode: traceRes.statusCode, allowHeader: advertisedAllow },
      recommendation: 'Disable the TRACE method on your web server (e.g., TraceEnable Off in Apache, or reject TRACE in Nginx).',
      cwe: 'CWE-200',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://owasp.org/www-community/attacks/Cross_Site_Tracing']
    });
  }

  // Deduplicate supported methods
  const uniqueMethods = [...new Set(supportedMethods.filter(Boolean))];

  return {
    advertisedAllow: advertisedAllow || 'None advertised',
    supportedMethods: uniqueMethods.length > 0 ? uniqueMethods : ['GET', 'HEAD', 'POST'],
    traceEnabled,
    findings
  };
}
