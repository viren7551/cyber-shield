import { safeRequest } from '../engine/httpClient.js';

/**
 * CyberShield Web Security Scanner - CORS Misconfiguration Analyzer
 * Safely tests Cross-Origin Resource Sharing policies for dangerous wildcard
 * configurations, arbitrary origin reflection, and insecure credentials handling.
 */

const TEST_ORIGIN = 'https://security-audit-probe.example';

/**
 * Perform safe CORS policy audit on a target endpoint
 * @param {string} targetUrl
 * @param {object} baseHeaders - Headers observed on base response
 * @param {object} clientOptions - HTTP options
 */
export async function analyzeCors(targetUrl, baseHeaders = {}, clientOptions = {}) {
  const findings = [];

  // Check base headers first
  const baseAcao = baseHeaders['access-control-allow-origin'];
  const baseAcac = baseHeaders['access-control-allow-credentials'];
  const baseAcam = baseHeaders['access-control-allow-methods'];
  const baseAcah = baseHeaders['access-control-allow-headers'];

  // Send safe test request with arbitrary Origin
  const corsProbeRes = await safeRequest(targetUrl, {
    method: 'OPTIONS',
    headers: {
      'Origin': TEST_ORIGIN,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'X-Custom-Test'
    },
    timeoutMs: 6000,
    ...clientOptions
  });

  const probeHeaders = corsProbeRes.success ? corsProbeRes.headers : {};
  const acao = probeHeaders['access-control-allow-origin'] || baseAcao;
  const acac = (probeHeaders['access-control-allow-credentials'] || baseAcac)?.toLowerCase() === 'true';
  const acam = probeHeaders['access-control-allow-methods'] || baseAcam;
  const acah = probeHeaders['access-control-allow-headers'] || baseAcah;

  const corsStatus = {
    allowOrigin: acao || 'Not Configured',
    allowCredentials: acac,
    allowMethods: acam || 'Default',
    allowHeaders: acah || 'Default',
    originReflected: false
  };

  if (!acao) {
    return { status: corsStatus, findings };
  }

  // 1. Wildcard origin + Allow-Credentials
  if (acao === '*' && acac) {
    findings.push({
      ruleId: 'CORS_WILDCARD_WITH_CREDENTIALS',
      title: 'Dangerous CORS: Wildcard Origin With Credentials Allowed',
      severity: 'High',
      confidence: 'High',
      category: 'CORS Security',
      url: targetUrl,
      description: 'The server sets Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.',
      impact: 'While modern browsers reject this combination, legacy or non-standard user agents may expose authenticated user sessions to cross-origin theft.',
      evidence: { allowOrigin: acao, allowCredentials: true },
      recommendation: 'Do not use wildcard origins when credentials (cookies, authorization headers) are required. Maintain an explicit whitelist of trusted origins.',
      cwe: 'CWE-942',
      owasp: 'A01:2021 - Broken Access Control',
      references: ['https://portswigger.net/web-security/cors']
    });
  }

  // 2. Arbitrary Origin Reflection
  if (acao === TEST_ORIGIN) {
    corsStatus.originReflected = true;
    const isCritical = acac;

    findings.push({
      ruleId: isCritical ? 'CORS_ARBITRARY_ORIGIN_REFLECTION_WITH_CREDS' : 'CORS_ARBITRARY_ORIGIN_REFLECTION',
      title: isCritical
        ? 'Critical CORS: Arbitrary Origin Reflected With Credentials'
        : 'CORS Policy Reflects Arbitrary Origin Header',
      severity: isCritical ? 'Critical' : 'Medium',
      confidence: 'High',
      category: 'CORS Security',
      url: targetUrl,
      description: `The application dynamically reflects arbitrary incoming Origin headers ("${TEST_ORIGIN}") in Access-Control-Allow-Origin${isCritical ? ' with Access-Control-Allow-Credentials: true' : ''}.`,
      impact: isCritical
        ? 'Any website visited by an authenticated user can read private user data, bypass CSRF tokens, and hijack account details via cross-origin XMLHttpRequest/fetch.'
        : 'Any third-party website can read response bodies from this endpoint.',
      evidence: { sentOrigin: TEST_ORIGIN, reflectedAcao: acao, allowCredentials: acac },
      recommendation: 'Validate the Origin header against a strict, static server-side whitelist before echoing it in Access-Control-Allow-Origin.',
      cwe: 'CWE-942',
      owasp: 'A01:2021 - Broken Access Control',
      references: [
        'https://portswigger.net/web-security/cors',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html'
      ]
    });
  }

  // 3. Overly broad public wildcard on potentially sensitive paths
  const isSensitivePath = /api|auth|account|user|profile|admin/i.test(targetUrl);
  if (acao === '*' && isSensitivePath && !acac) {
    findings.push({
      ruleId: 'CORS_OPEN_WILDCARD_SENSITIVE_ENDPOINT',
      title: 'Public Wildcard CORS on API/Sensitive Endpoint',
      severity: 'Low',
      confidence: 'Medium',
      category: 'CORS Security',
      url: targetUrl,
      description: 'The endpoint returns Access-Control-Allow-Origin: * on an API or account path.',
      impact: 'Allows all third-party web applications to read data returned by this endpoint. If public data is intended, this is informational; otherwise, internal data may leak.',
      evidence: { allowOrigin: '*' },
      recommendation: 'If this endpoint returns confidential data, restrict the allowed origins to authorized front-end domains.',
      cwe: 'CWE-942',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS']
    });
  }

  return { status: corsStatus, findings };
}
