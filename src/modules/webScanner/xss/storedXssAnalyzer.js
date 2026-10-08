import { safeRequest } from '../engine/httpClient.js';
import { analyzeReflectionContext, canAlterParsingContext, XSS_CONTEXTS, FINDING_STATES } from './contextAnalyzer.js';
import { analyzeOutputEncoding, ENCODING_STATUS } from './encodingAnalyzer.js';

/**
 * CyberShield Web Security Scanner - Stored XSS Lifecycle Analyzer
 * Evaluates the full stored XSS lifecycle:
 * POST input -> Storage Accepted -> Later Retrieval -> Reflection Context -> Encoding Evaluation.
 * Never claims confirmed XSS unless both storage AND retrieval in an unsafe context are demonstrated.
 */

const STORAGE_NAME_PATTERNS = [
  /comment/i, /message/i, /feedback/i, /review/i, /post/i,
  /bio/i, /about/i, /desc/i, /content/i, /body/i, /text/i,
  /notes/i, /title/i, /status/i, /summary/i, /details/i
];

const STORAGE_PATH_PATTERNS = [
  /comment/i, /feedback/i, /review/i, /post/i, /message/i,
  /profile/i, /forum/i, /contact/i, /ticket/i, /inquiry/i
];

/**
 * Passively analyze forms and endpoints for potential Stored XSS candidate locations.
 * @param {Array<object>} forms - Discovered forms
 * @param {Array<object>} endpoints - Discovered in-scope endpoints
 * @param {string} targetUrl - Root target application URL
 * @returns {Array<object>} - Stored XSS candidate findings
 */
export function analyzeStoredXssCandidates(forms = [], endpoints = [], targetUrl = '') {
  const findings = [];
  const reportedEndpoints = new Set();

  for (const form of forms) {
    if (!form) continue;
    const actionUrl = form.action || form.rawAction || targetUrl;
    if (!actionUrl) continue;

    const method = (form.method || 'GET').toUpperCase();
    const isStateChanging = method === 'POST' || method === 'PUT' || method === 'PATCH';

    const candidateInputs = [];
    let hasTextarea = false;

    for (const input of form.inputs || []) {
      if (!input || !input.name) continue;
      const name = input.name.toLowerCase();
      const type = (input.type || 'text').toLowerCase();

      if (type === 'password' || type === 'hidden') continue;

      const matchesStorageName = STORAGE_NAME_PATTERNS.some(p => p.test(name));
      if (type === 'textarea' || matchesStorageName) {
        if (type === 'textarea') hasTextarea = true;
        candidateInputs.push({ name: input.name, type });
      }
    }

    const matchesPath = STORAGE_PATH_PATTERNS.some(p => p.test(actionUrl));

    // Only flag state-changing forms with storage-like fields as candidates
    if (isStateChanging && (candidateInputs.length > 0 || matchesPath)) {
      const endpointKey = `${method}:${actionUrl}`;
      if (reportedEndpoints.has(endpointKey)) continue;
      reportedEndpoints.add(endpointKey);

      const fieldNames = candidateInputs.map(i => i.name).join(', ') || 'submission content';
      const reasoning = `The endpoint "${actionUrl}" accepts user input via HTTP ${method} on fields associated with persistent content (${fieldNames}). Storage and subsequent retrieval in an executable browser context have not been demonstrated. Passive candidate analysis only.`;

      findings.push({
        id: `stored_${Math.random().toString(36).substring(2, 9)}`,
        ruleId: 'STORED_XSS_CANDIDATE',
        title: `Potential Stored XSS Candidate on ${method} "${actionUrl}" (Field: ${fieldNames})`,
        category: 'Cross-Site Scripting',
        type: 'stored',
        severity: hasTextarea ? 'Medium' : 'Low',
        confidence: hasTextarea ? 'Medium' : 'Low',
        findingState: FINDING_STATES.NEEDS_MANUAL_VERIFICATION,
        status: 'Needs Manual Verification',
        verificationStatus: 'needs_verification',
        reflectionDetected: false,
        storageDetected: false,
        retrievalDetected: false,
        context: 'UNKNOWN',
        encoding: 'UNKNOWN',
        source: candidateInputs[0]?.name || 'content',
        sink: null,
        url: actionUrl,
        affectedUrls: [actionUrl],
        parameter: candidateInputs[0]?.name || 'content',
        method,
        reasoning,
        description: reasoning,
        impact: 'If submitted content is stored and later rendered into web pages without context-aware HTML entity encoding, Stored Cross-Site Scripting (Persistent XSS) will occur.',
        evidence: {
          storageEvidence: 'UNKNOWN',
          retrievalEvidence: 'UNKNOWN',
          reflectionContext: 'UNKNOWN',
          encoding: 'UNKNOWN',
          endpoint: actionUrl,
          httpMethod: method,
          candidateFields: candidateInputs.map(i => `${i.name} (${i.type})`),
          hasTextareaField: hasTextarea,
          storageIndicator: matchesPath ? 'Path matches storage pattern' : 'Input names match persistent field pattern',
          safetyNotice: 'Passive candidate observation. No state-changing data was submitted to the target.'
        },
        remediation: `1. Ensure all stored user content undergoes context-aware HTML entity encoding when rendered.
2. For rich text fields, sanitize on input and output using strict allowlists (e.g. DOMPurify).
3. Deploy Content Security Policy (CSP) with script-src 'self'.`,
        cwe: 'CWE-79',
        owasp: 'A03:2021 - Injection',
        references: [
          'https://owasp.org/www-community/attacks/xss/#stored-xss-attacks',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ]
      });
    }
  }

  return findings;
}

/**
 * Actively audits the complete Stored XSS lifecycle against a target form and retrieval endpoints.
 * @param {object} form - Form definition ({ action, method, inputs })
 * @param {Array<string>} retrievalUrls - Candidate URLs where stored content might be retrieved
 * @param {object} options - Request options
 * @returns {Promise<object|null>} - Stored XSS finding or null
 */
export async function auditStoredXssLifecycle(form, retrievalUrls = [], options = {}) {
  const { userAgent, timeoutMs = 4000 } = options;
  if (!form || !form.action) return null;

  const candidateInput = (form.inputs || []).find(i => {
    const type = (i.type || 'text').toLowerCase();
    const name = (i.name || '').toLowerCase();
    return type === 'textarea' || STORAGE_NAME_PATTERNS.some(p => p.test(name));
  }) || form.inputs?.[0];

  if (!candidateInput || !candidateInput.name) return null;

  const canaryId = Math.random().toString(36).substring(2, 8);
  const canaryToken = `STOREDXSS_${canaryId}`;
  const probePayload = `${canaryToken}'"><csxss>&`;

  // Build form body
  const bodyParams = new URLSearchParams();
  for (const inp of form.inputs || []) {
    if (!inp.name) continue;
    if (inp.name === candidateInput.name) {
      bodyParams.set(inp.name, probePayload);
    } else {
      bodyParams.set(inp.name, 'test');
    }
  }

  // 1. Submit POST request
  let postSuccess = false;
  try {
    const postRes = await safeRequest(form.action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString(),
      timeoutMs,
      userAgent
    });
    if (postRes.statusCode >= 200 && postRes.statusCode < 400) {
      postSuccess = true;
    }
  } catch {
    return null;
  }

  if (!postSuccess) return null;

  // 2. Check candidate retrieval URLs
  const candidateRetrievalList = Array.from(new Set([form.action, ...retrievalUrls]));

  for (const retUrl of candidateRetrievalList) {
    try {
      const getRes = await safeRequest(retUrl, {
        method: 'GET',
        timeoutMs,
        userAgent
      });

      if (!getRes.success || !getRes.body || typeof getRes.body !== 'string') continue;

      const body = getRes.body;
      const contextRes = analyzeReflectionContext(body, canaryToken);

      if (!contextRes.reflected) continue;

      // Persistence and retrieval confirmed!
      const encodingRes = analyzeOutputEncoding(body, canaryToken, '\'"><csxss>&');
      const alterability = canAlterParsingContext(encodingRes.unencodedChars, contextRes.context, contextRes.quoteChar);

      // If stored input is retrieved but safely encoded -> No XSS!
      if (encodingRes.status === ENCODING_STATUS.SAFE_ENCODED || encodingRes.encoding === 'HTML_ENTITIES') {
        const reasoning = 'Stored input is persisted and retrieved, but the application safely applies HTML entity encoding. No XSS vulnerability exists.';
        return {
          id: `stored_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'STORED_SAFE_ENCODING',
          title: `Stored Content Neutralized with Safe Output Encoding on "${retUrl}"`,
          category: 'Input Reflection',
          type: 'stored',
          severity: 'Informational',
          confidence: 'High',
          findingState: FINDING_STATES.ENCODED_REFLECTION,
          status: 'Resolved',
          verificationStatus: 'verified',
          reflectionDetected: true,
          storageDetected: true,
          retrievalDetected: true,
          context: contextRes.context,
          encoding: 'HTML_ENTITIES',
          source: candidateInput.name,
          sink: null,
          url: retUrl,
          affectedUrls: [form.action, retUrl],
          parameter: candidateInput.name,
          method: 'POST / GET',
          reasoning,
          description: reasoning,
          evidence: {
            storageEvidence: 'YES',
            retrievalEvidence: 'YES',
            reflectionContext: contextRes.context,
            encoding: 'HTML_ENTITIES',
            injectionValue: probePayload,
            returnedValue: canaryToken + encodingRes.encodedChars.join(''),
            formAction: form.action,
            retrievalUrl: retUrl
          }
        };
      }

      // If stored input is retrieved into an unsafe context without encoding -> Stored XSS!
      if (alterability.canAlter && encodingRes.status === ENCODING_STATUS.UNENCODED) {
        const reasoning = `Stored user input was successfully persisted via ${form.action} and subsequently retrieved at ${retUrl} into ${contextRes.context} without HTML entity encoding. Unencoded delimiters (${encodingRes.unencodedChars.join(', ')}) were returned.`;

        return {
          id: `stored_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'STORED_XSS_VERIFIED',
          title: `Stored Cross-Site Scripting (XSS) on "${retUrl}" (Field: "${candidateInput.name}")`,
          category: 'Cross-Site Scripting',
          type: 'stored',
          severity: 'High',
          confidence: 'High',
          findingState: FINDING_STATES.HIGH_CONFIDENCE_XSS,
          status: 'Open',
          verificationStatus: 'verified',
          reflectionDetected: true,
          storageDetected: true,
          retrievalDetected: true,
          context: contextRes.context,
          encoding: 'NONE',
          source: candidateInput.name,
          sink: null,
          url: retUrl,
          affectedUrls: [form.action, retUrl],
          parameter: candidateInput.name,
          method: 'POST / GET',
          reasoning,
          description: reasoning,
          impact: 'Stored XSS executes in every victim browser session that accesses the retrieved page, enabling persistent session hijacking and account takeover.',
          evidence: {
            storageEvidence: 'YES',
            retrievalEvidence: 'YES',
            reflectionContext: contextRes.context,
            encoding: 'NONE',
            unencodedMetas: encodingRes.unencodedChars.join(', '),
            injectionValue: probePayload,
            returnedValue: canaryToken + encodingRes.unencodedChars.join(''),
            formAction: form.action,
            retrievalUrl: retUrl,
            contextSnippet: contextRes.snippet
          },
          remediation: `Ensure all stored user content undergoes context-aware HTML entity encoding when displayed.
1. In PHP: echo htmlspecialchars($stored_data, ENT_QUOTES, 'UTF-8');
2. In Node.js / Express: Use template auto-escaping.
3. In Python / Django: Ensure auto-escaping is active.`
        };
      }
    } catch {}
  }

  return null;
}
