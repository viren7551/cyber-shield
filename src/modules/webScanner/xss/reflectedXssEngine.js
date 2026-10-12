import { safeRequest } from '../engine/httpClient.js';
import { analyzeReflectionContext, canAlterParsingContext, XSS_CONTEXTS, FINDING_STATES } from './contextAnalyzer.js';
import { analyzeOutputEncoding, ENCODING_STATUS } from './encodingAnalyzer.js';

/**
 * CyberShield Web Security Scanner - Reflected XSS Detection Engine
 * Multi-stage pipeline: DISCOVERY -> DETECTION -> CONTEXT ANALYSIS -> VERIFICATION -> FINDING
 * Strictly separates input reflection from confirmed/potential XSS.
 * Reflection alone NEVER becomes an XSS finding.
 */

const MARKER_PREFIX = 'XSSSCAN_';
const DELIMITER_PROBE = '\'"><csxss>&';

/**
 * Audit candidate parameters for reflection and reflected XSS vulnerabilities.
 * @param {Array<object>} parameterInventory - Discovered parameter inventory
 * @param {object} options - Request options (userAgent, timeoutMs, rateLimitMs, abortSignal, maxProbes)
 * @returns {Promise<Array<object>>} - Findings array
 */
export async function auditReflectedXss(parameterInventory = [], options = {}) {
  const {
    userAgent,
    timeoutMs = 4500,
    rateLimitMs = 100,
    abortSignal = null,
    maxProbes = 25
  } = options;

  const findings = [];
  const probedKeySet = new Set();
  let probesExecuted = 0;

  for (const entry of parameterInventory) {
    if (probesExecuted >= maxProbes) break;
    if (abortSignal && abortSignal.aborted) break;

    const endpointUrl = entry.endpoint;
    const method = (entry.method || 'GET').toUpperCase();

    // Support both GET query inputs and POST form inputs
    if (method !== 'GET' && method !== 'POST') continue;

    for (const param of entry.parameters) {
      if (probesExecuted >= maxProbes) break;
      if (abortSignal && abortSignal.aborted) break;

      const paramName = param.name;
      if (!paramName || param.isCsrf) continue;

      const dedupeKey = `${method}:${endpointUrl}?${paramName}`;
      if (probedKeySet.has(dedupeKey)) continue;
      probedKeySet.add(dedupeKey);

      const isInput = !!(param.isInputField || param.source?.includes('Input') || param.source?.includes('Form'));
      const inputFieldData = {
        name: paramName,
        type: param.type || 'text',
        source: param.source || (isInput ? 'HTML Input Field' : 'URL Query Parameter'),
        pageUrl: param.pageUrl || endpointUrl,
        formAction: param.formAction || endpointUrl,
        formMethod: method,
        placeholder: param.placeholder || '',
        htmlSnippet: param.htmlSnippet || `<input type="${param.type || 'text'}" name="${paramName}">`
      };

      // =====================================================================
      // STAGE 1: DISCOVERY & CANARY REFLECTION CHECK (Alphanumeric Token Only)
      // =====================================================================
      const uniqueId = Math.random().toString(36).substring(2, 8);
      const canaryToken = `${MARKER_PREFIX}${uniqueId}`;

      let canaryUrl = entry.fullUrl || endpointUrl;
      const requestOptions1 = {
        method,
        timeoutMs: Math.min(4500, timeoutMs),
        userAgent,
        abortSignal
      };

      if (method === 'GET') {
        try {
          const u = new URL(entry.fullUrl || endpointUrl);
          u.searchParams.set(paramName, canaryToken);
          canaryUrl = u.toString();
        } catch {
          continue;
        }
      } else {
        requestOptions1.headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        };
        requestOptions1.body = `${encodeURIComponent(paramName)}=${encodeURIComponent(canaryToken)}`;
      }

      probesExecuted++;
      if (rateLimitMs > 0 && probesExecuted > 1) {
        await new Promise((r) => setTimeout(r, rateLimitMs));
      }

      let initialBody = null;
      try {
        const res1 = await safeRequest(canaryUrl, requestOptions1);
        if (!res1.success || !res1.body || typeof res1.body !== 'string') {
          continue;
        }
        initialBody = res1.body;
      } catch {
        continue;
      }

      // Check if pure alphanumeric canary token was reflected in response
      const initialReflection = analyzeReflectionContext(initialBody, canaryToken);
      if (!initialReflection.reflected) {
        // CASE A: Input is NOT reflected -> No finding
        continue;
      }

      // =====================================================================
      // STAGE 2: CONTEXT ANALYSIS & SYNTAX ALTERATION / ENCODING PROBE
      // =====================================================================
      const syntaxId = Math.random().toString(36).substring(2, 8);
      const syntaxCanary = `${MARKER_PREFIX}${syntaxId}`;
      const syntaxPayload = `${syntaxCanary}${DELIMITER_PROBE}`;

      let syntaxUrl = entry.fullUrl || endpointUrl;
      const requestOptions2 = {
        method,
        timeoutMs: Math.min(4500, timeoutMs),
        userAgent,
        abortSignal
      };

      if (method === 'GET') {
        try {
          const u2 = new URL(entry.fullUrl || endpointUrl);
          u2.searchParams.set(paramName, syntaxPayload);
          syntaxUrl = u2.toString();
        } catch {
          continue;
        }
      } else {
        requestOptions2.headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        };
        requestOptions2.body = `${encodeURIComponent(paramName)}=${encodeURIComponent(syntaxPayload)}`;
      }

      probesExecuted++;
      if (rateLimitMs > 0) {
        await new Promise((r) => setTimeout(r, rateLimitMs));
      }

      let syntaxBody = null;
      try {
        const res2 = await safeRequest(syntaxUrl, requestOptions2);
        if (res2.success && res2.body && typeof res2.body === 'string') {
          syntaxBody = res2.body;
        }
      } catch {}

      // Analyze reflection and encoding of the syntax probe
      const bodyToAnalyze = syntaxBody || initialBody;
      const markerUsed = syntaxBody ? syntaxCanary : canaryToken;
      const probeUsed = syntaxBody ? syntaxPayload : canaryToken;

      const contextRes = analyzeReflectionContext(bodyToAnalyze, markerUsed);
      const encodingRes = syntaxBody
        ? analyzeOutputEncoding(bodyToAnalyze, markerUsed, DELIMITER_PROBE)
        : {
            status: ENCODING_STATUS.CANARY_ONLY,
            encoding: 'UNKNOWN',
            reflectionFound: true,
            hasUnencodedMetas: false,
            isProperlyEncoded: false,
            unencodedChars: [],
            encodedChars: [],
            transformations: {}
          };

      // Determine if unencoded characters can alter browser parsing for this context
      const alterability = canAlterParsingContext(
        encodingRes.unencodedChars,
        contextRes.context,
        contextRes.quoteChar
      );

      // Format location string
      const locStr = contextRes.reflectionLocation
        ? `Line ${contextRes.reflectionLocation.line}, Col ${contextRes.reflectionLocation.col}`
        : 'Body offset ' + (bodyToAnalyze.indexOf(markerUsed) || 0);

      // =====================================================================
      // STAGE 3: MULTI-SIGNAL FINDING CLASSIFICATION
      // =====================================================================

      // ---------------------------------------------------------------------
      // CASE B: Input reflected but properly encoded (ENCODED_REFLECTION)
      // ---------------------------------------------------------------------
      if (
        encodingRes.status === ENCODING_STATUS.SAFE_ENCODED ||
        encodingRes.encoding === 'HTML_ENTITIES' ||
        (encodingRes.encodedChars.length >= 2 && encodingRes.unencodedChars.length === 0)
      ) {
        const reasoning = isInput
          ? `The input field "${paramName}" (<${param.type || 'text'}>) was reflected, but special characters were HTML encoded. No XSS vulnerability was established.`
          : 'The parameter was reflected, but special characters were HTML encoded. No XSS vulnerability was established.';

        findings.push({
          id: `refl_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'INPUT_REFLECTION_SAFE_ENCODING',
          title: isInput
            ? `Input Reflection (Safely Encoded) on Input Field "${paramName}"`
            : `Input Reflection (Safely Encoded) on Parameter "${paramName}"`,
          category: 'Input Reflection',
          type: 'reflection',
          severity: 'Informational',
          confidence: 'High',
          findingState: FINDING_STATES.ENCODED_REFLECTION,
          status: 'Resolved',
          verificationStatus: 'verified',
          reflectionDetected: true,
          storageDetected: false,
          retrievalDetected: false,
          context: contextRes.context,
          encoding: 'HTML_ENTITIES',
          source: paramName,
          sink: null,
          url: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
          affectedUrls: [method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl],
          parameter: paramName,
          method,
          occurrences: contextRes.occurrences,
          reasoning,
          description: reasoning,
          impact: 'Informational finding: No exploitable cross-site scripting exists. The server safely neutralized HTML metacharacters with standard entity encoding.',
          inputField: isInput ? inputFieldData : null,
          evidence: {
            injectionValue: probeUsed,
            returnedValue: markerUsed + encodingRes.encodedChars.join(''),
            reflectionLocation: locStr,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            encodingTransformations: encodingRes.transformations,
            detectionReasoning: reasoning,
            vulnerableEndpoint: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
            vulnerableParameter: paramName,
            detectedContext: contextRes.context,
            encodingStatus: 'Safe HTML Entity Encoded',
            reproducibleUrl: syntaxUrl || canaryUrl,
            inputField: isInput ? inputFieldData : null,
            foundOnPage: inputFieldData.pageUrl,
            formAction: inputFieldData.formAction,
            htmlSnippet: inputFieldData.htmlSnippet,
            isInputField: isInput
          },
          remediation: 'Maintain current output encoding practices.',
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
          ]
        });
      }

      // ---------------------------------------------------------------------
      // CASE D: Strong evidence showing unencoded input altering parsing context
      // (HIGH_CONFIDENCE_XSS)
      // ---------------------------------------------------------------------
      else if (
        alterability.canAlter &&
        encodingRes.status === ENCODING_STATUS.UNENCODED &&
        (contextRes.context === XSS_CONTEXTS.HTML_TEXT ||
          contextRes.context === XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE ||
          contextRes.context === XSS_CONTEXTS.HTML_ATTRIBUTE ||
          contextRes.context === XSS_CONTEXTS.JAVASCRIPT_STRING ||
          contextRes.context === XSS_CONTEXTS.JAVASCRIPT_CODE ||
          contextRes.context === XSS_CONTEXTS.SCRIPT_CONTEXT)
      ) {
        const reasoning = isInput
          ? `Attacker-controlled input submitted via input field "${paramName}" (<${param.type || 'text'}>) on page "${inputFieldData.pageUrl}" was reflected into a browser-executable context (${contextRes.context}) without adequate output encoding. Injected syntax (${encodingRes.unencodedChars.join(', ')}) was returned unescaped, allowing alteration of the browser parsing context.`
          : `Attacker-controlled input was reflected into a browser-executable context (${contextRes.context}) without adequate output encoding. Injected syntax (${encodingRes.unencodedChars.join(', ')}) was returned unescaped, allowing alteration of the browser parsing context.`;

        findings.push({
          id: `xss_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'REFLECTED_XSS_HIGH_CONFIDENCE',
          title: isInput
            ? `High Confidence Potential XSS on Input Field "${paramName}" (<${param.type || 'text'}>) (${contextRes.context})`
            : `High Confidence Potential XSS on Parameter "${paramName}" (${contextRes.context})`,
          category: 'Cross-Site Scripting',
          type: 'reflected',
          severity: 'High',
          confidence: 'High',
          findingState: FINDING_STATES.HIGH_CONFIDENCE_XSS,
          status: 'Open',
          verificationStatus: 'needs_verification',
          reflectionDetected: true,
          storageDetected: false,
          retrievalDetected: false,
          context: contextRes.context,
          encoding: 'NONE',
          source: paramName,
          sink: null,
          url: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
          affectedUrls: [method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl],
          parameter: paramName,
          method,
          occurrences: contextRes.occurrences,
          reasoning,
          description: isInput
            ? `The input field <${param.type || 'text'} name="${paramName}"> discovered on page "${inputFieldData.pageUrl}" reflects user-supplied data into ${contextRes.context} without appropriate output encoding. ${alterability.explanation}`
            : `The parameter "${paramName}" reflects user-supplied data into ${contextRes.context} without appropriate output encoding. ${alterability.explanation}`,
          impact: 'An attacker can supply malicious JavaScript via a link or form input. When a victim loads the payload, script executes in their browser session, allowing cookie theft, credential harvesting, or DOM manipulation.',
          inputField: isInput ? inputFieldData : null,
          evidence: {
            injectionValue: probeUsed,
            returnedValue: markerUsed + encodingRes.unencodedChars.join(''),
            reflectionLocation: locStr,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            encodingTransformations: encodingRes.transformations,
            detectionReasoning: reasoning,
            vulnerableEndpoint: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
            vulnerableParameter: paramName,
            detectedContext: contextRes.context,
            encodingStatus: 'Unencoded (Raw Delimiters Reflected)',
            unencodedMetas: encodingRes.unencodedChars.join(', '),
            reproducibleUrl: syntaxUrl || canaryUrl,
            inputField: isInput ? inputFieldData : null,
            foundOnPage: inputFieldData.pageUrl,
            formAction: inputFieldData.formAction,
            htmlSnippet: inputFieldData.htmlSnippet,
            isInputField: isInput
          },
          remediation: `Apply context-aware output encoding to "${paramName}" before rendering it into the HTML document:
1. In PHP: htmlspecialchars($_${method}['${paramName}'] ?? '', ENT_QUOTES, 'UTF-8')
2. In Node.js / Express: validator.escape(req.${method === 'POST' ? 'body' : 'query'}.${paramName} || '')
3. In Python (Flask/Django): Ensure auto-escaping is active; do not use |safe
4. Deploy a strict Content Security Policy (CSP) with script-src 'self'.`,
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection',
          references: [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
          ]
        });
      }

      // ---------------------------------------------------------------------
      // CASE C: Reflected in an interesting context but exploitability cannot be established
      // (POTENTIAL_XSS / NEEDS_MANUAL_VERIFICATION)
      // ---------------------------------------------------------------------
      else if (
        encodingRes.status === ENCODING_STATUS.PARTIALLY_ENCODED ||
        contextRes.context === XSS_CONTEXTS.HTML_COMMENT ||
        (alterability.canAlter && encodingRes.status === ENCODING_STATUS.CANARY_ONLY)
      ) {
        const reasoning = isInput
          ? `The input field "${paramName}" (<${param.type || 'text'}>) on page "${inputFieldData.pageUrl}" was reflected into an HTML/attribute/script context and the scanner observed insufficient output encoding. Manual verification is recommended.`
          : 'The parameter was reflected into an HTML/attribute/script context and the scanner observed insufficient output encoding. Manual verification is recommended.';

        findings.push({
          id: `xss_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'REFLECTED_XSS_POTENTIAL',
          title: isInput
            ? `Potential Reflected XSS on Input Field "${paramName}" (<${param.type || 'text'}>) (${contextRes.context})`
            : `Potential Reflected XSS on Parameter "${paramName}" (${contextRes.context})`,
          category: 'Cross-Site Scripting',
          type: 'reflected',
          severity: 'Medium',
          confidence: 'Medium',
          findingState: FINDING_STATES.POTENTIAL_XSS,
          status: 'Needs Manual Verification',
          verificationStatus: 'needs_verification',
          reflectionDetected: true,
          storageDetected: false,
          retrievalDetected: false,
          context: contextRes.context,
          encoding: encodingRes.encoding || 'PARTIAL',
          source: paramName,
          sink: null,
          url: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
          affectedUrls: [method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl],
          parameter: paramName,
          method,
          occurrences: contextRes.occurrences,
          reasoning,
          description: isInput
            ? `The input field <${param.type || 'text'} name="${paramName}"> on page "${inputFieldData.pageUrl}" reflects user input into ${contextRes.context}. Partial encoding or boundary constraints were observed. ${alterability.explanation}`
            : `The parameter "${paramName}" reflects user input into ${contextRes.context}. Partial encoding or boundary constraints were observed. ${alterability.explanation}`,
          impact: 'Depending on application filtering and surrounding HTML structure, partial encoding may allow context breakouts.',
          inputField: isInput ? inputFieldData : null,
          evidence: {
            injectionValue: probeUsed,
            returnedValue: markerUsed + (encodingRes.unencodedChars.join('') || ''),
            reflectionLocation: locStr,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            encodingTransformations: encodingRes.transformations,
            detectionReasoning: reasoning,
            vulnerableEndpoint: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
            vulnerableParameter: paramName,
            detectedContext: contextRes.context,
            encodingStatus: encodingRes.status,
            unencodedMetas: encodingRes.unencodedChars.join(', '),
            reproducibleUrl: syntaxUrl || canaryUrl,
            inputField: isInput ? inputFieldData : null,
            foundOnPage: inputFieldData.pageUrl,
            formAction: inputFieldData.formAction,
            htmlSnippet: inputFieldData.htmlSnippet,
            isInputField: isInput
          },
          remediation: 'Ensure universal context-aware HTML entity encoding is applied to all metacharacters (<, >, ", \', &).',
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']
        });
      }

      // ---------------------------------------------------------------------
      // CASE B2: Reflection Only (REFLECTION_ONLY) - NEVER XSS!
      // ---------------------------------------------------------------------
      else {
        const reasoning = isInput
          ? `The input field "${paramName}" (<${param.type || 'text'}>) value was reflected in the HTTP response. The observed reflection alone does not establish cross-site scripting because the scanner did not establish an executable browser context.`
          : 'The parameter value was reflected in the HTTP response. The observed reflection alone does not establish cross-site scripting because the scanner did not establish an executable browser context.';

        findings.push({
          id: `refl_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'INPUT_REFLECTION_ONLY',
          title: isInput
            ? `Input Reflection in ${contextRes.context} on Input Field "${paramName}"`
            : `Input Reflection in ${contextRes.context} on Parameter "${paramName}"`,
          category: 'Input Reflection',
          type: 'reflection',
          severity: 'Informational',
          confidence: 'High',
          findingState: FINDING_STATES.REFLECTION_ONLY,
          status: 'Resolved',
          verificationStatus: 'verified',
          reflectionDetected: true,
          storageDetected: false,
          retrievalDetected: false,
          context: contextRes.context,
          encoding: encodingRes.encoding || 'NONE',
          source: paramName,
          sink: null,
          url: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
          affectedUrls: [method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl],
          parameter: paramName,
          method,
          occurrences: contextRes.occurrences,
          reasoning,
          description: reasoning,
          impact: 'Informational finding: User input is reflected in the HTTP response body. This proves input reflection only and is NOT an XSS vulnerability.',
          inputField: isInput ? inputFieldData : null,
          evidence: {
            injectionValue: probeUsed,
            returnedValue: markerUsed,
            reflectionLocation: locStr,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            encodingTransformations: encodingRes.transformations,
            detectionReasoning: reasoning,
            vulnerableEndpoint: method === 'GET' ? `${endpointUrl}?${paramName}=` : endpointUrl,
            vulnerableParameter: paramName,
            detectedContext: contextRes.context,
            encodingStatus: encodingRes.status,
            reproducibleUrl: canaryUrl,
            inputField: isInput ? inputFieldData : null,
            foundOnPage: inputFieldData.pageUrl,
            formAction: inputFieldData.formAction,
            htmlSnippet: inputFieldData.htmlSnippet,
            isInputField: isInput
          },
          remediation: 'Ensure context-appropriate encoding is maintained if this field is ever rendered in active contexts.',
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']
        });
      }
    }
  }

  return findings;
}
