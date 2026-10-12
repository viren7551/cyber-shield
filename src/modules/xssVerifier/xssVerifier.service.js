import { safeRequest } from '../webScanner/engine/httpClient.js';
import { validateTargetUrl } from '../webScanner/engine/scopeValidator.js';
import { analyzeReflectionContext, canAlterParsingContext, XSS_CONTEXTS } from '../webScanner/xss/contextAnalyzer.js';
import { analyzeOutputEncoding, ENCODING_STATUS } from '../webScanner/xss/encodingAnalyzer.js';

/**
 * CyberShield - Dedicated XSS Injection Verification Service
 * Audits a specific target URL using user-provided payloads (from an uploaded file or custom list).
 * Tests each payload safely, determines reflection, output encoding, and vulnerability status.
 */

/**
 * Encodes dangerous characters to standard HTML entities
 */
function getHtmlEntityEncoded(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Checks if the response body contains the HTML-entity encoded version of the payload
 */
function findEncodedReflection(body, payload) {
  if (!body || !payload) return { found: false };

  const standard = getHtmlEntityEncoded(payload);
  if (standard !== payload && body.includes(standard)) {
    return { found: true, index: body.indexOf(standard), matchedText: standard, type: 'HTML_ENTITIES' };
  }

  // Check single-quote &#x27; / &apos; variants
  const altQuote = standard.replace(/&#39;/g, '&#x27;');
  if (altQuote !== payload && body.includes(altQuote)) {
    return { found: true, index: body.indexOf(altQuote), matchedText: altQuote, type: 'HTML_ENTITIES' };
  }

  const aposQuote = standard.replace(/&#39;/g, '&apos;');
  if (aposQuote !== payload && body.includes(aposQuote)) {
    return { found: true, index: body.indexOf(aposQuote), matchedText: aposQuote, type: 'HTML_ENTITIES' };
  }

  return { found: false };
}

/**
 * Verify an array of payloads against a target URL and parameter
 * @param {object} params
 * @param {string} params.targetUrl - Target endpoint URL
 * @param {string} [params.parameterName] - Parameter to inject into (optional, can be inferred from URL)
 * @param {string} [params.httpMethod='GET'] - HTTP Method ('GET' or 'POST')
 * @param {Array<string>} params.payloads - Array of payloads to verify
 * @param {object} [params.options] - Configuration options (rateLimitMs, timeoutMs, customHeaders)
 */
export async function verifyCustomPayloads(params) {
  const {
    targetUrl,
    parameterName = '',
    httpMethod = 'GET',
    payloads = [],
    options = {}
  } = params;

  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new Error('Target URL is required.');
  }

  if (!Array.isArray(payloads) || payloads.length === 0) {
    throw new Error('At least one payload must be provided for verification.');
  }

  // Validate target URL against basic protocol check & SSRF
  const targetVal = await validateTargetUrl(targetUrl, true); // Allow local lab for testing
  if (!targetVal.valid) {
    throw new Error(`Invalid Target URL: ${targetVal.error}`);
  }

  const {
    rateLimitMs = 40,
    timeoutMs = 4500,
    customHeaders = {},
    abortSignal = null,
    onProgress = null
  } = options;

  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl.trim());
  } catch {
    throw new Error('Malformed Target URL format.');
  }

  // Infer parameter name if not explicitly specified
  let effectiveParam = parameterName.trim();
  if (!effectiveParam) {
    const searchKeys = Array.from(parsedTarget.searchParams.keys());
    if (searchKeys.length > 0) {
      effectiveParam = searchKeys[0];
    } else {
      effectiveParam = 'q'; // Default fallback parameter
    }
  }

  const method = httpMethod.toUpperCase() === 'POST' ? 'POST' : 'GET';
  const startTime = Date.now();
  const results = [];

  let vulnerableCount = 0;
  let safeEncodedCount = 0;
  let notReflectedCount = 0;
  let blockedCount = 0;
  let filteredCount = 0;
  let errorCount = 0;

  const recordResult = (resItem) => {
    results.push(resItem);
    if (typeof onProgress === 'function') {
      try {
        onProgress({
          index: results.length,
          total: payloads.length,
          completed: results.length,
          remaining: Math.max(0, payloads.length - results.length),
          percent: Math.round((results.length / payloads.length) * 100),
          currentPayload: resItem.payload,
          result: resItem,
          counts: {
            vulnerableCount,
            safeEncodedCount,
            notReflectedCount,
            blockedCount,
            filteredCount,
            errorCount
          },
          elapsedMs: Date.now() - startTime
        });
      } catch {}
    }
  };

  for (let i = 0; i < payloads.length; i++) {
    if (abortSignal && abortSignal.aborted) break;

    const payload = String(payloads[i] || '').trim();
    if (!payload) continue;

    if (rateLimitMs > 0 && i > 0) {
      await new Promise(r => setTimeout(r, rateLimitMs));
    }

    const probeStart = Date.now();
    let requestUrl = targetUrl;
    let requestOptions = {
      method,
      timeoutMs,
      headers: { ...customHeaders },
      abortSignal
    };

    if (method === 'GET') {
      try {
        const u = new URL(targetUrl);
        u.searchParams.set(effectiveParam, payload);
        requestUrl = u.toString();
      } catch {
        requestUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${encodeURIComponent(effectiveParam)}=${encodeURIComponent(payload)}`;
      }
    } else {
      requestOptions.headers['Content-Type'] = requestOptions.headers['Content-Type'] || 'application/x-www-form-urlencoded';
      requestOptions.body = `${encodeURIComponent(effectiveParam)}=${encodeURIComponent(payload)}`;
    }

    let response;
    try {
      response = await safeRequest(requestUrl, requestOptions);
    } catch (err) {
      response = { success: false, statusCode: 0, error: err.message };
    }

    const durationMs = Date.now() - probeStart;

    if (!response.success || !response.body) {
      errorCount++;
      recordResult({
        index: i + 1,
        payload,
        status: 'ERROR',
        label: response.statusCode === 0 ? 'Connection Failed / Timeout' : `HTTP Error (${response.statusCode})`,
        severity: 'Error',
        statusCode: response.statusCode || 0,
        responseTimeMs: durationMs,
        reflected: false,
        context: 'N/A',
        encoding: 'N/A',
        evidence: {
          error: response.error || 'No response body received'
        }
      });
      continue;
    }

    const body = response.body;
    const statusCode = response.statusCode;

    // Check if WAF or server blocked the payload (e.g. 403 Forbidden, 406 Not Acceptable, 400 Bad Request)
    if (statusCode === 403 || statusCode === 406 || (statusCode === 400 && !body.includes(payload))) {
      blockedCount++;
      recordResult({
        index: i + 1,
        payload,
        status: 'BLOCKED',
        label: `Blocked by Server (HTTP ${statusCode})`,
        severity: 'Low',
        statusCode,
        responseTimeMs: durationMs,
        reflected: false,
        context: 'N/A',
        encoding: 'BLOCKED',
        evidence: {
          httpStatus: statusCode,
          details: 'The web server or application firewall rejected the request.'
        }
      });
      continue;
    }

    // Check reflection
    const exactIndex = body.indexOf(payload);
    const reflected = exactIndex !== -1;

    // Analyze output encoding using delimiter check
    const encodingAnalysis = analyzeOutputEncoding(body, payload);

    if (reflected) {
      const contextRes = analyzeReflectionContext(body, payload);

      // Check if unencoded dangerous characters can alter context
      const alterability = canAlterParsingContext(
        encodingAnalysis.unencodedChars,
        contextRes.context,
        contextRes.quoteChar
      );

      // Extract evidence snippet
      const snippetStart = Math.max(0, exactIndex - 60);
      const snippetEnd = Math.min(body.length, exactIndex + payload.length + 60);
      const rawSnippet = body.substring(snippetStart, snippetEnd);

      const linesBefore = body.substring(0, exactIndex).split('\n');
      const lineNum = linesBefore.length;
      const colNum = linesBefore[linesBefore.length - 1].length + 1;

      // Determine if it is fully vulnerable (unencoded in executable context) or encoded
      const hasUnencodedDelimiters = encodingAnalysis.hasUnencodedMetas || (payload.includes('<') && !body.includes('&lt;'));

      if (
        hasUnencodedDelimiters &&
        (contextRes.context === XSS_CONTEXTS.HTML_TEXT ||
         contextRes.context === XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE ||
         contextRes.context === XSS_CONTEXTS.HTML_ATTRIBUTE ||
         contextRes.context === XSS_CONTEXTS.SCRIPT_CONTEXT ||
         contextRes.context === XSS_CONTEXTS.JAVASCRIPT_STRING ||
         contextRes.context === XSS_CONTEXTS.JAVASCRIPT_CODE)
      ) {
        vulnerableCount++;
        recordResult({
          index: i + 1,
          payload,
          status: 'VULNERABLE',
          label: 'Vulnerable: Unencoded Reflection',
          severity: 'Critical',
          statusCode,
          responseTimeMs: durationMs,
          reflected: true,
          context: contextRes.context,
          encoding: 'RAW_UNENCODED',
          evidence: {
            snippet: rawSnippet,
            line: lineNum,
            col: colNum,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            detectedContext: contextRes.context,
            unencodedChars: encodingAnalysis.unencodedChars,
            explanation: `Payload reflected verbatim into ${contextRes.context} without HTML entity sanitization.`
          }
        });
      } else if (
        encodingAnalysis.status === ENCODING_STATUS.SAFE_ENCODED ||
        encodingAnalysis.encoding === 'HTML_ENTITIES' ||
        body.includes('&lt;') ||
        body.includes('&#')
      ) {
        safeEncodedCount++;
        recordResult({
          index: i + 1,
          payload,
          status: 'SAFE_ENCODED',
          label: 'Safely Encoded Reflection',
          severity: 'Informational',
          statusCode,
          responseTimeMs: durationMs,
          reflected: true,
          context: contextRes.context,
          encoding: 'HTML_ENTITIES',
          evidence: {
            snippet: rawSnippet,
            line: lineNum,
            col: colNum,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            detectedContext: contextRes.context,
            explanation: 'The server safely neutralized HTML metacharacters with entity encoding.'
          }
        });
      } else {
        // Reflected in benign context or partial encoding
        filteredCount++;
        recordResult({
          index: i + 1,
          payload,
          status: 'FILTERED',
          label: 'Reflected (Partial / Constrained)',
          severity: 'Medium',
          statusCode,
          responseTimeMs: durationMs,
          reflected: true,
          context: contextRes.context,
          encoding: encodingAnalysis.encoding || 'PARTIAL',
          evidence: {
            snippet: rawSnippet,
            line: lineNum,
            col: colNum,
            contextBefore: contextRes.contextBefore,
            contextAfter: contextRes.contextAfter,
            detectedContext: contextRes.context,
            explanation: `Reflected in context ${contextRes.context}. Partial transformation observed.`
          }
        });
      }
    } else {
      // Check if reflected as HTML entity encoded form (e.g. <script> -> &lt;script&gt;)
      const encodedMatch = findEncodedReflection(body, payload);
      if (encodedMatch.found) {
        safeEncodedCount++;
        const matchIdx = encodedMatch.index;
        const snippetStart = Math.max(0, matchIdx - 60);
        const snippetEnd = Math.min(body.length, matchIdx + encodedMatch.matchedText.length + 60);
        const rawSnippet = body.substring(snippetStart, snippetEnd);
        const linesBefore = body.substring(0, matchIdx).split('\n');
        const lineNum = linesBefore.length;
        const colNum = linesBefore[linesBefore.length - 1].length + 1;

        recordResult({
          index: i + 1,
          payload,
          status: 'SAFE_ENCODED',
          label: 'Safely Encoded Reflection',
          severity: 'Informational',
          statusCode,
          responseTimeMs: durationMs,
          reflected: true,
          context: 'HTML_TEXT (Escaped)',
          encoding: 'HTML_ENTITIES',
          evidence: {
            snippet: rawSnippet,
            line: lineNum,
            col: colNum,
            matchedText: encodedMatch.matchedText,
            detectedContext: 'HTML_TEXT (Escaped)',
            explanation: 'The server safely neutralized HTML metacharacters with entity encoding (e.g. &lt;, &gt;, &quot;, &#39;).'
          }
        });
        continue;
      }

      // Check if partially reflected (e.g. stripped tags like <script> stripped to text)
      const sanitizedCandidate = payload.replace(/[<>'"&]/g, '');
      const partiallyReflected = sanitizedCandidate.length > 3 && body.includes(sanitizedCandidate);

      if (partiallyReflected) {
        filteredCount++;
        recordResult({
          index: i + 1,
          payload,
          status: 'FILTERED',
          label: 'Sanitized / Characters Stripped',
          severity: 'Low',
          statusCode,
          responseTimeMs: durationMs,
          reflected: true,
          context: 'HTML Filtered',
          encoding: 'STRIPPED',
          evidence: {
            snippet: 'Dangerous delimiters were stripped by the server.',
            explanation: 'The server filtered or removed HTML tag delimiters.'
          }
        });
      } else {
        notReflectedCount++;
        recordResult({
          index: i + 1,
          payload,
          status: 'NOT_REFLECTED',
          label: 'Not Reflected in Response',
          severity: 'Safe',
          statusCode,
          responseTimeMs: durationMs,
          reflected: false,
          context: 'NONE',
          encoding: 'N/A',
          evidence: {
            explanation: 'The parameter value does not appear in the response body.'
          }
        });
      }
    }
  }

  const totalDurationMs = Date.now() - startTime;

  return {
    targetUrl,
    parameterName: effectiveParam,
    httpMethod: method,
    summary: {
      totalPayloads: payloads.length,
      testedCount: results.length,
      vulnerableCount,
      safeEncodedCount,
      notReflectedCount,
      blockedCount,
      filteredCount,
      errorCount,
      durationMs: totalDurationMs,
      vulnerabilityRate: results.length > 0 ? Math.round((vulnerableCount / results.length) * 100) : 0
    },
    results
  };
}

/**
 * Returns safe, standardized sample payloads for testing
 */
export function getSamplePayloads() {
  return [
    {
      category: 'Diagnostic Canaries',
      description: 'Harmless alphanumeric markers to test if input reaches HTML output',
      payloads: [
        'XSS_CANARY_TEST_101',
        'XSS_CANARY_<b>TEST</b>',
        '"><csxss_test>',
        '\'><csxss_test>'
      ]
    },
    {
      category: 'HTML Text Context',
      description: 'Tests if angle brackets (< >) break out into new HTML tags',
      payloads: [
        '<csxss>alert(1)</csxss>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<b>bold_test</b>'
      ]
    },
    {
      category: 'Attribute Context Breakouts',
      description: 'Tests if quotation marks (" or \') close attributes and add event handlers',
      payloads: [
        '" onfocus="alert(1)" autofocus="',
        '\' onfocus=\'alert(1)\' autofocus=\'',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>'
      ]
    },
    {
      category: 'JavaScript String Context',
      description: 'Tests if string literals in <script> tags can be escaped',
      payloads: [
        '-alert(1)-',
        '\';alert(1)//',
        '";alert(1)//',
        '</script><script>alert(1)</script>'
      ]
    }
  ];
}
