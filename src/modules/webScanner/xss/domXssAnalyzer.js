import { safeRequest } from '../engine/httpClient.js';
import { isUrlInScope } from '../engine/scopeValidator.js';
import { FINDING_STATES } from './contextAnalyzer.js';

/**
 * CyberShield Web Security Scanner - DOM XSS & JavaScript Static Data Flow Analyzer
 * Performs safe static analysis of in-scope JavaScript to trace data flows:
 * SOURCE -> TRANSFORMATION -> SINK.
 * Verifies whether input is neutralized by sanitizers (DOMPurify, textContent) before reaching sinks.
 */

// Attacker-controllable DOM sources
const DOM_SOURCES = [
  { name: 'location.hash', pattern: /location\.hash\b/g, risk: 'High' },
  { name: 'location.search', pattern: /location\.search\b/g, risk: 'High' },
  { name: 'location.href', pattern: /location\.href\b/g, risk: 'High' },
  { name: 'location.pathname', pattern: /location\.pathname\b/g, risk: 'Medium' },
  { name: 'document.URL', pattern: /document\.URL\b/g, risk: 'High' },
  { name: 'document.documentURI', pattern: /document\.documentURI\b/g, risk: 'High' },
  { name: 'document.referrer', pattern: /document\.referrer\b/g, risk: 'Medium' },
  { name: 'window.name', pattern: /window\.name\b/g, risk: 'Medium' },
  { name: 'postMessage', pattern: /(?:window\.)?addEventListener\s*\(\s*['"]message['"]/g, risk: 'Medium' }
];

// Dangerous DOM execution sinks
const DOM_SINKS = [
  { name: 'element.innerHTML', pattern: /\.\s*innerHTML\s*=/g, risk: 'High' },
  { name: 'element.outerHTML', pattern: /\.\s*outerHTML\s*=/g, risk: 'High' },
  { name: 'element.insertAdjacentHTML', pattern: /\.\s*insertAdjacentHTML\s*\(/g, risk: 'High' },
  { name: 'document.write', pattern: /document\.write(?:ln)?\s*\(/g, risk: 'High' },
  { name: 'eval', pattern: /\beval\s*\(/g, risk: 'High' },
  { name: 'setTimeout(string)', pattern: /setTimeout\s*\(\s*['"`][^'"`]+['"`]/g, risk: 'Medium' },
  { name: 'setInterval(string)', pattern: /setInterval\s*\(\s*['"`][^'"`]+['"`]/g, risk: 'Medium' },
  { name: 'Function constructor', pattern: /new\s+Function\s*\(/g, risk: 'High' }
];

// Recognized client-side sanitizers and safe wrappers
const SANITIZATION_PATTERNS = [
  /DOMPurify\.sanitize\s*\(/i,
  /sanitizeHtml\s*\(/i,
  /\.textContent\s*=/i,
  /\.innerText\s*=/i,
  /escapeHTML\s*\(/i,
  /validator\.escape\s*\(/i
];

/**
 * Extract SPA routes from JavaScript source code (React, Vue, Angular, Next.js).
 * @param {string} jsCode - JavaScript content
 * @returns {Array<string>} - Discovered route paths
 */
export function extractSpaRoutes(jsCode) {
  if (!jsCode || typeof jsCode !== 'string') return [];
  const routes = new Set();

  const pathRegex = /(?:path|route|to)\s*[:=]\s*['"](\/[a-zA-Z0-9_\-\/:]*)['"]/gi;
  let match;
  while ((match = pathRegex.exec(jsCode)) !== null) {
    const route = match[1];
    if (route && route.length > 1 && !route.startsWith('//') && !route.includes('*')) {
      routes.add(route.split(':')[0]);
    }
  }

  return Array.from(routes).slice(0, 30);
}

/**
 * Checks if code between source and sink applies proper sanitization.
 */
function isCodeSanitized(codeSnippet) {
  return SANITIZATION_PATTERNS.some(p => p.test(codeSnippet));
}

/**
 * Statically analyze a block of JavaScript code for DOM XSS source-to-sink data flows.
 * @param {string} jsCode - JavaScript source code
 * @param {string} scriptOriginUrl - URL of script or hosting page
 * @returns {Array<object>} - Detected DOM XSS findings
 */
export function analyzeJavaScriptForDomXss(jsCode, scriptOriginUrl = '') {
  if (!jsCode || typeof jsCode !== 'string') return [];
  const findings = [];

  // 1. Identify present sources with exact match locations
  const foundSources = [];
  for (const src of DOM_SOURCES) {
    src.pattern.lastIndex = 0;
    let match;
    while ((match = src.pattern.exec(jsCode)) !== null) {
      foundSources.push({
        name: src.name,
        index: match.index,
        risk: src.risk
      });
      // Limit occurrences per pattern to avoid combinatorial explosion
      if (foundSources.filter(s => s.name === src.name).length >= 5) break;
    }
  }

  // 2. Identify present sinks with exact match locations
  const foundSinks = [];
  for (const snk of DOM_SINKS) {
    snk.pattern.lastIndex = 0;
    let match;
    while ((match = snk.pattern.exec(jsCode)) !== null) {
      foundSinks.push({
        name: snk.name,
        index: match.index,
        risk: snk.risk
      });
      if (foundSinks.filter(s => s.name === snk.name).length >= 5) break;
    }
  }

  // If no source or no sink, no DOM XSS relationship can exist
  if (foundSources.length === 0 || foundSinks.length === 0) {
    return [];
  }

  const reportedPairs = new Set();

  // 3. Trace data flows: check for proximity and variable propagation
  for (const source of foundSources) {
    for (const sink of foundSinks) {
      const distance = sink.index - source.index;

      // Source must precede sink or be close within same execution block
      if (distance > 0 && distance < 450) {
        const pairKey = `${source.name}->${sink.name}`;
        if (reportedPairs.has(pairKey)) continue;

        const blockCode = jsCode.substring(source.index, sink.index + 50);

        // Check if intermediate code applies sanitization (TEST 8)
        if (isCodeSanitized(blockCode)) {
          // Input is safely sanitized before reaching sink -> Do not flag as vulnerability!
          continue;
        }

        // Trace data flow relationship
        // Look for variable assignment: var payload = source; ... sink = payload;
        const assignRegex = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*[^;]*$/;
        const codeBeforeSource = jsCode.substring(Math.max(0, source.index - 30), source.index);
        const codeAfterSource = jsCode.substring(source.index, Math.min(jsCode.length, source.index + 80));

        let varName = null;
        const varMatch = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/.exec(codeBeforeSource + codeAfterSource);
        if (varMatch) {
          varName = varMatch[1];
        }

        // Check if variable actually reaches sink: sink = ... varName ...
        let dataFlowEstablished = false;
        if (varName && blockCode.includes(varName)) {
          dataFlowEstablished = true;
        } else if (distance < 90) {
          // Direct assignment without intermediate variable: e.g. innerHTML = location.hash
          dataFlowEstablished = true;
        }

        if (!dataFlowEstablished) {
          // Proximity exists but data flow cannot be confirmed
          continue;
        }

        reportedPairs.add(pairKey);

        const snippetStart = Math.max(0, source.index - 25);
        const snippetEnd = Math.min(jsCode.length, sink.index + 45);
        const codeSnippet = jsCode.substring(snippetStart, snippetEnd).replace(/[\r\n]+/g, ' ').trim();

        const dataFlowDescription = varName
          ? `${source.name} ➔ Variable (${varName}) ➔ ${sink.name}`
          : `${source.name} ➔ Direct Assignment ➔ ${sink.name}`;

        const reasoning = `Client-side static data flow analysis confirmed that attacker-controllable DOM source "${source.name}" propagates directly into dangerous execution sink "${sink.name}" without intervening HTML sanitization (e.g. DOMPurify).`;

        findings.push({
          id: `dom_${Math.random().toString(36).substring(2, 9)}`,
          ruleId: 'DOM_XSS_DATA_FLOW',
          title: `Potential DOM-Based XSS via Source "${source.name}" flowing into Sink "${sink.name}"`,
          category: 'Cross-Site Scripting',
          type: 'dom',
          severity: distance < 120 ? 'High' : 'Medium',
          confidence: varName ? 'High' : 'Medium',
          findingState: FINDING_STATES.POTENTIAL_XSS,
          status: 'Open',
          verificationStatus: 'needs_verification',
          reflectionDetected: false,
          storageDetected: false,
          retrievalDetected: false,
          context: 'JAVASCRIPT_CODE',
          encoding: 'NONE',
          source: source.name,
          sink: sink.name,
          url: scriptOriginUrl,
          affectedUrls: [scriptOriginUrl],
          parameter: source.name,
          method: 'Client-Side (DOM)',
          reasoning,
          description: reasoning,
          impact: 'DOM-based XSS executes entirely inside the victim browser session without sending data to the server, bypassing web application firewalls and server filters.',
          evidence: {
            source: source.name,
            sink: sink.name,
            dataFlow: dataFlowDescription,
            codeSnippet: codeSnippet.length > 250 ? codeSnippet.substring(0, 250) + '...' : codeSnippet,
            proximityDistance: `${distance} characters`,
            detectionReasoning: reasoning,
            sanitizationCheck: 'No trusted sanitizers (DOMPurify, textContent) observed between source and sink.'
          },
          remediation: `1. Use safe DOM manipulation properties:
   - Replace element.innerHTML = payload with element.textContent = payload.
2. If HTML rendering is strictly required, neutralize content using DOMPurify:
   element.innerHTML = DOMPurify.sanitize(payload);
3. Refrain from passing user input to eval() or document.write().`,
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection'
        });
      }
    }
  }

  return findings;
}

/**
 * Scan discovered endpoints and HTML pages for DOM XSS vulnerabilities.
 * @param {Array<object>} endpoints - Discovered in-scope endpoints from crawler
 * @param {object} options - Options (targetOrigin, userAgent, timeoutMs, abortSignal)
 * @returns {Promise<object>} - { findings, discoveredRoutes }
 */
export async function auditDomXss(endpoints = [], options = {}) {
  const {
    targetOrigin = '',
    userAgent,
    timeoutMs = 5000,
    abortSignal = null
  } = options;

  const findings = [];
  const discoveredRoutes = new Set();
  const auditedScripts = new Set();

  const jsEndpoints = [];
  for (const ep of endpoints) {
    if (!ep || !ep.url) continue;
    const isJs = ep.url.endsWith('.js') || ep.type === 'JavaScript Asset' || ep.contentType?.includes('javascript');
    if (isJs && isUrlInScope(ep.url, targetOrigin)) {
      jsEndpoints.push(ep.url);
    }
  }

  const targetScripts = jsEndpoints.slice(0, 8);

  for (const scriptUrl of targetScripts) {
    if (abortSignal && abortSignal.aborted) break;
    if (auditedScripts.has(scriptUrl)) continue;
    auditedScripts.add(scriptUrl);

    try {
      const res = await safeRequest(scriptUrl, {
        method: 'GET',
        timeoutMs: Math.min(4500, timeoutMs),
        userAgent,
        abortSignal
      });

      if (res.success && res.body && typeof res.body === 'string') {
        const domFindings = analyzeJavaScriptForDomXss(res.body, scriptUrl);
        if (domFindings.length > 0) {
          findings.push(...domFindings);
        }

        const routes = extractSpaRoutes(res.body);
        for (const r of routes) discoveredRoutes.add(r);
      }
    } catch {}
  }

  return {
    findings,
    discoveredRoutes: Array.from(discoveredRoutes)
  };
}
