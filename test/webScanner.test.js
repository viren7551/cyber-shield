import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { validateTargetUrl, isUrlInScope, isPrivateIPv4, isPrivateIPv6 } from '../src/modules/webScanner/engine/scopeValidator.js';
import { analyzeHeaders } from '../src/modules/webScanner/analyzers/headerAnalyzer.js';
import { analyzeCookies } from '../src/modules/webScanner/analyzers/cookieAnalyzer.js';
import { analyzeCors } from '../src/modules/webScanner/analyzers/corsAnalyzer.js';
import {
  analyzeReflectedXss,
  analyzeReflectionContext,
  canAlterParsingContext,
  XSS_CONTEXTS,
  FINDING_STATES,
  analyzeOutputEncoding,
  ENCODING_STATUS,
  buildParameterInventory,
  analyzeJavaScriptForDomXss,
  extractSpaRoutes,
  analyzeStoredXssCandidates,
  auditStoredXssLifecycle,
  verifyXssFinding
} from '../src/modules/webScanner/analyzers/xssAnalyzer.js';
import { deduplicateFindings } from '../src/modules/webScanner/findings/findingDeduplicator.js';
import { calculateRiskScore } from '../src/modules/webScanner/scoring/riskScorer.js';
import { maskValue, maskCookieHeader } from '../src/modules/webScanner/evidence/evidenceRedactor.js';
import { generateJsonReport, generateMarkdownReport, generateHtmlReport } from '../src/modules/webScanner/reports/reportGenerator.js';
import { createMockLabServer } from '../src/modules/webScanner/testLab/mockVulnerableServer.js';
import { runSecurityScan } from '../src/modules/webScanner/engine/scannerEngine.js';
import { SecurityScanService } from '../src/modules/webScanner/webScanner.model.js';

describe('Web Security Scanner - Comprehensive Test Suite', () => {

  // --------------------------------------------------------------------------
  // 1. SSRF & Scope Protections
  // --------------------------------------------------------------------------
  describe('SSRF & Scope Validation', () => {
    it('should identify private IPv4 ranges correctly', () => {
      assert.strictEqual(isPrivateIPv4('127.0.0.1'), true);
      assert.strictEqual(isPrivateIPv4('10.0.0.1'), true);
      assert.strictEqual(isPrivateIPv4('172.16.5.10'), true);
      assert.strictEqual(isPrivateIPv4('192.168.1.1'), true);
      assert.strictEqual(isPrivateIPv4('169.254.169.254'), true);
      assert.strictEqual(isPrivateIPv4('8.8.8.8'), false);
      assert.strictEqual(isPrivateIPv4('1.1.1.1'), false);
    });

    it('should identify private IPv6 addresses correctly', () => {
      assert.strictEqual(isPrivateIPv6('::1'), true);
      assert.strictEqual(isPrivateIPv6('fe80::1'), true);
      assert.strictEqual(isPrivateIPv6('2606:4700:4700::1111'), false);
    });

    it('should block localhost without allowLocalLab override', async () => {
      const res = await validateTargetUrl('http://localhost:3000', false);
      assert.strictEqual(res.valid, false);
      assert.match(res.error, /SSRF Protection/i);
    });

    it('should permit localhost when allowLocalLab is true', async () => {
      const res = await validateTargetUrl('http://127.0.0.1:8080/test', true);
      assert.strictEqual(res.valid, true);
      assert.strictEqual(res.isLocalLab, true);
      assert.strictEqual(res.hostname, '127.0.0.1');
    });

    it('should strictly enforce domain scope boundaries', () => {
      const targetOrigin = 'https://example.com';
      assert.strictEqual(isUrlInScope('https://example.com/about', targetOrigin, false), true);
      assert.strictEqual(isUrlInScope('https://example.com/login', targetOrigin, false), true);
      assert.strictEqual(isUrlInScope('https://api.example.com', targetOrigin, false), false);
      assert.strictEqual(isUrlInScope('https://api.example.com', targetOrigin, true), true);
      assert.strictEqual(isUrlInScope('https://malicious.org', targetOrigin, true), false);
    });
  });

  // --------------------------------------------------------------------------
  // 2. Security Header Analyzer
  // --------------------------------------------------------------------------
  describe('Security Header Analyzer', () => {
    it('should detect missing CSP, HSTS, and X-Content-Type-Options', () => {
      const response = {
        headers: {
          'server': 'nginx/1.24.0'
        }
      };
      const result = analyzeHeaders(response, 'https://test-site.example');
      const ruleIds = result.findings.map(f => f.ruleId);

      assert.ok(ruleIds.includes('SEC_HEADER_MISSING_CSP'), 'Missing CSP must be detected');
      assert.ok(ruleIds.includes('SEC_HEADER_MISSING_HSTS'), 'Missing HSTS must be detected');
      assert.ok(ruleIds.includes('SEC_HEADER_MISSING_X_CONTENT_TYPE_OPTIONS'), 'Missing nosniff must be detected');
      assert.ok(ruleIds.includes('INFO_DISCLOSURE_SERVER_VERSION'), 'Server version disclosure must be detected');
    });

    it('should detect weak CSP with unsafe-inline and wildcards', () => {
      const response = {
        headers: {
          'content-security-policy': "default-src 'self' *; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
          'strict-transport-security': 'max-age=31536000; includeSubDomains'
        }
      };
      const result = analyzeHeaders(response, 'https://test-site.example');
      const ruleIds = result.findings.map(f => f.ruleId);

      assert.ok(ruleIds.includes('SEC_HEADER_WEAK_CSP_UNSAFE_INLINE'), 'unsafe-inline must be detected');
      assert.ok(ruleIds.includes('SEC_HEADER_WEAK_CSP_UNSAFE_EVAL'), 'unsafe-eval must be detected');
      assert.ok(ruleIds.includes('SEC_HEADER_CSP_WILDCARD_SOURCE'), 'Wildcard in CSP must be detected');
      assert.ok(!ruleIds.includes('SEC_HEADER_MISSING_HSTS'), 'Valid HSTS should not be flagged as missing');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Cookie Security Analyzer
  // --------------------------------------------------------------------------
  describe('Cookie Security Analyzer', () => {
    it('should detect insecure cookies missing Secure and HttpOnly flags', () => {
      const setCookie = 'session_id=super_secret_token_123; Path=/';
      const result = analyzeCookies(setCookie, 'https://bank.example');
      const ruleIds = result.findings.map(f => f.ruleId);

      assert.ok(ruleIds.includes('SEC_COOKIE_MISSING_SECURE'), 'Missing Secure on HTTPS must be flagged');
      assert.ok(ruleIds.includes('SEC_COOKIE_MISSING_HTTPONLY'), 'Missing HttpOnly on session cookie must be flagged');
      assert.ok(ruleIds.includes('SEC_COOKIE_MISSING_SAMESITE'), 'Missing SameSite must be flagged');
      assert.strictEqual(result.cookies[0].maskedValue.includes('super_secret_token_123'), false, 'Value must be masked');
    });
  });

  // --------------------------------------------------------------------------
  // 4. Evidence Redaction
  // --------------------------------------------------------------------------
  describe('Evidence Redactor', () => {
    it('should redact sensitive session values and passwords', () => {
      const masked = maskValue('mySecretPassword123');
      assert.strictEqual(masked.includes('Password123'), false);
      assert.strictEqual(masked.startsWith('myS'), true);

      const cookieStr = maskCookieHeader('token=xyz987654321; Path=/; HttpOnly');
      assert.strictEqual(cookieStr.includes('xyz987654321'), false);
    });
  });

  // --------------------------------------------------------------------------
  // 5. Finding Deduplication & Risk Scoring
  // --------------------------------------------------------------------------
  describe('Finding Deduplication & Risk Scoring', () => {
    it('should group duplicate findings across multiple URLs into one primary finding', () => {
      const raw = [
        { ruleId: 'MISSING_CSP', title: 'Missing CSP', severity: 'Medium', url: '/page1' },
        { ruleId: 'MISSING_CSP', title: 'Missing CSP', severity: 'Medium', url: '/page2' },
        { ruleId: 'MISSING_CSP', title: 'Missing CSP', severity: 'Medium', url: '/page3' },
        { ruleId: 'WEAK_COOKIE', title: 'Weak Cookie', severity: 'Low', url: '/login' }
      ];

      const deduplicated = deduplicateFindings(raw);
      assert.strictEqual(deduplicated.length, 2);

      const cspFinding = deduplicated.find(f => f.ruleId === 'MISSING_CSP');
      assert.strictEqual(cspFinding.affectedUrls.length, 3);
      assert.deepStrictEqual(cspFinding.affectedUrls, ['/page1', '/page2', '/page3']);
    });

    it('should calculate objective transparent risk score with explanation', () => {
      const findings = [
        { severity: 'Critical', confidence: 'High', affectedUrls: ['/'] },
        { severity: 'High', confidence: 'High', affectedUrls: ['/a', '/b'] },
        { severity: 'Medium', confidence: 'High', affectedUrls: ['/c'] }
      ];

      const score = calculateRiskScore(findings, 5);
      assert.ok(score.score > 50, 'Critical + High findings should result in elevated risk score');
      assert.ok(score.explanation.length > 20, 'Explanation must be provided');
      assert.strictEqual(score.counts.Critical, 1);
      assert.strictEqual(score.counts.High, 1);
      assert.strictEqual(score.counts.Medium, 1);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Local Test Lab & Full End-to-End Scan Integration
  // --------------------------------------------------------------------------
  describe('Local Test Lab Integration Scan & 8 XSS Lab Test Scenarios', () => {
    let mockServer;
    const testPort = 9888;
    const testTarget = `http://127.0.0.1:${testPort}`;

    before(async () => {
      mockServer = createMockLabServer();
      await new Promise((resolve) => mockServer.listen(testPort, '127.0.0.1', resolve));
    });

    after(async () => {
      if (mockServer) {
        await new Promise((resolve) => mockServer.close(resolve));
      }
    });

    it('should perform real scan against the local test lab and detect intentional flaws', async () => {
      const scanParams = {
        target: testTarget,
        profile: 'standard',
        allowLocalLab: true,
        maxDepth: 1,
        maxPages: 5,
        timeoutMs: 4000
      };

      const scanResult = await runSecurityScan(scanParams, 'test_scan_001');

      assert.strictEqual(scanResult.status, 'completed', 'Scan must complete successfully');
      assert.ok(scanResult.findings.length > 0, 'Real findings must be generated against test lab');

      const findingTitles = scanResult.findings.map(f => f.title);

      const hasMissingCsp = findingTitles.some(t => t.includes('Content-Security-Policy'));
      const hasServerDisclosure = findingTitles.some(t => t.includes('Server'));
      const hasCookieFinding = findingTitles.some(t => t.includes('Cookie'));

      assert.ok(hasMissingCsp, 'Scanner must detect missing CSP in test lab');
      assert.ok(hasServerDisclosure, 'Scanner must detect server version disclosure in test lab');
      assert.ok(hasCookieFinding, 'Scanner must detect weak cookie in test lab');

      // Verify persistence & retrieval
      await SecurityScanService.createScan(scanResult);
      const retrieved = await SecurityScanService.getScanById('test_scan_001');
      assert.strictEqual(retrieved.scanId, 'test_scan_001');

      // Verify report generation
      const jsonReport = generateJsonReport(scanResult, scanResult.findings, scanResult.endpoints);
      assert.ok(jsonReport.executiveSummary.targetUrl.includes(String(testPort)));
      assert.strictEqual(jsonReport.technicalFindings.length, scanResult.findings.length);

      const htmlReport = generateHtmlReport(scanResult, scanResult.findings, scanResult.endpoints);
      assert.ok(htmlReport.includes('<!DOCTYPE html>'));
      assert.ok(htmlReport.includes(scanResult.target));

      const mdReport = generateMarkdownReport(scanResult, scanResult.findings, scanResult.endpoints);
      assert.ok(mdReport.includes('# CyberShield Web Security Audit Report'));
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 1 - Input is not reflected -> Expected: No XSS finding
    // ------------------------------------------------------------------------
    it('TEST 1: should not create XSS finding when input is not reflected', async () => {
      const endpoints = [{ url: `${testTarget}/no-reflection?q=search` }];
      const findings = await analyzeReflectedXss(endpoints, { timeoutMs: 3000, targetUrl: testTarget });
      const xssFinding = findings.find(f => f.parameter === 'q' && f.type === 'reflected');
      assert.strictEqual(xssFinding, undefined, 'No XSS finding must be created when input is not reflected');
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 2 - Input is reflected as plain HTML text -> Expected: Reflection Only (Informational, NOT XSS)
    // ------------------------------------------------------------------------
    it('TEST 2: should classify plain HTML text reflection as Reflection Only (Informational, NOT XSS)', async () => {
      const endpoints = [{ url: `${testTarget}/plain-reflection?q=test` }];
      const findings = await analyzeReflectedXss(endpoints, { timeoutMs: 3000, targetUrl: testTarget });
      const reflFinding = findings.find(f => f.parameter === 'q');

      assert.ok(reflFinding, 'Must identify input reflection');
      assert.strictEqual(reflFinding.type, 'reflection', 'Must be classified as reflection, NOT XSS');
      assert.strictEqual(reflFinding.severity, 'Informational', 'Reflection only must be Informational severity');
      assert.strictEqual(reflFinding.findingState, FINDING_STATES.REFLECTION_ONLY, 'Must have REFLECTION_ONLY state');
      assert.strictEqual(reflFinding.reflectionDetected, true);
      assert.strictEqual(reflFinding.category, 'Input Reflection');
      assert.ok(reflFinding.reasoning.includes('does not establish cross-site scripting'));
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 3 - Input is HTML encoded -> Expected: Encoded Reflection (Informational, NOT XSS)
    // ------------------------------------------------------------------------
    it('TEST 3: should classify HTML encoded input as Encoded Reflection (Informational, NOT XSS)', async () => {
      const endpoints = [{ url: `${testTarget}/safe-search?q=test` }];
      const findings = await analyzeReflectedXss(endpoints, { timeoutMs: 3000, targetUrl: testTarget });
      const safeFinding = findings.find(f => f.parameter === 'q');

      assert.ok(safeFinding, 'Must identify encoded reflection finding');
      assert.strictEqual(safeFinding.type, 'reflection', 'Must be classified as reflection, NOT XSS');
      assert.strictEqual(safeFinding.severity, 'Informational', 'Safe encoded reflection must be Informational severity');
      assert.strictEqual(safeFinding.findingState, FINDING_STATES.ENCODED_REFLECTION, 'Must have ENCODED_REFLECTION state');
      assert.strictEqual(safeFinding.encoding, 'HTML_ENTITIES', 'Encoding must be recognized as HTML_ENTITIES');
      assert.ok(safeFinding.reasoning.includes('No XSS vulnerability was established'));
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 4 - Input reaches dangerous HTML context without encoding -> Expected: High Confidence XSS
    // ------------------------------------------------------------------------
    it('TEST 4: should detect unencoded reflection altering parsing context as High Confidence XSS', async () => {
      const endpoints = [{ url: `${testTarget}/search?q=initial` }];
      const findings = await analyzeReflectedXss(endpoints, { timeoutMs: 3000, targetUrl: testTarget });
      const xssFinding = findings.find(f => f.parameter === 'q' && f.type === 'reflected');

      assert.ok(xssFinding, 'Must detect reflected XSS finding on parameter q');
      assert.strictEqual(xssFinding.type, 'reflected');
      assert.strictEqual(xssFinding.cwe, 'CWE-79');
      assert.strictEqual(xssFinding.severity, 'High');
      assert.strictEqual(xssFinding.findingState, FINDING_STATES.HIGH_CONFIDENCE_XSS);
      assert.strictEqual(xssFinding.encoding, 'NONE');
      assert.ok(xssFinding.evidence.vulnerableEndpoint.includes('/search'));
      assert.strictEqual(xssFinding.evidence.vulnerableParameter, 'q');
      assert.ok(xssFinding.reasoning.includes('Attacker-controlled input was reflected'));
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 5 - Stored input is saved but safely encoded when displayed -> Expected: No XSS
    // ------------------------------------------------------------------------
    it('TEST 5: should report No XSS when stored input is safely encoded upon retrieval', async () => {
      const form = {
        action: `${testTarget}/stored-safe`,
        method: 'POST',
        inputs: [{ name: 'comment', type: 'textarea' }]
      };
      const result = await auditStoredXssLifecycle(form, [`${testTarget}/stored-safe`], { timeoutMs: 3000 });
      assert.ok(result, 'Must complete lifecycle audit');
      assert.strictEqual(result.severity, 'Informational');
      assert.strictEqual(result.findingState, FINDING_STATES.ENCODED_REFLECTION);
      assert.strictEqual(result.category, 'Input Reflection');
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 6 - Stored input retrieved into unsafe context -> Expected: High Confidence Stored XSS
    // ------------------------------------------------------------------------
    it('TEST 6: should detect High Confidence Stored XSS when persisted input is retrieved unescaped', async () => {
      const form = {
        action: `${testTarget}/stored-vuln`,
        method: 'POST',
        inputs: [{ name: 'comment', type: 'textarea' }]
      };
      const result = await auditStoredXssLifecycle(form, [`${testTarget}/stored-vuln`], { timeoutMs: 3000 });
      assert.ok(result, 'Must detect verified stored XSS');
      assert.strictEqual(result.type, 'stored');
      assert.strictEqual(result.severity, 'High');
      assert.strictEqual(result.findingState, FINDING_STATES.HIGH_CONFIDENCE_XSS);
      assert.strictEqual(result.storageDetected, true);
      assert.strictEqual(result.retrievalDetected, true);
      assert.strictEqual(result.encoding, 'NONE');
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 7 - DOM source reaches dangerous sink -> Expected: Potential DOM XSS
    // ------------------------------------------------------------------------
    it('TEST 7: should detect Potential DOM XSS when source flows directly into dangerous sink', async () => {
      const endpoints = [{ url: `${testTarget}/static/dom-test.js`, type: 'JavaScript Asset' }];
      const findings = await analyzeReflectedXss(endpoints, { timeoutMs: 3000, targetUrl: testTarget });
      const domFinding = findings.find(f => f.type === 'dom');

      assert.ok(domFinding, 'Must detect DOM XSS finding');
      assert.strictEqual(domFinding.type, 'dom');
      assert.strictEqual(domFinding.cwe, 'CWE-79');
      assert.ok(domFinding.evidence.source.includes('location.hash'));
      assert.ok(domFinding.evidence.sink.includes('innerHTML'));
      assert.strictEqual(domFinding.findingState, FINDING_STATES.POTENTIAL_XSS);
    });

    // ------------------------------------------------------------------------
    // SECTION 15: TEST 8 - DOM source exists but is safely sanitized before sink -> Expected: No XSS
    // ------------------------------------------------------------------------
    it('TEST 8: should not flag DOM XSS when data flow is safely sanitized (e.g. textContent)', async () => {
      const safeJsCode = `
        window.addEventListener('DOMContentLoaded', function() {
          var userPayload = location.hash.substring(1);
          if (userPayload) {
            document.getElementById('output').textContent = userPayload;
          }
        });
      `;
      const findings = analyzeJavaScriptForDomXss(safeJsCode, `${testTarget}/static/dom-safe.js`);
      assert.strictEqual(findings.length, 0, 'Safely sanitized DOM flow must NOT produce XSS vulnerability finding');
    });
  });

  // --------------------------------------------------------------------------
  // 7. XSS Detection Engine - Comprehensive Unit Tests
  // --------------------------------------------------------------------------
  describe('Cross-Site Scripting (XSS) Engine - Unit & Detection Tests', () => {
    it('should accurately detect reflection contexts (Text, Attribute, Value, Script, URL, Comment)', () => {
      const marker = 'XSSSCAN_TEST123';

      // HTML Text context
      const htmlText = `<div><h1>Search for: ${marker}</h1><p>Results</p></div>`;
      const textRes = analyzeReflectionContext(htmlText, marker);
      assert.strictEqual(textRes.reflected, true);
      assert.strictEqual(textRes.context, XSS_CONTEXTS.HTML_TEXT);

      // HTML Attribute Value context
      const htmlAttrVal = `<form><input type="text" name="q" value="${marker}"></form>`;
      const attrValRes = analyzeReflectionContext(htmlAttrVal, marker);
      assert.strictEqual(attrValRes.reflected, true);
      assert.strictEqual(attrValRes.context, XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE);

      // HTML Attribute context (attribute name / bare)
      const htmlAttr = `<form><input type="text" ${marker}="foo"></form>`;
      const attrRes = analyzeReflectionContext(htmlAttr, marker);
      assert.strictEqual(attrRes.reflected, true);
      assert.strictEqual(attrRes.context, XSS_CONTEXTS.HTML_ATTRIBUTE);

      // JavaScript context
      const htmlJs = `<script>var searchQuery = "${marker}"; console.log(searchQuery);</script>`;
      const jsRes = analyzeReflectionContext(htmlJs, marker);
      assert.strictEqual(jsRes.reflected, true);
      assert.strictEqual(jsRes.context, XSS_CONTEXTS.JAVASCRIPT_STRING);

      // URL context
      const htmlUrl = `<a href="/profile?ref=${marker}">View Profile</a>`;
      const urlRes = analyzeReflectionContext(htmlUrl, marker);
      assert.strictEqual(urlRes.reflected, true);
      assert.strictEqual(urlRes.context, XSS_CONTEXTS.URL_CONTEXT);

      // HTML Comment context
      const htmlComment = `<!-- User query debug: ${marker} --><div>Page content</div>`;
      const commentRes = analyzeReflectionContext(htmlComment, marker);
      assert.strictEqual(commentRes.reflected, true);
      assert.strictEqual(commentRes.context, XSS_CONTEXTS.HTML_COMMENT);
    });

    it('should accurately evaluate context alterability with canAlterParsingContext', () => {
      // In HTML_TEXT: < and > can alter context, alphanumeric alone cannot
      const canAlterText = canAlterParsingContext(['<', '>'], XSS_CONTEXTS.HTML_TEXT);
      assert.strictEqual(canAlterText.canAlter, true);

      const cannotAlterText = canAlterParsingContext([], XSS_CONTEXTS.HTML_TEXT);
      assert.strictEqual(cannotAlterText.canAlter, false);

      // In HTML_ATTRIBUTE_VALUE with double quote: " can alter context
      const canAlterAttr = canAlterParsingContext(['"'], XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE, '"');
      assert.strictEqual(canAlterAttr.canAlter, true);

      const cannotAlterAttr = canAlterParsingContext(["'"], XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE, '"');
      assert.strictEqual(cannotAlterAttr.canAlter, false);
    });

    it('should distinguish properly encoded input from unencoded reflection (False Positive Reduction)', () => {
      const marker = 'XSSSCAN_ENC_01';

      // Safely entity encoded response
      const safeHtml = `<h1>Search for: ${marker}&#39;&quot;&gt;&lt;csxss&gt;&amp;</h1>`;
      const safeRes = analyzeOutputEncoding(safeHtml, marker);
      assert.strictEqual(safeRes.status, ENCODING_STATUS.SAFE_ENCODED);
      assert.strictEqual(safeRes.hasUnencodedMetas, false);

      // Raw unencoded reflection
      const vulnHtml = `<h1>Search for: ${marker}'"><csxss>&</h1>`;
      const vulnRes = analyzeOutputEncoding(vulnHtml, marker);
      assert.strictEqual(vulnRes.status, ENCODING_STATUS.UNENCODED);
      assert.strictEqual(vulnRes.hasUnencodedMetas, true);
      assert.ok(vulnRes.unencodedChars.includes('<'));
      assert.ok(vulnRes.unencodedChars.includes('>'));
    });

    it('should build a normalized parameter inventory from endpoints and forms', () => {
      const endpoints = [
        { url: 'https://example.com/search?q=cyber&sort=asc', contentType: 'text/html' },
        { url: 'https://example.com/item?id=42', contentType: 'text/html' }
      ];
      const forms = [
        {
          action: 'https://example.com/feedback',
          method: 'POST',
          inputs: [
            { name: 'name', type: 'text' },
            { name: 'comments', type: 'textarea' },
            { name: 'csrf_token', type: 'hidden' }
          ]
        }
      ];

      const inventory = buildParameterInventory(endpoints, forms, 'https://example.com');
      assert.ok(inventory.length >= 2, 'Should create inventory entries for search and feedback');

      const searchEntry = inventory.find(e => e.endpoint.includes('/search'));
      assert.ok(searchEntry);
      assert.strictEqual(searchEntry.method, 'GET');
      const paramNames = searchEntry.parameters.map(p => p.name);
      assert.ok(paramNames.includes('q'));
      assert.ok(paramNames.includes('sort'));

      const feedbackEntry = inventory.find(e => e.endpoint.includes('/feedback'));
      assert.ok(feedbackEntry);
      assert.strictEqual(feedbackEntry.method, 'POST');
      const feedbackParamNames = feedbackEntry.parameters.map(p => p.name);
      assert.ok(feedbackParamNames.includes('comments'));
    });

    it('should statically analyze JavaScript for DOM XSS sources, sinks, and SPA routes', () => {
      const jsCode = `
        function renderProfile() {
          var userHash = location.hash.substring(1);
          document.getElementById('profile-view').innerHTML = userHash;
        }
        const appRoutes = [
          { path: '/dashboard', component: Dashboard },
          { path: '/settings', component: Settings }
        ];
      `;

      const findings = analyzeJavaScriptForDomXss(jsCode, 'https://example.com/static/bundle.js');
      assert.strictEqual(findings.length, 1, 'Must detect 1 DOM XSS finding');
      assert.strictEqual(findings[0].type, 'dom');
      assert.strictEqual(findings[0].cwe, 'CWE-79');
      assert.ok(findings[0].evidence.source.includes('location.hash'));
      assert.ok(findings[0].evidence.sink.includes('innerHTML'));

      const routes = extractSpaRoutes(jsCode);
      assert.ok(routes.includes('/dashboard'));
      assert.ok(routes.includes('/settings'));
    });

    it('should identify Stored XSS candidate locations on state-changing forms', () => {
      const forms = [
        {
          action: 'https://example.com/submit-review',
          method: 'POST',
          inputs: [
            { name: 'author', type: 'text' },
            { name: 'review', type: 'textarea' }
          ]
        }
      ];

      const candidates = analyzeStoredXssCandidates(forms, [], 'https://example.com');
      assert.strictEqual(candidates.length, 1, 'Must identify 1 Stored XSS candidate');
      assert.strictEqual(candidates[0].type, 'stored');
      assert.strictEqual(candidates[0].severity, 'Medium');
      assert.strictEqual(candidates[0].confidence, 'Medium');
      assert.strictEqual(candidates[0].storageDetected, false);
      assert.strictEqual(candidates[0].retrievalDetected, false);
      assert.ok(candidates[0].evidence.candidateFields.some(f => f.includes('review')));
    });

    it('should perform safe non-destructive verification of findings', async () => {
      const storedFinding = {
        type: 'stored',
        url: 'https://example.com/comment',
        parameter: 'comment',
        evidence: { endpoint: 'https://example.com/comment' }
      };

      const verifyRes = await verifyXssFinding(storedFinding);
      assert.strictEqual(verifyRes.verified, true);
      assert.strictEqual(verifyRes.findingState, 'Needs Manual Verification');
    });
  });

});
