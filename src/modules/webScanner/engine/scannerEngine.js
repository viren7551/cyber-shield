import { validateTargetUrl } from './scopeValidator.js';
import { safeRequest } from './httpClient.js';
import { analyzeRedirects } from '../analyzers/redirectAnalyzer.js';
import { analyzeTls } from '../analyzers/tlsAnalyzer.js';
import { analyzeHeaders } from '../analyzers/headerAnalyzer.js';
import { analyzeCookies } from '../analyzers/cookieAnalyzer.js';
import { analyzeCors } from '../analyzers/corsAnalyzer.js';
import { analyzeHttpMethods } from '../analyzers/methodAnalyzer.js';
import { detectTechnologies } from '../analyzers/technologyDetector.js';
import { analyzeReflectedXss, buildParameterInventory } from '../analyzers/xssAnalyzer.js';
import { crawlTarget } from '../crawler/crawler.js';
import { deduplicateFindings } from '../findings/findingDeduplicator.js';
import { calculateRiskScore } from '../scoring/riskScorer.js';
import { sanitizeEvidence } from '../evidence/evidenceRedactor.js';

// In-memory active scan controllers for instant cancellation
const activeScanControllers = new Map();
// In-memory event listeners for real-time progress SSE
const scanEventListeners = new Map();

/**
 * Register a listener for real-time scan progress updates
 */
export function registerScanListener(scanId, callback) {
  if (!scanEventListeners.has(scanId)) {
    scanEventListeners.set(scanId, new Set());
  }
  scanEventListeners.get(scanId).add(callback);
}

/**
 * Remove a listener
 */
export function removeScanListener(scanId, callback) {
  if (scanEventListeners.has(scanId)) {
    scanEventListeners.get(scanId).delete(callback);
    if (scanEventListeners.get(scanId).size === 0) {
      scanEventListeners.delete(scanId);
    }
  }
}

/**
 * Broadcast progress event to all active listeners
 */
function emitScanProgress(scanId, eventData) {
  if (scanEventListeners.has(scanId)) {
    for (const cb of scanEventListeners.get(scanId)) {
      try {
        cb(eventData);
      } catch (err) {
        console.warn('[ScanProgress] Listener notification error:', err.message);
      }
    }
  }
}

/**
 * Cancel an active scan
 */
export function cancelActiveScan(scanId) {
  if (activeScanControllers.has(scanId)) {
    const controller = activeScanControllers.get(scanId);
    controller.abort();
    activeScanControllers.delete(scanId);
    emitScanProgress(scanId, {
      type: 'status',
      status: 'cancelled',
      step: 'Scan cancelled by user',
      progress: 100
    });
    return true;
  }
  return false;
}

/**
 * Main Web Security Scanner Orchestrator
 * @param {object} scanParams - User scan configuration
 * @param {string} scanId - ID of the scan record
 */
export async function runSecurityScan(scanParams, scanId) {
  const {
    target,
    profile = 'standard',
    maxDepth: customMaxDepth,
    maxPages: customMaxPages,
    timeoutMs: customTimeout = 10000,
    rateLimitMs: customRateLimit = 150,
    userAgent,
    includeSubdomains = false,
    analyzeForms: enableForms = true,
    analyzeCookies: enableCookies = true,
    analyzeHeaders: enableHeaders = true,
    analyzeTls: enableTls = true,
    allowLocalLab = false
  } = scanParams;

  // Configure profile parameters
  let maxDepth = 2;
  let maxPages = 30;

  if (profile === 'quick') {
    maxDepth = 1;
    maxPages = 5;
  } else if (profile === 'deep') {
    maxDepth = 3;
    maxPages = 60;
  }

  if (customMaxDepth !== undefined && customMaxDepth !== '') maxDepth = parseInt(customMaxDepth, 10);
  if (customMaxPages !== undefined && customMaxPages !== '') maxPages = parseInt(customMaxPages, 10);
  const timeoutMs = parseInt(customTimeout, 10) || 10000;
  const rateLimitMs = parseInt(customRateLimit, 10) || 150;

  const abortController = new AbortController();
  activeScanControllers.set(scanId, abortController);

  const startTime = Date.now();
  const rawFindings = [];
  let discoveredEndpoints = [];
  let discoveredForms = [];
  let tlsAnalysis = null;
  let headerAnalysis = null;
  let cookieAnalysis = null;
  let corsAnalysis = null;
  let methodAnalysis = null;
  let redirectAnalysis = null;
  let detectedTechnologies = [];

  const updateProgress = (step, currentModule, progressPercent, extra = {}) => {
    emitScanProgress(scanId, {
      type: 'progress',
      scanId,
      step,
      currentModule,
      progress: progressPercent,
      urlsScanned: extra.urlsScanned || 1,
      findingsDiscovered: rawFindings.length,
      durationMs: Date.now() - startTime,
      ...extra
    });
  };

  try {
    // -------------------------------------------------------------
    // Phase 1: Target Validation & SSRF Check (5%)
    // -------------------------------------------------------------
    updateProgress('Target validation & SSRF verification', 'Target Validator', 5);

    const targetVal = await validateTargetUrl(target, allowLocalLab);
    if (!targetVal.valid) {
      throw new Error(`Target Validation Failed: ${targetVal.error}`);
    }

    const normalizedTarget = targetVal.normalizedUrl;
    const isHttps = targetVal.protocol === 'https:';

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 2: Initial HTTP Request & Redirect Chain (15%)
    // -------------------------------------------------------------
    updateProgress('Connecting to target & tracing redirects', 'HTTP Client', 15);

    const initialRes = await safeRequest(normalizedTarget, {
      timeoutMs,
      userAgent,
      abortSignal: abortController.signal
    });

    if (!initialRes.success) {
      throw new Error(`Initial connection to target failed: ${initialRes.error || 'Server unreachable'}`);
    }

    // Inspect redirect behavior
    redirectAnalysis = await analyzeRedirects(normalizedTarget, initialRes, {
      timeoutMs,
      userAgent,
      abortSignal: abortController.signal
    });
    if (redirectAnalysis.findings?.length) {
      rawFindings.push(...redirectAnalysis.findings);
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 3: TLS / SSL Deep Inspection (30%)
    // -------------------------------------------------------------
    if (enableTls && (isHttps || targetVal.port === 443)) {
      updateProgress('Auditing TLS / SSL certificates & ciphers', 'TLS Analyzer', 30);
      tlsAnalysis = await analyzeTls(targetVal.hostname, targetVal.port, 8000);
      if (tlsAnalysis.findings?.length) {
        rawFindings.push(...tlsAnalysis.findings);
      }
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 4: Security Header Analysis (45%)
    // -------------------------------------------------------------
    if (enableHeaders) {
      updateProgress('Evaluating HTTP security headers', 'Header Analyzer', 45);
      headerAnalysis = analyzeHeaders(initialRes, normalizedTarget);
      if (headerAnalysis.findings?.length) {
        rawFindings.push(...headerAnalysis.findings);
      }
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 5: Cookie Security Audit (55%)
    // -------------------------------------------------------------
    if (enableCookies) {
      updateProgress('Auditing cookie security flags & domains', 'Cookie Analyzer', 55);
      const cookiesHeader = initialRes.headers['set-cookie'];
      cookieAnalysis = analyzeCookies(cookiesHeader, normalizedTarget);
      if (cookieAnalysis.findings?.length) {
        rawFindings.push(...cookieAnalysis.findings);
      }
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 6: CORS & HTTP Method Probe (65%)
    // -------------------------------------------------------------
    updateProgress('Probing CORS policy & HTTP methods', 'CORS & Method Analyzer', 65);

    corsAnalysis = await analyzeCors(normalizedTarget, initialRes.headers, {
      timeoutMs,
      userAgent,
      abortSignal: abortController.signal
    });
    if (corsAnalysis.findings?.length) {
      rawFindings.push(...corsAnalysis.findings);
    }

    methodAnalysis = await analyzeHttpMethods(normalizedTarget, {
      timeoutMs,
      userAgent,
      abortSignal: abortController.signal
    });
    if (methodAnalysis.findings?.length) {
      rawFindings.push(...methodAnalysis.findings);
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 7: Passive Technology Fingerprinting (70%)
    // -------------------------------------------------------------
    updateProgress('Fingerprinting frameworks and servers', 'Technology Detector', 70);

    detectedTechnologies = detectTechnologies(
      initialRes.headers,
      initialRes.body,
      cookieAnalysis?.cookies || []
    );

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 8: Controlled In-Scope Crawling & Form Analysis (85%)
    // -------------------------------------------------------------
    updateProgress('Executing controlled crawl & endpoint discovery', 'Web Crawler', 75);

    const crawlResult = await crawlTarget(normalizedTarget, {
      maxDepth,
      maxPages,
      rateLimitMs,
      includeSubdomains,
      userAgent,
      timeoutMs,
      abortSignal: abortController.signal,
      onPageCrawled: (event) => {
        updateProgress(
          `Crawling: ${event.url.substring(0, 50)}...`,
          'Web Crawler',
          Math.min(84, 75 + Math.round((event.pagesCrawledCount / maxPages) * 9)),
          { urlsScanned: event.pagesCrawledCount }
        );
      },
      onEndpointProbed: (event) => {
        updateProgress(
          `Visiting endpoints (${event.probedCount}/${event.totalCount}): ${event.url.substring(0, 42)}... [200 OK]`,
          'Endpoint Verifier',
          Math.min(89, 83 + Math.round((event.probedCount / event.totalCount) * 6)),
          { endpointsVerified: event.probedCount, totalEndpoints: event.totalCount }
        );
      }
    });

    discoveredEndpoints = crawlResult.discoveredEndpoints || [];
    discoveredForms = crawlResult.discoveredForms || [];
    const discoveredInputFields = crawlResult.discoveredInputFields || [];

    if (crawlResult.findings?.length) {
      rawFindings.push(...crawlResult.findings);
    }

    // Inspect headers and cookies on subsequent crawled pages as well for thorough coverage
    if (crawlResult.crawledPages && crawlResult.crawledPages.length > 1) {
      for (let i = 1; i < crawlResult.crawledPages.length; i++) {
        const page = crawlResult.crawledPages[i];
        if (enableHeaders && page.headers) {
          const subHeaderRes = analyzeHeaders(page, page.url);
          if (subHeaderRes.findings?.length) {
            rawFindings.push(...subHeaderRes.findings);
          }
        }
        if (enableCookies && page.headers?.['set-cookie']) {
          const subCookieRes = analyzeCookies(page.headers['set-cookie'], page.url);
          if (subCookieRes.findings?.length) {
            rawFindings.push(...subCookieRes.findings);
          }
        }
      }
    }

    if (abortController.signal.aborted) throw new Error('Scan cancelled by user.');

    // -------------------------------------------------------------
    // Phase 9: Finding Deduplication & Risk Scoring (95%)
    // -------------------------------------------------------------
    updateProgress('Deduplicating findings & calculating risk score', 'Scoring Engine', 95);

    const deduplicatedFindings = deduplicateFindings(rawFindings);
    const riskScoreData = calculateRiskScore(deduplicatedFindings, crawlResult.totalPagesScanned || 1);

    // -------------------------------------------------------------
    // Phase 10: Finalizing & Sanitizing Evidence (100%)
    // -------------------------------------------------------------
    updateProgress('Finalizing security audit report', 'Report Generator', 100);

    const sanitizedFindings = deduplicatedFindings.map(f => ({
      ...f,
      evidence: sanitizeEvidence(f.evidence)
    }));

    const sanitizedCookies = (cookieAnalysis?.cookies || []).map(c => ({
      ...c,
      maskedValue: c.maskedValue || '********'
    }));

    activeScanControllers.delete(scanId);

    const scanResult = {
      scanId,
      status: 'completed',
      target: normalizedTarget,
      hostname: targetVal.hostname,
      isLocalLab: targetVal.isLocalLab,
      profile,
      startedAt: new Date(startTime),
      completedAt: new Date(),
      duration: Date.now() - startTime,
      riskScore: riskScoreData.score,
      statistics: riskScoreData,
      targetInfo: {
        resolvedIps: targetVal.resolvedIps,
        statusCode: initialRes.statusCode,
        technologies: detectedTechnologies,
        tls: tlsAnalysis,
        headerAudit: headerAnalysis?.headerAudit || {},
        cookies: sanitizedCookies,
        cors: corsAnalysis?.status || {},
        methods: methodAnalysis?.supportedMethods || [],
        redirects: redirectAnalysis?.chain || [],
        totalPagesCrawled: crawlResult.totalPagesScanned,
        totalEndpointsDiscovered: discoveredEndpoints.length,
        workingEndpointsCount: discoveredEndpoints.filter(e => e.isWorking || (e.statusCode >= 200 && e.statusCode < 400)).length,
        visitableEndpointsCount: discoveredEndpoints.filter(e => e.isWorking || (e.statusCode >= 200 && e.statusCode < 400)).length,
        totalFormsDiscovered: discoveredForms.length,
        forms: discoveredForms,
        inputFields: discoveredInputFields,
        totalInputFieldsDiscovered: discoveredInputFields.length,
        parameterizedUrls: crawlResult.parameterizedUrls || [],
        totalParameterizedUrls: (crawlResult.parameterizedUrls || []).length,
        parameterInventory: buildParameterInventory(discoveredEndpoints, discoveredForms, normalizedTarget, discoveredInputFields)
      },
      findings: sanitizedFindings,
      endpoints: discoveredEndpoints,
      parameterizedUrls: crawlResult.parameterizedUrls || []
    };

    emitScanProgress(scanId, {
      type: 'completed',
      scanId,
      result: scanResult,
      progress: 100
    });

    return scanResult;
  } catch (err) {
    activeScanControllers.delete(scanId);
    const isCancelled = abortController.signal.aborted || err.message.includes('cancelled');

    const failedResult = {
      scanId,
      status: isCancelled ? 'cancelled' : 'failed',
      target,
      startedAt: new Date(startTime),
      completedAt: new Date(),
      duration: Date.now() - startTime,
      error: err.message,
      riskScore: 0,
      statistics: { score: 0, counts: {}, explanation: 'Scan did not complete.' },
      targetInfo: {},
      findings: [],
      endpoints: []
    };

    emitScanProgress(scanId, {
      type: isCancelled ? 'cancelled' : 'failed',
      scanId,
      error: err.message,
      progress: 100
    });

    return failedResult;
  }
}
