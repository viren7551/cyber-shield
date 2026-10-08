import {
  runFullXssAudit,
  verifyXssFinding
} from '../xss/xssOrchestrator.js';
import { buildParameterInventory } from '../xss/parameterInventory.js';
import { analyzeReflectionContext, canAlterParsingContext, XSS_CONTEXTS, FINDING_STATES } from '../xss/contextAnalyzer.js';
import { analyzeOutputEncoding, ENCODING_STATUS } from '../xss/encodingAnalyzer.js';
import { auditReflectedXss } from '../xss/reflectedXssEngine.js';
import { analyzeStoredXssCandidates, auditStoredXssLifecycle } from '../xss/storedXssAnalyzer.js';
import { auditDomXss, analyzeJavaScriptForDomXss, extractSpaRoutes } from '../xss/domXssAnalyzer.js';

/**
 * CyberShield Web Security Scanner - Master XSS Analyzer Facade
 * Provides unified entry points for Reflected, Stored Candidate, and DOM XSS audits.
 */

/**
 * Audit discovered endpoints and forms for all XSS vector classes (Reflected, Stored, DOM).
 * @param {Array<object>} endpoints - Discovered in-scope endpoints from crawler
 * @param {object} options - Request options (targetUrl, forms, userAgent, timeoutMs, abortSignal)
 * @returns {Promise<Array<object>>} - Detected XSS vulnerability findings
 */
export async function analyzeReflectedXss(endpoints = [], options = {}) {
  const result = await runFullXssAudit(endpoints, options);
  return result.findings || [];
}

export {
  runFullXssAudit,
  verifyXssFinding,
  buildParameterInventory,
  analyzeReflectionContext,
  canAlterParsingContext,
  XSS_CONTEXTS,
  FINDING_STATES,
  analyzeOutputEncoding,
  ENCODING_STATUS,
  auditReflectedXss,
  analyzeStoredXssCandidates,
  auditStoredXssLifecycle,
  auditDomXss,
  analyzeJavaScriptForDomXss,
  extractSpaRoutes
};
