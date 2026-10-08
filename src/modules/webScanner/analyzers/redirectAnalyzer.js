import { safeRequest } from '../engine/httpClient.js';
import { isUrlInScope } from '../engine/scopeValidator.js';

/**
 * CyberShield Web Security Scanner - Redirect Chain Analyzer
 * Traces HTTP to HTTPS upgrades, multi-hop chains, canonical host patterns,
 * and detects suspicious external redirects.
 */

/**
 * Inspect redirect behavior starting from target URL
 * @param {string} targetUrl
 * @param {object} baseResult - Output of initial request
 * @param {object} clientOptions
 */
export async function analyzeRedirects(targetUrl, baseResult, clientOptions = {}) {
  const findings = [];
  const redirectChain = [...(baseResult?.redirectChain || [])];

  const parsedTarget = new URL(targetUrl);
  const isPlainHttp = parsedTarget.protocol === 'http:';

  // If initial target was plain HTTP, test if it automatically redirects to HTTPS
  let httpToHttpsEnforced = false;
  if (isPlainHttp) {
    if (redirectChain.length > 0) {
      const finalHop = redirectChain[redirectChain.length - 1];
      if (finalHop.to.startsWith('https://')) {
        httpToHttpsEnforced = true;
      }
    }

    if (!httpToHttpsEnforced) {
      findings.push({
        ruleId: 'REDIRECT_NO_HTTPS_ENFORCEMENT',
        title: 'Plaintext HTTP Does Not Automatically Redirect to HTTPS',
        severity: 'Medium',
        confidence: 'High',
        category: 'Transport Security',
        url: targetUrl,
        description: 'The web application is accessible over unencrypted HTTP (port 80) and does not automatically issue a 301/308 redirect to its secure HTTPS version.',
        impact: 'Users who navigate to the site without typing https:// communicate in cleartext, enabling eavesdropping, session hijacking, and ISP content injection.',
        evidence: { initialUrl: targetUrl, finalUrl: baseResult?.url || targetUrl, redirectChainCount: redirectChain.length },
        recommendation: 'Configure your web server or load balancer to issue a 301 Permanent Redirect for all HTTP requests to HTTPS.',
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html']
      });
    }
  }

  // Check chain length
  if (redirectChain.length > 3) {
    findings.push({
      ruleId: 'REDIRECT_EXCESSIVE_CHAIN',
      title: `Excessive Redirect Chain Detected (${redirectChain.length} Hops)`,
      severity: 'Low',
      confidence: 'High',
      category: 'Configuration',
      url: targetUrl,
      description: `The request required ${redirectChain.length} consecutive redirects before reaching the destination page.`,
      impact: 'Severely degrades initial page load performance and increases susceptibility to open redirect vulnerabilities.',
      evidence: { hops: redirectChain.map(h => `${h.statusCode} -> ${h.to}`) },
      recommendation: 'Streamline redirection logic to point directly to the canonical destination in a single 301 hop.',
      cwe: 'CWE-601',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developers.google.com/search/docs/crawling-indexing/301-redirects']
    });
  }

  // Check for suspicious cross-domain redirects
  for (const hop of redirectChain) {
    const inScope = isUrlInScope(hop.to, parsedTarget.origin, true);
    if (!inScope) {
      findings.push({
        ruleId: 'REDIRECT_OUT_OF_SCOPE_EXTERNAL',
        title: 'Initial Request Redirects to External Domain',
        severity: 'Medium',
        confidence: 'High',
        category: 'Scope & Architecture',
        url: targetUrl,
        description: `Target URL "${hop.from}" issued a redirect to an external third-party domain: "${hop.to}".`,
        impact: 'Could indicate an unvalidated open redirect or unintended traffic redirection.',
        evidence: { from: hop.from, to: hop.to, statusCode: hop.statusCode },
        recommendation: 'Ensure external redirects validate destination domains against an allowlist.',
        cwe: 'CWE-601',
        owasp: 'A01:2021 - Broken Access Control',
        references: ['https://cwe.mitre.org/data/definitions/601.html']
      });
      break;
    }
  }

  return {
    chain: redirectChain,
    chainLength: redirectChain.length,
    finalUrl: baseResult?.url || targetUrl,
    httpToHttpsEnforced,
    findings
  };
}
