import {
  normalizeUrl,
  analyzeSuspiciousPatterns,
  analyzeDomainReputation,
  analyzeRedirects,
  checkHttpsAndCertificate,
  calculatePhishingVerdict,
  runFullAnalysis
} from './urlAnalyzer.engine.js';

/**
 * Pre-configured test presets demonstrating real-world phishing techniques
 */
const DEMO_PRESETS = [
  {
    id: 'homoglyph-paypal',
    name: 'Homoglyph / Punycode IDN Deception',
    category: 'Cyrillic Spoofing',
    url: 'http://xn--pypal-4ve.com/signin/webapps/mpp/home',
    description: 'Impersonates PayPal using a Cyrillic "а" (U+0430) rendered via Punycode.'
  },
  {
    id: 'subdomain-stacking',
    name: 'Subdomain Deception & Brand Stacking',
    category: 'Subdomain Abuse',
    url: 'https://login.microsoft.com.account-verify-security.xyz/oauth2/authorize?client_id=sec',
    description: 'Buries the real domain (.xyz) behind stacked Microsoft login subdomains.'
  },
  {
    id: 'ip-credentials-auth',
    name: 'Direct IP Host with Userinfo & Port',
    category: 'IP & Auth Deception',
    url: 'http://admin:pass@194.26.29.112:8080/secure/wallet/auth.php?token=9284204',
    description: 'Uses raw IP host, user credentials in URL, non-standard port and credential path.'
  },
  {
    id: 'young-domain-login',
    name: 'Typosquatting & Password Harvest',
    category: 'Typosquatting',
    url: 'https://paypa1-security-verification.live/account/confirm-password.php',
    description: 'Typosquatted domain on high-risk TLD with aggressive login keyword targeting.'
  },
  {
    id: 'clean-github',
    name: 'Legitimate Domain (Baseline Safe)',
    category: 'Clean / Safe',
    url: 'https://github.com/security',
    description: 'Clean HTTPS URL on a registered, aged domain with valid public CA certificate.'
  }
];

/**
 * POST /api/url-analyzer/analyze
 * Comprehensive full-spectrum URL and phishing analysis
 */
export async function analyzeUrl(req, res) {
  try {
    const { url: targetUrl } = req.body;
    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid "url" string in the request body.'
      });
    }

    const report = await runFullAnalysis(targetUrl);
    return res.status(200).json({
      success: true,
      data: report
    });
  } catch (error) {
    console.error('[URL Analyzer Error]:', error.message);
    return res.status(400).json({
      success: false,
      error: error.message || 'Failed to analyze URL.'
    });
  }
}

/**
 * POST /api/url-analyzer/normalize
 * Immediate URL canonicalization, component parsing, and normalization
 */
export async function normalizeUrlOnly(req, res) {
  try {
    const { url: targetUrl } = req.body;
    if (!targetUrl) {
      return res.status(400).json({ success: false, error: 'URL is required.' });
    }

    const normalized = normalizeUrl(targetUrl);
    const patterns = analyzeSuspiciousPatterns(normalized);

    return res.status(200).json({
      success: true,
      data: {
        normalized,
        quickPatterns: patterns
      }
    });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
}

/**
 * POST /api/url-analyzer/redirects
 * Follow redirect chain and track intermediate hops
 */
export async function traceRedirectsOnly(req, res) {
  try {
    const { url: targetUrl, maxHops } = req.body;
    if (!targetUrl) {
      return res.status(400).json({ success: false, error: 'URL is required.' });
    }

    const norm = normalizeUrl(targetUrl);
    const redirects = await analyzeRedirects(norm.canonicalUrl, maxHops || 8);

    return res.status(200).json({
      success: true,
      data: redirects
    });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
}

/**
 * POST /api/url-analyzer/cert
 * Inspect SSL/TLS certificate and TLS cipher details
 */
export async function inspectCertOnly(req, res) {
  try {
    const { url: targetUrl, host, port } = req.body;
    let targetHost = host;
    let targetPort = port ? parseInt(port, 10) : 443;

    if (targetUrl) {
      const norm = normalizeUrl(targetUrl);
      targetHost = norm.components.hostname;
      targetPort = parseInt(norm.components.port, 10) || 443;
    }

    if (!targetHost) {
      return res.status(400).json({ success: false, error: 'Host or URL is required.' });
    }

    const certData = await checkHttpsAndCertificate(targetHost, targetPort);
    return res.status(200).json({
      success: true,
      data: certData
    });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
}

/**
 * POST /api/url-analyzer/batch
 * Analyze a batch of URLs (up to 10)
 */
export async function batchAnalyze(req, res) {
  try {
    const { urls } = req.body;
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ success: false, error: 'Array of "urls" is required.' });
    }

    const limit = urls.slice(0, 10);
    const results = await Promise.all(
      limit.map(async (u) => {
        try {
          const report = await runFullAnalysis(u);
          return {
            url: u,
            success: true,
            riskScore: report.assessment.riskScore,
            verdict: report.assessment.verdict,
            badgeClass: report.assessment.badgeClass,
            summary: report.assessment.summary,
            criticalCount: report.assessment.findings.filter((f) => f.severity === 'CRITICAL').length
          };
        } catch (err) {
          return {
            url: u,
            success: false,
            error: err.message
          };
        }
      })
    );

    return res.status(200).json({
      success: true,
      data: {
        total: results.length,
        items: results
      }
    });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
}

/**
 * GET /api/url-analyzer/presets
 * Return list of interactive testing presets
 */
export async function getPresets(req, res) {
  return res.status(200).json({
    success: true,
    data: DEMO_PRESETS
  });
}
