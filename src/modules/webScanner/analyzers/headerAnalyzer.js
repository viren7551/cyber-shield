/**
 * CyberShield Web Security Scanner - Security Header Analyzer
 * Evaluates HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
 * Referrer-Policy, Permissions-Policy, COOP, CORP, COEP, Cache-Control, Information Leaks).
 */

/**
 * Run comprehensive security header checks against an HTTP response
 * @param {object} response - Output from safeRequest
 * @param {string} targetUrl - URL tested
 */
export function analyzeHeaders(response, targetUrl) {
  const findings = [];
  const headers = response?.headers || {};
  const isHttps = targetUrl.startsWith('https://');
  const urlObj = new URL(targetUrl);
  const pathname = urlObj.pathname.toLowerCase();

  // Summary status dictionary for UI header matrix
  const headerAudit = {
    csp: { name: 'Content-Security-Policy', status: 'missing', value: null },
    hsts: { name: 'Strict-Transport-Security', status: 'missing', value: null },
    xContentType: { name: 'X-Content-Type-Options', status: 'missing', value: null },
    xFrame: { name: 'X-Frame-Options', status: 'missing', value: null },
    referrer: { name: 'Referrer-Policy', status: 'missing', value: null },
    permissions: { name: 'Permissions-Policy', status: 'missing', value: null },
    coop: { name: 'Cross-Origin-Opener-Policy', status: 'missing', value: null },
    corp: { name: 'Cross-Origin-Resource-Policy', status: 'missing', value: null },
    coep: { name: 'Cross-Origin-Embedder-Policy', status: 'missing', value: null },
    cacheControl: { name: 'Cache-Control', status: 'present', value: headers['cache-control'] || null },
    serverDisclosure: { name: 'Server', status: 'secure', value: headers['server'] || null }
  };

  // 1. Content-Security-Policy
  const csp = headers['content-security-policy'];
  if (!csp) {
    headerAudit.csp.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_CSP',
      title: 'Missing Content-Security-Policy Header',
      severity: 'Medium',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'The Content-Security-Policy (CSP) HTTP header is not implemented. CSP prevents Cross-Site Scripting (XSS), clickjacking, and code injection attacks by restricting the sources from which resources can be loaded.',
      impact: 'Without CSP, the browser cannot restrict unauthorized script execution, increasing exposure to persistent and reflected XSS attacks.',
      evidence: { header: 'Content-Security-Policy', observed: 'Header absent' },
      recommendation: "Implement a robust Content-Security-Policy header. E.g.: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
      cwe: 'CWE-1021',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
      ]
    });
  } else {
    headerAudit.csp.value = csp;
    headerAudit.csp.status = 'present';

    // Inspect CSP directives for dangerous patterns
    const cspDirectives = csp.toLowerCase();

    if (cspDirectives.includes("'unsafe-inline'")) {
      headerAudit.csp.status = 'warning';
      findings.push({
        ruleId: 'SEC_HEADER_WEAK_CSP_UNSAFE_INLINE',
        title: "Content-Security-Policy Contains 'unsafe-inline'",
        severity: 'Medium',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: "The Content-Security-Policy header permits 'unsafe-inline' script or style execution, largely negating protection against Cross-Site Scripting (XSS).",
        impact: 'Attackers who inject inline <script> tags or inline event handlers (onerror, onload) can execute unauthorized JavaScript.',
        evidence: { header: 'Content-Security-Policy', observed: csp },
        recommendation: "Remove 'unsafe-inline' from script-src. Use cryptographic nonces (nonce-...) or SHA-256 hashes for authorized inline scripts.",
        cwe: 'CWE-79',
        owasp: 'A03:2021 - Injection',
        references: ['https://content-security-policy.com/unsafe-inline/']
      });
    }

    if (cspDirectives.includes("'unsafe-eval'")) {
      headerAudit.csp.status = 'warning';
      findings.push({
        ruleId: 'SEC_HEADER_WEAK_CSP_UNSAFE_EVAL',
        title: "Content-Security-Policy Contains 'unsafe-eval'",
        severity: 'Low',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: "The Content-Security-Policy permits 'unsafe-eval', allowing strings to be converted into executable code via eval(), Function(), setTimeout(), and setInterval().",
        impact: 'Increases vulnerability to DOM-based XSS when user input is parsed by dynamic script evaluators.',
        evidence: { header: 'Content-Security-Policy', observed: csp },
        recommendation: "Refactor code to eliminate eval() and Function constructor usage, then remove 'unsafe-eval' from CSP.",
        cwe: 'CWE-95',
        owasp: 'A03:2021 - Injection',
        references: ['https://content-security-policy.com/unsafe-eval/']
      });
    }

    if (/(?:script-src|default-src)[^;]*\*/.test(cspDirectives)) {
      headerAudit.csp.status = 'warning';
      findings.push({
        ruleId: 'SEC_HEADER_CSP_WILDCARD_SOURCE',
        title: 'Content-Security-Policy Allows Wildcard Source (*)',
        severity: 'Medium',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: 'The Content-Security-Policy includes a wildcard (*) in script-src or default-src, permitting scripts to be downloaded and executed from any internet origin.',
        impact: 'Attackers can host malicious payloads on arbitrary third-party servers and load them into the application context.',
        evidence: { header: 'Content-Security-Policy', observed: csp },
        recommendation: 'Replace wildcard origins with specific trusted domain origins or self.',
        cwe: 'CWE-16',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://w3c.github.io/webappsec-csp/']
      });
    }
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  if (isHttps) {
    if (!hsts) {
      headerAudit.hsts.status = 'missing';
      findings.push({
        ruleId: 'SEC_HEADER_MISSING_HSTS',
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        severity: 'Medium',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: 'The HTTP Strict-Transport-Security (HSTS) header informs user agents that all communications must occur exclusively over encrypted HTTPS.',
        impact: 'Users are exposed to SSL-stripping and man-in-the-middle (MITM) downgrade attacks on initial visits or untrusted networks.',
        evidence: { header: 'Strict-Transport-Security', observed: 'Header absent on HTTPS endpoint' },
        recommendation: 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        cwe: 'CWE-523',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
      });
    } else {
      headerAudit.hsts.value = hsts;
      headerAudit.hsts.status = 'present';

      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAgeSeconds = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

      if (maxAgeSeconds < 10368000) { // Less than ~120 days
        headerAudit.hsts.status = 'warning';
        findings.push({
          ruleId: 'SEC_HEADER_HSTS_SHORT_MAX_AGE',
          title: 'HSTS max-age Duration Too Short',
          severity: 'Low',
          confidence: 'High',
          category: 'Security Headers',
          url: targetUrl,
          description: `The HSTS max-age directive is set to ${maxAgeSeconds} seconds. Industry standards and OWASP recommend at least 1 year (31,536,000 seconds).`,
          impact: 'Short HSTS lifetimes expire quickly, leaving client sessions vulnerable to downgrade attacks if visits are infrequent.',
          evidence: { header: 'Strict-Transport-Security', observed: hsts },
          recommendation: 'Increase HSTS max-age to 31536000 (1 year).',
          cwe: 'CWE-523',
          owasp: 'A05:2021 - Security Misconfiguration',
          references: ['https://hstspreload.org/']
        });
      }

      if (!hsts.toLowerCase().includes('includesubdomains')) {
        findings.push({
          ruleId: 'SEC_HEADER_HSTS_NO_SUBDOMAINS',
          title: 'HSTS Missing includeSubDomains Directive',
          severity: 'Low',
          confidence: 'High',
          category: 'Security Headers',
          url: targetUrl,
          description: 'The Strict-Transport-Security header does not include the includeSubDomains flag.',
          impact: 'Subdomains of this domain may be accessed over unencrypted HTTP, risking cookie eavesdropping or DNS spoofing.',
          evidence: { header: 'Strict-Transport-Security', observed: hsts },
          recommendation: 'Append "; includeSubDomains" to the Strict-Transport-Security header.',
          cwe: 'CWE-523',
          owasp: 'A05:2021 - Security Misconfiguration',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html']
        });
      }
    }
  }

  // 3. X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    headerAudit.xContentType.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_X_CONTENT_TYPE_OPTIONS',
      title: 'Missing or Ineffective X-Content-Type-Options Header',
      severity: 'Low',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'The X-Content-Type-Options response header prevents browsers from MIME-sniffing a response away from the declared Content-Type.',
      impact: 'Without nosniff, browsers may interpret untrusted user-uploaded images or text files as executable JavaScript or CSS.',
      evidence: { header: 'X-Content-Type-Options', observed: xcto || 'Header absent' },
      recommendation: 'Add the header: X-Content-Type-Options: nosniff',
      cwe: 'CWE-16',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
    });
  } else {
    headerAudit.xContentType.value = xcto;
    headerAudit.xContentType.status = 'present';
  }

  // 4. X-Frame-Options (Clickjacking defense)
  const xfo = headers['x-frame-options'];
  const hasCspFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');

  if (!xfo && !hasCspFrameAncestors) {
    headerAudit.xFrame.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_X_FRAME_OPTIONS',
      title: 'Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)',
      severity: 'Medium',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'Neither X-Frame-Options nor CSP frame-ancestors was detected. This allows the web page to be rendered inside an <iframe>, <frame>, or <object> on an external malicious website.',
      impact: 'Enables clickjacking attacks where transparent frames trick users into clicking buttons or triggering transactions unknowingly.',
      evidence: { header: 'X-Frame-Options', observed: 'Header absent' },
      recommendation: "Configure X-Frame-Options: DENY (or SAMEORIGIN), and add CSP frame-ancestors 'self';",
      cwe: 'CWE-1021',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
    });
  } else if (xfo) {
    headerAudit.xFrame.value = xfo;
    const xfoVal = xfo.toUpperCase();
    if (xfoVal !== 'DENY' && xfoVal !== 'SAMEORIGIN') {
      headerAudit.xFrame.status = 'warning';
      findings.push({
        ruleId: 'SEC_HEADER_WEAK_X_FRAME_OPTIONS',
        title: 'Deprecated or Invalid X-Frame-Options Value',
        severity: 'Low',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: `X-Frame-Options is set to "${xfo}". Values like ALLOW-FROM are obsolete and unsupported by modern browsers.`,
        impact: 'Browser will ignore unrecognized framing directives, leaving the page vulnerable to framing.',
        evidence: { header: 'X-Frame-Options', observed: xfo },
        recommendation: 'Use X-Frame-Options: DENY or SAMEORIGIN.',
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
      });
    } else {
      headerAudit.xFrame.status = 'present';
    }
  }

  // 5. Referrer-Policy
  const referrerPolicy = headers['referrer-policy'];
  if (!referrerPolicy) {
    headerAudit.referrer.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_REFERRER_POLICY',
      title: 'Missing Referrer-Policy Header',
      severity: 'Low',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'The Referrer-Policy header governs how much referrer information (including URLs and query string tokens) is sent with requests made from your site.',
      impact: 'Sensitive URL parameters (tokens, session IDs, internal paths) may leak to external third-party sites via the Referer header.',
      evidence: { header: 'Referrer-Policy', observed: 'Header absent' },
      recommendation: 'Configure Referrer-Policy: strict-origin-when-cross-origin',
      cwe: 'CWE-116',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
    });
  } else {
    headerAudit.referrer.value = referrerPolicy;
    if (referrerPolicy.toLowerCase().includes('unsafe-url')) {
      headerAudit.referrer.status = 'warning';
      findings.push({
        ruleId: 'SEC_HEADER_UNSAFE_REFERRER_POLICY',
        title: 'Insecure Referrer-Policy Configuration (unsafe-url)',
        severity: 'Low',
        confidence: 'High',
        category: 'Security Headers',
        url: targetUrl,
        description: 'Referrer-Policy is set to unsafe-url, leaking full request paths and queries across all origins and protocols.',
        impact: 'Sensitive session tokens, reset keys, or account IDs in URLs are leaked to third-party servers.',
        evidence: { header: 'Referrer-Policy', observed: referrerPolicy },
        recommendation: 'Change Referrer-Policy to strict-origin-when-cross-origin.',
        cwe: 'CWE-116',
        owasp: 'A05:2021 - Security Misconfiguration',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
      });
    } else {
      headerAudit.referrer.status = 'present';
    }
  }

  // 6. Permissions-Policy
  const permissionsPolicy = headers['permissions-policy'];
  if (!permissionsPolicy) {
    headerAudit.permissions.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_PERMISSIONS_POLICY',
      title: 'Missing Permissions-Policy Header',
      severity: 'Informational',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'The Permissions-Policy header allows sites to restrict access to sensitive browser features (e.g., camera, microphone, geolocation, usb, payment).',
      impact: 'Embedded frames or third-party scripts could request or invoke sensitive hardware features.',
      evidence: { header: 'Permissions-Policy', observed: 'Header absent' },
      recommendation: 'Implement Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
      cwe: 'CWE-16',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
    });
  } else {
    headerAudit.permissions.value = permissionsPolicy;
    headerAudit.permissions.status = 'present';
  }

  // 7. Cross-Origin-Opener-Policy (COOP)
  const coop = headers['cross-origin-opener-policy'];
  if (!coop) {
    headerAudit.coop.status = 'missing';
    findings.push({
      ruleId: 'SEC_HEADER_MISSING_COOP',
      title: 'Missing Cross-Origin-Opener-Policy (COOP) Header',
      severity: 'Informational',
      confidence: 'High',
      category: 'Security Headers',
      url: targetUrl,
      description: 'Cross-Origin-Opener-Policy (COOP) isolates your top-level browsing context, preventing cross-origin documents from accessing the window object.',
      impact: 'Leaves site open to cross-origin attacks like Spectre or window.opener DOM tampering.',
      evidence: { header: 'Cross-Origin-Opener-Policy', observed: 'Header absent' },
      recommendation: 'Set Cross-Origin-Opener-Policy: same-origin',
      cwe: 'CWE-16',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy']
    });
  } else {
    headerAudit.coop.value = coop;
    headerAudit.coop.status = 'present';
  }

  // 8. Cross-Origin-Resource-Policy (CORP)
  const corp = headers['cross-origin-resource-policy'];
  if (corp) {
    headerAudit.corp.value = corp;
    headerAudit.corp.status = 'present';
  }

  // 9. Cross-Origin-Embedder-Policy (COEP)
  const coep = headers['cross-origin-embedder-policy'];
  if (coep) {
    headerAudit.coep.value = coep;
    headerAudit.coep.status = 'present';
  }

  // 10. Cache-Control on sensitive paths
  const isSensitivePath = /login|signin|account|auth|admin|portal|profile|dashboard|checkout|payment/i.test(pathname);
  const cacheControl = headers['cache-control'] || '';
  if (isSensitivePath) {
    const isNoStore = cacheControl.toLowerCase().includes('no-store');
    if (!isNoStore) {
      findings.push({
        ruleId: 'SEC_CACHE_SENSITIVE_DATA_EXPOSURE',
        title: 'Sensitive Endpoint Missing Cache-Control: no-store',
        severity: 'Low',
        confidence: 'High',
        category: 'Information Disclosure',
        url: targetUrl,
        description: `The URL path "${pathname}" appears to be a sensitive or authenticated page, but does not specify "Cache-Control: no-store".`,
        impact: 'Browser caches and intermediate proxies may store sensitive personal data or session state, which can be retrieved on shared workstations.',
        evidence: { header: 'Cache-Control', observed: cacheControl || 'Header absent' },
        recommendation: 'Set Cache-Control: no-store, no-cache, must-revalidate on all sensitive pages.',
        cwe: 'CWE-525',
        owasp: 'A04:2021 - Insecure Design',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html']
      });
    }
  }

  // 11. Server & Framework Version Disclosure
  const serverHeader = headers['server'];
  const xPoweredBy = headers['x-powered-by'];
  const xAspNet = headers['x-aspnet-version'] || headers['x-aspnetmvc-version'];

  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    headerAudit.serverDisclosure.status = 'warning';
    findings.push({
      ruleId: 'INFO_DISCLOSURE_SERVER_VERSION',
      title: 'Server Header Discloses Software Version',
      severity: 'Low',
      confidence: 'High',
      category: 'Information Disclosure',
      url: targetUrl,
      description: `The HTTP Server header discloses detailed server version information: "${serverHeader}".`,
      impact: 'Assists attackers during reconnaissance to identify known CVEs and target specific unpatched vulnerabilities in that exact version.',
      evidence: { header: 'Server', observed: serverHeader },
      recommendation: 'Configure your web server (e.g. server_tokens off in Nginx, ServerSignature Off in Apache) to suppress banner versions.',
      cwe: 'CWE-200',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html']
    });
  }

  if (xPoweredBy) {
    findings.push({
      ruleId: 'INFO_DISCLOSURE_X_POWERED_BY',
      title: 'X-Powered-By Technology Disclosure',
      severity: 'Low',
      confidence: 'High',
      category: 'Information Disclosure',
      url: targetUrl,
      description: `The server leaks backend framework identity via the X-Powered-By header: "${xPoweredBy}".`,
      impact: 'Reveals backend tech stack to attackers, facilitating targeted exploit research.',
      evidence: { header: 'X-Powered-By', observed: xPoweredBy },
      recommendation: 'Disable X-Powered-By headers (e.g. app.disable("x-powered-by") in Express, expose_php = Off in php.ini).',
      cwe: 'CWE-200',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework']
    });
  }

  if (xAspNet) {
    findings.push({
      ruleId: 'INFO_DISCLOSURE_ASPNET_VERSION',
      title: 'ASP.NET Version Disclosure Header',
      severity: 'Low',
      confidence: 'High',
      category: 'Information Disclosure',
      url: targetUrl,
      description: `The application leaks ASP.NET framework version: "${xAspNet}".`,
      impact: 'Facilitates reconnaissance against .NET framework vulnerabilities.',
      evidence: { header: 'X-AspNet-Version', observed: xAspNet },
      recommendation: 'Remove enableVersionHeader in web.config.',
      cwe: 'CWE-200',
      owasp: 'A05:2021 - Security Misconfiguration',
      references: ['https://cwe.mitre.org/data/definitions/200.html']
    });
  }

  return { findings, headerAudit };
}
