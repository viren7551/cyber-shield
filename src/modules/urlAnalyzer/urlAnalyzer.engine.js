import url from 'url';
import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';

/**
 * CyberShield URL & Phishing Analyzer Engine
 * High-precision defensive analysis for URL normalization, domain age,
 * redirect chains, suspicious phishing heuristics, homoglyphs, and SSL/TLS checks.
 */

// Top targeted brands frequently impersonated in phishing campaigns
const MONITORED_BRANDS = [
  { name: 'PayPal', slug: 'paypal', legitDomains: ['paypal.com', 'paypal.me'] },
  { name: 'Google', slug: 'google', legitDomains: ['google.com', 'accounts.google.com', 'gmail.com'] },
  { name: 'Microsoft', slug: 'microsoft', legitDomains: ['microsoft.com', 'login.microsoftonline.com', 'live.com', 'office.com'] },
  { name: 'Apple', slug: 'apple', legitDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'] },
  { name: 'Amazon', slug: 'amazon', legitDomains: ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'] },
  { name: 'Netflix', slug: 'netflix', legitDomains: ['netflix.com'] },
  { name: 'Meta / Facebook', slug: 'facebook', legitDomains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'Instagram', slug: 'instagram', legitDomains: ['instagram.com'] },
  { name: 'WhatsApp', slug: 'whatsapp', legitDomains: ['whatsapp.com', 'web.whatsapp.com'] },
  { name: 'Telegram', slug: 'telegram', legitDomains: ['telegram.org', 't.me'] },
  { name: 'Chase Bank', slug: 'chase', legitDomains: ['chase.com'] },
  { name: 'Bank of America', slug: 'bankofamerica', legitDomains: ['bankofamerica.com'] },
  { name: 'Wells Fargo', slug: 'wellsfargo', legitDomains: ['wellsfargo.com'] },
  { name: 'Citibank', slug: 'citi', legitDomains: ['citi.com', 'citibank.com'] },
  { name: 'Binance', slug: 'binance', legitDomains: ['binance.com'] },
  { name: 'Coinbase', slug: 'coinbase', legitDomains: ['coinbase.com'] },
  { name: 'MetaMask', slug: 'metamask', legitDomains: ['metamask.io'] },
  { name: 'Steam', slug: 'steam', legitDomains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'DHL', slug: 'dhl', legitDomains: ['dhl.com'] },
  { name: 'FedEx', slug: 'fedex', legitDomains: ['fedex.com'] },
  { name: 'UPS', slug: 'ups', legitDomains: ['ups.com'] },
  { name: 'USPS', slug: 'usps', legitDomains: ['usps.com'] },
  { name: 'Adobe', slug: 'adobe', legitDomains: ['adobe.com'] },
  { name: 'Dropbox', slug: 'dropbox', legitDomains: ['dropbox.com'] },
  { name: 'Twitter / X', slug: 'twitter', legitDomains: ['twitter.com', 'x.com'] },
  { name: 'LinkedIn', slug: 'linkedin', legitDomains: ['linkedin.com'] },
  { name: 'eBay', slug: 'ebay', legitDomains: ['ebay.com'] }
];

// High-risk TLDs statistically prevalent in disposable/phishing registrations
const HIGH_RISK_TLDS = new Set([
  'top', 'xyz', 'click', 'link', 'zip', 'mov', 'fit', 'gq', 'cf', 'tk', 'ml',
  'men', 'work', 'rest', 'country', 'bar', 'buzz', 'cam', 'center', 'cfd',
  'icu', 'lat', 'live', 'loan', 'monster', 'quest', 'sbs', 'surf', 'tokyo',
  'vip', 'racing', 'party', 'date', 'faith', 'review', 'science', 'stream'
]);

// Suspicious security & credential keywords in subdomains/paths
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'account', 'security', 'secure',
  'update', 'banking', 'wallet', 'confirm', 'confirmation', 'password', 'passwd',
  'billing', 'support', 'recovery', 'recover', '2fa', 'mfa', 'auth', 'authorize',
  'authenticate', 'validation', 'token', 'session', 'credential', 'kyc', 'dispute',
  'suspended', 'unlock', 'reactivate', 'claim', 'refund', 'invoice', 'payment'
];

// Cyrillic and Greek lookalikes commonly exploited in homoglyph / IDN attacks
const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
  '\u0457': 'i', '\u03BF': 'o', '\u03C1': 'p', '\u03BD': 'v', '\u03C9': 'w',
  '\u0454': 'e', '\u045B': 'h', '\u0406': 'I', '\u0410': 'A', '\u0412': 'B',
  '\u0415': 'E', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O',
  '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X'
};

/**
 * Computes Levenshtein edit distance between two strings
 */
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Calculates Shannon entropy of a string (identifies algorithmic randomness / DGA)
 */
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const freqs = {};
  for (let i = 0; i < len; i++) {
    const c = str[i];
    freqs[c] = (freqs[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in freqs) {
    const p = freqs[c] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Splits hostname into subdomains, second-level domain (SLD), and TLD
 */
function splitDomainComponents(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 1) {
    return { subdomains: '', sld: hostname, tld: '', registeredDomain: hostname };
  }

  // Handle multi-part ccTLDs like .co.uk, .com.au, .gov.in, .org.in
  const doubleTlds = ['co.uk', 'com.au', 'com.br', 'co.nz', 'co.za', 'gov.in', 'co.in', 'org.in', 'ac.uk', 'edu.au'];
  const lastTwo = parts.slice(-2).join('.').toLowerCase();

  let tld = '';
  let sld = '';
  let subdomains = '';

  if (doubleTlds.includes(lastTwo) && parts.length >= 3) {
    tld = lastTwo;
    sld = parts[parts.length - 3].toLowerCase();
    subdomains = parts.slice(0, parts.length - 3).join('.').toLowerCase();
  } else {
    tld = parts[parts.length - 1].toLowerCase();
    sld = parts[parts.length - 2].toLowerCase();
    subdomains = parts.slice(0, parts.length - 2).join('.').toLowerCase();
  }

  const registeredDomain = `${sld}.${tld}`;
  return { subdomains, sld, tld, registeredDomain };
}

/**
 * 1. URL Normalization Engine
 * Standardizes URLs, strips default ports, cleans redundant slashes,
 * decodes Punycode/IDN, extracts components and compares raw vs canonical.
 */
export function normalizeUrl(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Valid URL string is required for analysis');
  }

  let trimmed = rawInput.trim();

  // If no scheme specified, assume http/https
  let hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed);
  if (!hasScheme) {
    // If looks like an IP or standard domain, default to https://
    trimmed = 'https://' + trimmed;
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    // Attempt fallback with encodeURI
    try {
      parsed = new URL(encodeURI(trimmed));
    } catch (err) {
      throw new Error(`Invalid URL format: ${err.message}`);
    }
  }

  const protocol = parsed.protocol.toLowerCase();
  let hostname = parsed.hostname.toLowerCase();

  // Punycode & IDN conversion
  const unicodeHostname = url.domainToUnicode(hostname);
  const asciiHostname = url.domainToASCII(unicodeHostname);
  const isPunycode = hostname.startsWith('xn--') || unicodeHostname !== hostname;

  // Check if hostname is an IP address
  const isIpv4 = net.isIPv4(hostname);
  const isIpv6 = net.isIPv6(hostname);
  const isIp = isIpv4 || isIpv6;

  // Remove default ports
  let port = parsed.port;
  if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
    port = '';
  }

  // Normalize pathname: collapse multiple consecutive slashes, resolve . and ..
  let pathname = parsed.pathname || '/';
  pathname = pathname.replace(/\/{2,}/g, '/');

  // Normalize search parameters: sort keys alphabetically for canonical consistency
  const searchParams = new URLSearchParams(parsed.search);
  const sortedParams = new URLSearchParams();
  const keys = Array.from(new Set(searchParams.keys())).sort();
  for (const k of keys) {
    const vals = searchParams.getAll(k);
    vals.forEach((v) => sortedParams.append(k, v));
  }
  const normalizedSearch = sortedParams.toString() ? `?${sortedParams.toString()}` : '';

  // Extract auth/userinfo if present
  const username = parsed.username || '';
  const password = parsed.password || '';
  const hasUserinfo = Boolean(username || password);

  // Construct canonical normalized URL
  let hostPort = hostname;
  if (port) hostPort += `:${port}`;
  let authPart = '';
  if (hasUserinfo) {
    authPart = password ? `${username}:${password}@` : `${username}@`;
  }

  const canonicalUrl = `${protocol}//${authPart}${hostPort}${pathname}${normalizedSearch}${parsed.hash}`;
  const displayUnicodeUrl = `${protocol}//${authPart}${unicodeHostname}${port ? ':' + port : ''}${pathname}${normalizedSearch}${parsed.hash}`;

  const domainParts = isIp ? { subdomains: '', sld: hostname, tld: '', registeredDomain: hostname } : splitDomainComponents(hostname);

  return {
    originalInput: rawInput,
    canonicalUrl,
    displayUnicodeUrl,
    components: {
      protocol: protocol.replace(':', ''),
      hostname,
      unicodeHostname,
      isPunycode,
      isIp,
      isIpv4,
      isIpv6,
      port: port || (protocol === 'https:' ? '443' : '80'),
      isDefaultPort: !port,
      username,
      password,
      hasUserinfo,
      pathname,
      search: normalizedSearch,
      queryParams: Object.fromEntries(sortedParams.entries()),
      hash: parsed.hash,
      subdomains: domainParts.subdomains,
      subdomainList: domainParts.subdomains ? domainParts.subdomains.split('.') : [],
      sld: domainParts.sld,
      tld: domainParts.tld,
      registeredDomain: domainParts.registeredDomain
    },
    metrics: {
      totalLength: canonicalUrl.length,
      hostnameLength: hostname.length,
      pathLength: pathname.length,
      queryParamCount: Array.from(sortedParams.keys()).length,
      entropy: calculateEntropy(hostname)
    }
  };
}

/**
 * 2. Suspicious URL Patterns & Heuristics Analyzer
 * Detects homoglyph deception, brand spoofing, subdomain abuse,
 * suspicious keywords, IP hostnames, userinfo masking, and obfuscation.
 */
export function analyzeSuspiciousPatterns(normResult) {
  const { components, metrics, originalInput } = normResult;
  const findings = [];
  let scoreDeduction = 0; // Cumulative risk indicator (0 to 100)

  // 1. Host is a raw IP Address
  if (components.isIp) {
    findings.push({
      ruleId: 'IP_AS_HOSTNAME',
      severity: 'CRITICAL',
      points: 25,
      title: 'Host is a Raw IP Address',
      description: `The URL directly references an IP address (${components.hostname}) instead of a verified registered domain. Legitimate services virtually always use DNS domains. Phishing, C2 nodes, and malware staging frequently use raw IPs.`,
      detected: components.hostname
    });
    scoreDeduction += 25;
  }

  // 2. Userinfo Deception (Credential Masking)
  if (components.hasUserinfo || originalInput.includes('@')) {
    findings.push({
      ruleId: 'USERINFO_DECEPTION',
      severity: 'CRITICAL',
      points: 30,
      title: 'Deceptive Userinfo (@ Symbol in URL)',
      description: `The URL contains user authentication credentials or an '@' symbol prior to the hostname (${components.username}@${components.hostname}). Attackers frequently use 'https://trusted-bank.com@evil-site.com' to trick users into believing they are visiting the trusted service.`,
      detected: `${components.username}${components.password ? ':***' : ''}@`
    });
    scoreDeduction += 30;
  }

  // 3. Homoglyph / Punycode IDN Spoofing
  let homoglyphsDetected = [];
  if (components.isPunycode) {
    // Check characters against Cyrillic / Greek lookalikes
    for (const char of components.unicodeHostname) {
      if (HOMOGLYPH_MAP[char]) {
        homoglyphsDetected.push({
          spoofedChar: char,
          latinTarget: HOMOGLYPH_MAP[char],
          codePoint: `U+${char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`
        });
      }
    }

    findings.push({
      ruleId: 'HOMOGLYPH_IDN_SPOOF',
      severity: 'CRITICAL',
      points: 35,
      title: 'Internationalized Homoglyph (IDN) Spoofing Detected',
      description: `Punycode domain (${components.hostname}) decodes to '${components.unicodeHostname}'. This uses non-Latin characters (e.g. Cyrillic) visually identical to Latin letters to impersonate legitimate brand domains.`,
      detected: {
        punycode: components.hostname,
        unicode: components.unicodeHostname,
        homoglyphs: homoglyphsDetected
      }
    });
    scoreDeduction += 35;
  }

  // 4. Brand Impersonation & Typosquatting
  let brandSpoofed = null;
  const fullDomainStr = `${components.hostname}`.toLowerCase();
  const fullPathStr = `${components.pathname} ${components.search}`.toLowerCase();

  for (const brand of MONITORED_BRANDS) {
    const brandPattern = brand.slug.toLowerCase();
    const isLegitDomain = brand.legitDomains.some((d) => components.registeredDomain.toLowerCase() === d);

    if (!isLegitDomain) {
      // Check if brand is in subdomains or SLD (e.g., paypal.com.account-verify.xyz or paypa1.com)
      if (components.subdomains.includes(brandPattern)) {
        brandSpoofed = {
          brand: brand.name,
          type: 'SUBDOMAIN_IMPERSONATION',
          details: `Brand '${brand.name}' is embedded in the subdomain ('${components.subdomains}') while registered domain is actually '${components.registeredDomain}'. Classic phishing deception.`
        };
        break;
      } else if (components.sld.includes(brandPattern) && components.registeredDomain !== brand.legitDomains[0]) {
        brandSpoofed = {
          brand: brand.name,
          type: 'SLD_IMPERSONATION',
          details: `Brand '${brand.name}' is contained within the SLD '${components.sld}', but is not the authentic domain.`
        };
        break;
      } else {
        // Levenshtein typosquatting check on SLD
        const dist = levenshteinDistance(components.sld, brandPattern);
        if (dist === 1 || (dist === 2 && components.sld.length >= 6)) {
          brandSpoofed = {
            brand: brand.name,
            type: 'TYPOSQUATTING',
            details: `SLD '${components.sld}' is an edit distance of ${dist} from legitimate brand '${brand.name}'. Likely typosquatting.`
          };
          break;
        }
      }
    }
  }

  if (brandSpoofed) {
    findings.push({
      ruleId: 'BRAND_IMPERSONATION',
      severity: 'CRITICAL',
      points: 30,
      title: `Brand Impersonation Detected (${brandSpoofed.brand})`,
      description: brandSpoofed.details,
      detected: brandSpoofed
    });
    scoreDeduction += 30;
  }

  // 5. Suspicious Security & Login Keywords
  const matchedKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (components.subdomains.includes(kw) || components.pathname.toLowerCase().includes(kw) || components.search.toLowerCase().includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  if (matchedKeywords.length >= 2) {
    const pts = Math.min(20, matchedKeywords.length * 5);
    findings.push({
      ruleId: 'SUSPICIOUS_CREDENTIAL_KEYWORDS',
      severity: matchedKeywords.length >= 3 ? 'HIGH' : 'MEDIUM',
      points: pts,
      title: 'Credential / Security Action Keywords Present',
      description: `URL contains multiple authentication-sensitive terms (${matchedKeywords.slice(0, 5).join(', ')}). Attackers craft phishing paths mimicking corporate login portals.`,
      detected: matchedKeywords
    });
    scoreDeduction += pts;
  }

  // 6. Excessive Subdomains (Domain Stacking)
  if (components.subdomainList.length >= 3) {
    findings.push({
      ruleId: 'EXCESSIVE_SUBDOMAINS',
      severity: 'HIGH',
      points: 15,
      title: `Deep Subdomain Stacking (${components.subdomainList.length} levels)`,
      description: `Excessive subdomains (${components.subdomains}) are frequently used to push the real registered domain off-screen on mobile viewports.`,
      detected: components.subdomainList
    });
    scoreDeduction += 15;
  }

  // 7. Excessive URL Length
  if (metrics.totalLength > 120) {
    findings.push({
      ruleId: 'EXCESSIVE_URL_LENGTH',
      severity: 'MEDIUM',
      points: 10,
      title: `Suspiciously Long URL (${metrics.totalLength} chars)`,
      description: 'URLs exceeding 120 characters are commonly associated with obfuscated tracking, base64 payload delivery, or deep redirectors.',
      detected: `${metrics.totalLength} characters`
    });
    scoreDeduction += 10;
  }

  // 8. High Hostname Entropy (DGA Detection)
  if (metrics.entropy >= 3.75 && !components.isIp) {
    findings.push({
      ruleId: 'HIGH_DOMAIN_ENTROPY',
      severity: 'HIGH',
      points: 15,
      title: `High Domain Name Entropy (${metrics.entropy})`,
      description: 'The domain name exhibits statistical randomness consistent with Domain Generation Algorithms (DGA) used by malware command-and-control and disposable phishing kits.',
      detected: `Entropy: ${metrics.entropy}`
    });
    scoreDeduction += 15;
  }

  // 9. Multiple Hyphens in Domain
  const hyphenCount = (components.hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    findings.push({
      ruleId: 'MULTIPLE_DOMAIN_HYPHENS',
      severity: 'MEDIUM',
      points: 10,
      title: `Abnormal Hyphen Density (${hyphenCount} hyphens)`,
      description: `Domain contains ${hyphenCount} hyphens. Phishers concatenate keywords with hyphens (e.g. 'secure-login-account-verify.com') to create convincing names.`,
      detected: components.hostname
    });
    scoreDeduction += 10;
  }

  // 10. Non-Standard Web Port
  if (components.port && components.port !== '80' && components.port !== '443') {
    findings.push({
      ruleId: 'NON_STANDARD_PORT',
      severity: 'MEDIUM',
      points: 10,
      title: `Non-Standard Web Port (Port ${components.port})`,
      description: `URL directs traffic to port ${components.port}. Legitimate web portals rarely use non-standard ports, which are common in rogue servers, residential proxy tunnels, and phishing kits.`,
      detected: components.port
    });
    scoreDeduction += 10;
  }

  // 11. High Risk TLD
  if (HIGH_RISK_TLDS.has(components.tld)) {
    findings.push({
      ruleId: 'HIGH_RISK_TLD',
      severity: 'HIGH',
      points: 15,
      title: `High-Risk / Frequently Abused TLD (.${components.tld})`,
      description: `The top-level domain .${components.tld} has a statistically elevated abuse rate according to threat intelligence feeds due to ultra-low registration costs and lax verification.`,
      detected: `.${components.tld}`
    });
    scoreDeduction += 15;
  }

  return {
    findings,
    rawRiskScore: Math.min(100, scoreDeduction),
    hasCriticalFindings: findings.some((f) => f.severity === 'CRITICAL'),
    brandSpoofed
  };
}

/**
 * 3. Domain Age & Reputation Intelligence
 * Retrieves WHOIS/RDAP registration dates, calculates domain age,
 * checks DNS MX/SPF/DMARC records for hygiene.
 */
export async function analyzeDomainReputation(hostname) {
  const result = {
    hostname,
    isIp: net.isIP(hostname) !== 0,
    domainAgeDays: null,
    domainAgeFormatted: 'Unknown',
    registrationDate: null,
    expirationDate: null,
    registrar: 'Unknown',
    isNewlyRegistered: false,
    tldRisk: 'LOW',
    dnsHealth: {
      hasA: false,
      hasMx: false,
      hasSpf: false,
      hasDmarc: false
    },
    findings: []
  };

  if (result.isIp) {
    result.domainAgeFormatted = 'N/A (Direct IP address)';
    return result;
  }

  const parts = splitDomainComponents(hostname);
  const regDomain = parts.registeredDomain || hostname;

  // Check TLD Risk
  if (HIGH_RISK_TLDS.has(parts.tld)) {
    result.tldRisk = 'HIGH';
  } else if (['com', 'org', 'net', 'edu', 'gov', 'mil'].includes(parts.tld)) {
    result.tldRisk = 'LOW';
  } else {
    result.tldRisk = 'MEDIUM';
  }

  // Query RDAP (Registration Data Access Protocol) for domain registration age
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const rdapRes = await fetch(`https://rdap.org/domain/${regDomain}`, {
      headers: { 'User-Agent': 'CyberShield-Security-Suite/1.0' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (rdapRes.ok) {
      const data = await rdapRes.json();
      const events = data.events || [];
      const regEvent = events.find((e) => e.eventAction === 'registration');
      const expEvent = events.find((e) => e.eventAction === 'expiration');

      if (regEvent && regEvent.eventDate) {
        result.registrationDate = regEvent.eventDate;
        const regDate = new Date(regEvent.eventDate);
        const now = new Date();
        const diffMs = now - regDate;
        const ageDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
        result.domainAgeDays = ageDays;

        if (ageDays < 30) {
          result.isNewlyRegistered = true;
          result.domainAgeFormatted = `${ageDays} days old (Newly Registered Domain - High Risk)`;
          result.findings.push({
            ruleId: 'NEWLY_REGISTERED_DOMAIN',
            severity: 'CRITICAL',
            title: `Extremely Young Domain (${ageDays} days old)`,
            description: `Domain was created on ${regDate.toLocaleDateString()}. Domains less than 30 days old account for the vast majority of active phishing campaigns.`
          });
        } else if (ageDays < 90) {
          result.domainAgeFormatted = `${ageDays} days old (Young Domain)`;
          result.findings.push({
            ruleId: 'YOUNG_DOMAIN',
            severity: 'MEDIUM',
            title: `Young Domain (${ageDays} days old)`,
            description: `Domain was registered within the past 3 months (${regDate.toLocaleDateString()}). Exercise elevated caution.`
          });
        } else {
          const years = (ageDays / 365.25).toFixed(1);
          result.domainAgeFormatted = `${years} years old (${ageDays} days, created ${regDate.toLocaleDateString()})`;
        }
      }

      if (expEvent && expEvent.eventDate) {
        result.expirationDate = expEvent.eventDate;
      }

      // Extract registrar name from entities
      if (Array.isArray(data.entities)) {
        const registrarEntity = data.entities.find((ent) => (ent.roles || []).includes('registrar'));
        if (registrarEntity && registrarEntity.vcardArray && registrarEntity.vcardArray[1]) {
          const fn = registrarEntity.vcardArray[1].find((v) => v[0] === 'fn');
          if (fn && fn[3]) result.registrar = fn[3];
        }
      }
    }
  } catch {
    // RDAP unavailable or timed out; degrade gracefully
    result.domainAgeFormatted = 'Unable to query WHOIS/RDAP (Query timed out or restricted)';
  }

  // Check DNS records (A, MX, SPF, DMARC) via Node DNS promises
  try {
    const [aRecs, mxRecs, txtRecs, dmarcRecs] = await Promise.all([
      dns.resolve4(regDomain).catch(() => []),
      dns.resolveMx(regDomain).catch(() => []),
      dns.resolveTxt(regDomain).catch(() => []),
      dns.resolveTxt(`_dmarc.${regDomain}`).catch(() => [])
    ]);

    result.dnsHealth.hasA = aRecs.length > 0;
    result.dnsHealth.hasMx = mxRecs.length > 0;

    const flattenedTxt = txtRecs.map((t) => (Array.isArray(t) ? t.join('') : t));
    result.dnsHealth.hasSpf = flattenedTxt.some((t) => t.toLowerCase().startsWith('v=spf1'));
    result.dnsHealth.hasDmarc = dmarcRecs.length > 0;

    // Phishing indicator: Brand-related or login URL with no mail setup
    if (!result.dnsHealth.hasMx && !result.dnsHealth.hasSpf) {
      result.findings.push({
        ruleId: 'NO_MAIL_RECORDS',
        severity: 'LOW',
        title: 'Absence of Email Security Records (No MX / SPF)',
        description: 'Domain has no configured MX or SPF records, characteristic of burner domains used solely for web redirection or credential harvesting.'
      });
    }
  } catch {
    // DNS check failed
  }

  return result;
}

/**
 * 4. Redirect Chain Analyzer
 * Traces HTTP/HTTPS 3xx redirection hops sequentially (up to 8 hops),
 * timing each hop, extracting Location headers, detecting loops, cross-domain jumps,
 * and identifying the final destination URL.
 */
export async function analyzeRedirects(initialUrl, maxHops = 8) {
  const hops = [];
  let currentUrl = initialUrl;
  let hopCount = 0;
  let hasLoop = false;
  const visitedUrls = new Set([initialUrl]);
  const startTime = Date.now();

  while (hopCount < maxHops) {
    hopCount++;
    const hopStart = Date.now();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);

      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 CyberShield-Scanner/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        signal: controller.signal
      });
      clearTimeout(timeout);

      const elapsed = Date.now() - hopStart;
      const status = response.status;
      const location = response.headers.get('location');
      const server = response.headers.get('server') || 'Unknown';

      hops.push({
        hop: hopCount,
        url: currentUrl,
        statusCode: status,
        statusText: response.statusText,
        elapsedMs: elapsed,
        server,
        location: location || null
      });

      // Is it a redirect? (301, 302, 303, 307, 308)
      if ([301, 302, 303, 307, 308].includes(status) && location) {
        // Resolve relative redirects against current URL
        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch {
          nextUrl = location;
        }

        // Loop detection
        if (visitedUrls.has(nextUrl)) {
          hasLoop = true;
          hops.push({
            hop: hopCount + 1,
            url: nextUrl,
            statusCode: 'LOOP_DETECTED',
            statusText: 'Redirect Loop',
            elapsedMs: 0,
            location: null
          });
          break;
        }

        visitedUrls.add(nextUrl);
        currentUrl = nextUrl;
      } else {
        // Terminal hop reached (e.g. 200 OK, 404, 403, 500)
        break;
      }
    } catch (err) {
      hops.push({
        hop: hopCount,
        url: currentUrl,
        statusCode: 'FETCH_ERROR',
        statusText: err.name === 'AbortError' ? 'Connection Timed Out' : err.message,
        elapsedMs: Date.now() - hopStart,
        location: null
      });
      break;
    }
  }

  const finalUrl = hops.length > 0 ? hops[hops.length - 1].url : initialUrl;
  let isCrossDomain = false;
  let originHost = '';
  let finalHost = '';

  try {
    originHost = new URL(initialUrl).hostname;
    finalHost = new URL(finalUrl).hostname;
    isCrossDomain = originHost.toLowerCase() !== finalHost.toLowerCase();
  } catch {}

  const findings = [];
  if (hops.length > 3) {
    findings.push({
      ruleId: 'EXCESSIVE_REDIRECT_HOPS',
      severity: 'MEDIUM',
      title: `Excessive Redirect Chain (${hops.length} Hops)`,
      description: 'Multiple redirect steps are frequently used by cloaking networks to evade automated security scrapers.'
    });
  }

  if (isCrossDomain) {
    findings.push({
      ruleId: 'CROSS_DOMAIN_REDIRECT',
      severity: 'HIGH',
      title: 'Cross-Domain Redirection Detected',
      description: `Initial domain (${originHost}) silently redirects the client to a completely different domain (${finalHost}). Highly common with URL shorteners or compromised redirectors.`
    });
  }

  if (hasLoop) {
    findings.push({
      ruleId: 'REDIRECT_LOOP',
      severity: 'HIGH',
      title: 'Cyclic Redirect Loop Detected',
      description: 'The server redirected in an infinite loop, which can be an anti-analysis evasion or misconfiguration.'
    });
  }

  return {
    initialUrl,
    finalUrl,
    totalHops: hops.length,
    isCrossDomain,
    hasLoop,
    totalTimeMs: Date.now() - startTime,
    hops,
    findings
  };
}

/**
 * 5. HTTPS & SSL/TLS Certificate Inspector
 * Connects directly via Node tls.connect to evaluate cipher suites,
 * certificate validity, expiration, CN/SAN matches, and issuer reputation.
 */
export async function checkHttpsAndCertificate(hostname, port = 443) {
  const result = {
    protocol: port === 443 ? 'https' : 'http',
    hasTls: false,
    issuer: 'Unknown',
    issuerOrg: 'Unknown',
    subject: 'Unknown',
    subjectCn: 'Unknown',
    subjectAltNames: [],
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    isExpired: false,
    hostnameMatchesCert: false,
    tlsVersion: 'Unknown',
    cipherSuite: 'Unknown',
    isFreeOrAutomatedCert: false,
    isSelfSigned: false,
    findings: []
  };

  if (!hostname || net.isIP(hostname)) {
    result.findings.push({
      ruleId: 'IP_NO_CERT_CHECK',
      severity: 'INFO',
      title: 'Direct IP Target',
      description: 'Target is a direct IP address. TLS certificates are primarily designed for domain names.'
    });
    return result;
  }

  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host: hostname,
        port: port || 443,
        servername: hostname, // SNI (Server Name Indication)
        rejectUnauthorized: false, // Inspect certificate details even if invalid or untrusted
        timeout: 4500
      },
      () => {
        if (resolved) return;
        resolved = true;

        try {
          result.hasTls = true;
          const cert = socket.getPeerCertificate(true);
          result.tlsVersion = socket.getProtocol() || 'Unknown';
          const cipher = socket.getCipher();
          result.cipherSuite = cipher ? `${cipher.name} (${cipher.version})` : 'Unknown';

          if (cert && Object.keys(cert).length > 0) {
            result.issuer = cert.issuer ? cert.issuer.CN || 'Unknown' : 'Unknown';
            result.issuerOrg = cert.issuer ? cert.issuer.O || cert.issuer.CN || 'Unknown' : 'Unknown';
            result.subject = cert.subject ? cert.subject.CN || 'Unknown' : 'Unknown';
            result.subjectCn = cert.subject ? cert.subject.CN || 'Unknown' : 'Unknown';

            // Parse SANs
            if (cert.subjectaltname) {
              result.subjectAltNames = cert.subjectaltname
                .split(',')
                .map((s) => s.trim().replace(/^DNS:/i, ''))
                .filter(Boolean);
            }

            // Expiration checks
            if (cert.valid_from) result.validFrom = cert.valid_from;
            if (cert.valid_to) {
              result.validTo = cert.valid_to;
              const expDate = new Date(cert.valid_to);
              const now = new Date();
              const diffMs = expDate - now;
              const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
              result.daysRemaining = daysLeft;
              result.isExpired = daysLeft < 0;

              if (result.isExpired) {
                result.findings.push({
                  ruleId: 'EXPIRED_CERTIFICATE',
                  severity: 'CRITICAL',
                  title: 'SSL/TLS Certificate Has Expired',
                  description: `Certificate expired ${Math.abs(daysLeft)} days ago on ${expDate.toLocaleDateString()}. Traffic is susceptible to interception and browser security warnings.`
                });
              } else if (daysLeft < 14) {
                result.findings.push({
                  ruleId: 'EXPIRING_SOON',
                  severity: 'MEDIUM',
                  title: `Certificate Expiring Soon (${daysLeft} days left)`,
                  description: `Certificate will expire on ${expDate.toLocaleDateString()}.`
                });
              }
            }

            // Hostname match verification
            const allDomains = [result.subjectCn, ...result.subjectAltNames].filter(Boolean);
            result.hostnameMatchesCert = allDomains.some((d) => {
              const cleaned = d.toLowerCase();
              const target = hostname.toLowerCase();
              if (cleaned === target) return true;
              if (cleaned.startsWith('*.')) {
                const wildcardDomain = cleaned.slice(2);
                return target.endsWith(wildcardDomain);
              }
              return false;
            });

            if (!result.hostnameMatchesCert && allDomains.length > 0) {
              result.findings.push({
                ruleId: 'CERT_NAME_MISMATCH',
                severity: 'CRITICAL',
                title: 'Certificate Hostname Mismatch (Potential MITM or Spoof)',
                description: `Certificate was issued for '${result.subjectCn}' or [${result.subjectAltNames.slice(0, 3).join(', ')}], which does not match requested host '${hostname}'.`
              });
            }

            // Check if self-signed
            if (cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O) {
              result.isSelfSigned = true;
              result.findings.push({
                ruleId: 'SELF_SIGNED_CERTIFICATE',
                severity: 'HIGH',
                title: 'Self-Signed Certificate Detected',
                description: 'Certificate was not signed by a trusted public Certificate Authority (CA), commonly found on malicious staging hosts or development servers.'
              });
            }

            // Check free automated certs (e.g. Let\'s Encrypt, cPanel, Cloudflare)
            const issuerLower = (result.issuerOrg || result.issuer || '').toLowerCase();
            if (issuerLower.includes("let's encrypt") || issuerLower.includes('cpanel') || issuerLower.includes('zerossl')) {
              result.isFreeOrAutomatedCert = true;
            }
          }
        } catch (e) {
          result.findings.push({
            ruleId: 'CERT_PARSE_ERROR',
            severity: 'LOW',
            title: 'Certificate Details Incomplete',
            description: e.message
          });
        } finally {
          socket.destroy();
          resolve(result);
        }
      }
    );

    socket.on('error', (err) => {
      if (resolved) return;
      resolved = true;
      result.findings.push({
        ruleId: 'TLS_CONNECTION_FAILED',
        severity: 'MEDIUM',
        title: 'TLS Connection Failed',
        description: `Could not establish secure handshake on port ${port}: ${err.message}`
      });
      socket.destroy();
      resolve(result);
    });

    socket.on('timeout', () => {
      if (resolved) return;
      resolved = true;
      result.findings.push({
        ruleId: 'TLS_TIMEOUT',
        severity: 'LOW',
        title: 'TLS Handshake Timed Out',
        description: `Connection timed out after 4.5s attempting TLS handshake with ${hostname}:${port}.`
      });
      socket.destroy();
      resolve(result);
    });
  });
}

/**
 * 6. Composite Risk Scoring & Assessment Engine
 * Combines Normalization, Suspicious Patterns, Domain Age, Redirects,
 * and SSL/TLS findings into an overall risk score (0 - 100) and authoritative verdict.
 */
export function calculatePhishingVerdict(patterns, domainIntel, redirects, tlsCert, norm) {
  let score = patterns.rawRiskScore || 0;
  const allFindings = [...patterns.findings];

  // Integrate domain age findings
  if (domainIntel && domainIntel.findings) {
    allFindings.push(...domainIntel.findings);
    if (domainIntel.isNewlyRegistered) score += 30;
    else if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays < 90) score += 15;
  }

  // Integrate redirect findings
  if (redirects && redirects.findings) {
    allFindings.push(...redirects.findings);
    if (redirects.isCrossDomain) score += 20;
    if (redirects.hasLoop) score += 15;
  }

  // Integrate TLS findings
  if (tlsCert && tlsCert.findings) {
    allFindings.push(...tlsCert.findings);
    if (tlsCert.isExpired) score += 25;
    if (!tlsCert.hostnameMatchesCert && tlsCert.hasTls) score += 30;
    if (tlsCert.isSelfSigned) score += 20;
  }

  // Correlated threat: If brand is spoofed AND domain is using a free cert or young domain
  if (patterns.brandSpoofed && (domainIntel.isNewlyRegistered || tlsCert.isFreeOrAutomatedCert)) {
    score += 20;
    allFindings.push({
      ruleId: 'CORRELATED_BRAND_SPOOF_LOW_BARRIER',
      severity: 'CRITICAL',
      title: 'High-Probability Phishing: Brand Spoofing with Disposable Infrastructure',
      description: `Domain targets '${patterns.brandSpoofed.brand}' while using disposable/automated infrastructure (${tlsCert.isFreeOrAutomatedCert ? 'Automated Free TLS' : ''}${domainIntel.isNewlyRegistered ? ' + Young Domain' : ''}). Classic spear-phishing / credential harvesting signature.`
    });
  }

  // Cap score at 100
  const finalScore = Math.min(100, Math.max(0, score));

  // Determine Verdict
  let verdict = 'SAFE';
  let badgeClass = 'verdict-safe';
  let summary = 'No high-risk phishing indicators detected. The URL appears structurally normal and legitimate.';

  if (finalScore >= 65 || patterns.hasCriticalFindings) {
    verdict = 'MALICIOUS / PHISHING';
    badgeClass = 'verdict-malicious';
    summary = 'CRITICAL PHISHING RISK: Strong evidence of brand deception, credential theft, homoglyphs, or deceptive infrastructure.';
  } else if (finalScore >= 30) {
    verdict = 'SUSPICIOUS';
    badgeClass = 'verdict-suspicious';
    summary = 'ELEVATED RISK: Several suspicious characteristics detected (e.g. cross-domain hops, keyword stacking, or young domain). Treat with caution.';
  }

  // Sort findings by severity priority
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  allFindings.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));

  return {
    riskScore: finalScore,
    verdict,
    badgeClass,
    summary,
    totalFindings: allFindings.length,
    findings: allFindings
  };
}

/**
 * 7. Master Analyzer: Executes full end-to-end inspection pipeline
 */
export async function runFullAnalysis(rawUrl) {
  // 1. Normalize
  const normalized = normalizeUrl(rawUrl);

  // 2. Patterns Heuristics
  const patterns = analyzeSuspiciousPatterns(normalized);

  const hostname = normalized.components.hostname;
  const isIp = normalized.components.isIp;
  const port = parseInt(normalized.components.port, 10) || 443;

  // 3, 4, 5. Run async checks concurrently for maximum performance
  const [domainIntel, redirects, tlsCert] = await Promise.all([
    analyzeDomainReputation(hostname),
    analyzeRedirects(normalized.canonicalUrl, 6),
    checkHttpsAndCertificate(hostname, port)
  ]);

  // 6. Aggregate Composite Verdict
  const assessment = calculatePhishingVerdict(patterns, domainIntel, redirects, tlsCert, normalized);

  return {
    timestamp: new Date().toISOString(),
    url: rawUrl,
    normalized,
    patterns,
    domainIntel,
    redirects,
    tlsCert,
    assessment
  };
}
