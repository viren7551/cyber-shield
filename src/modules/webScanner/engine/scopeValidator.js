import url from 'url';
import dns from 'dns/promises';
import net from 'net';

/**
 * CyberShield Web Security Scanner - Scope & Target Validator
 * Protects against SSRF, DNS rebinding, private network probing,
 * and enforces strict target crawl scope boundaries.
 */

// Private IPv4 ranges (RFC 1918 + loopback + link-local + cloud metadata)
const PRIVATE_IPV4_RANGES = [
  { start: '10.0.0.0', end: '10.255.255.255' },         // 10.0.0.0/8 (RFC 1918)
  { start: '172.16.0.0', end: '172.31.255.255' },       // 172.16.0.0/12 (RFC 1918)
  { start: '192.168.0.0', end: '192.168.255.255' },     // 192.168.0.0/16 (RFC 1918)
  { start: '127.0.0.0', end: '127.255.255.255' },       // 127.0.0.0/8 (Loopback)
  { start: '169.254.0.0', end: '169.254.255.255' },     // 169.254.0.0/16 (Link-local / Cloud metadata)
  { start: '100.64.0.0', end: '100.127.255.255' },      // 100.64.0.0/10 (Carrier-grade NAT)
  { start: '0.0.0.0', end: '0.255.255.255' },           // 0.0.0.0/8 (Current network)
  { start: '224.0.0.0', end: '239.255.255.255' },       // 224.0.0.0/4 (Multicast)
  { start: '240.0.0.0', end: '255.255.255.255' }        // 240.0.0.0/4 (Reserved / Broadcast)
];

// Dangerous cloud metadata endpoints and hostnames
const DANGEROUS_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  'metadata.google.internal',
  '169.254.169.254',
  'instance-data',
  'metadata.aws'
]);

/**
 * Convert IPv4 dotted string to 32-bit unsigned integer
 */
function ipToLong(ip) {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

/**
 * Test whether an IPv4 address is in private/internal address space
 */
export function isPrivateIPv4(ip) {
  const ipNum = ipToLong(ip);
  if (ipNum === null) return true; // Malformed IPs blocked by default
  for (const range of PRIVATE_IPV4_RANGES) {
    const startNum = ipToLong(range.start);
    const endNum = ipToLong(range.end);
    if (ipNum >= startNum && ipNum <= endNum) {
      return true;
    }
  }
  return false;
}

/**
 * Test whether an IPv6 address is loopback, unique local, or link-local
 */
export function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase().trim();
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  if (normalized.startsWith('fe80:') || normalized.startsWith('fc00:') || normalized.startsWith('fd00:')) return true;
  if (normalized === '::' || normalized.startsWith('::ffff:127.')) return true;
  return false;
}

/**
 * Comprehensive Target URL and SSRF validation
 * @param {string} rawUrl - User target input
 * @param {boolean} allowLocalLab - Explicit user override for local labs / staging
 */
export async function validateTargetUrl(rawUrl, allowLocalLab = false) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'Target URL is required.' };
  }

  let trimmed = rawUrl.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    trimmed = 'https://' + trimmed;
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Target URL is not a valid RFC-compliant URL.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS protocols are supported for security scanning.' };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname.length > 253) {
    return { valid: false, error: 'Invalid target hostname.' };
  }

  // SSRF Protection: Check against blocked hostnames
  if (!allowLocalLab) {
    if (DANGEROUS_HOSTNAMES.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
      return {
        valid: false,
        error: `SSRF Protection: Requests to local/internal host "${hostname}" are blocked unless "Allow Local Lab" is explicitly enabled.`
      };
    }
  }

  // DNS Resolution & IP Check to prevent DNS rebinding bypasses
  let resolvedIps = [];
  try {
    if (net.isIP(hostname)) {
      resolvedIps = [hostname];
    } else {
      const addresses = await dns.lookup(hostname, { all: true });
      resolvedIps = addresses.map(a => a.address);
    }
  } catch (dnsErr) {
    // If local lab is permitted and DNS failed, could be a local hosts file entry or offline test
    if (!allowLocalLab) {
      return {
        valid: false,
        error: `Unable to resolve target hostname "${hostname}" (DNS Error: ${dnsErr.code || dnsErr.message}).`
      };
    }
  }

  // Check resolved IPs against SSRF filters
  if (!allowLocalLab && resolvedIps.length > 0) {
    for (const ip of resolvedIps) {
      const isV4 = net.isIPv4(ip);
      const isV6 = net.isIPv6(ip);

      if (isV4 && isPrivateIPv4(ip)) {
        return {
          valid: false,
          error: `SSRF Protection: Hostname "${hostname}" resolves to private IP (${ip}). Scanning internal/private networks is restricted.`
        };
      }
      if (isV6 && isPrivateIPv6(ip)) {
        return {
          valid: false,
          error: `SSRF Protection: Hostname "${hostname}" resolves to private IPv6 (${ip}). Internal network scanning is restricted.`
        };
      }
    }
  }

  // Return normalized valid target info
  return {
    valid: true,
    normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
    origin: parsed.origin,
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    pathname: parsed.pathname || '/',
    resolvedIps,
    isLocalLab: allowLocalLab && (DANGEROUS_HOSTNAMES.has(hostname) || (resolvedIps.length > 0 && isPrivateIPv4(resolvedIps[0])))
  };
}

/**
 * Checks whether a given link is within the permitted scan scope
 * @param {string} candidateUrl
 * @param {string} targetOrigin
 * @param {boolean} includeSubdomains
 */
export function isUrlInScope(candidateUrl, targetOrigin, includeSubdomains = false) {
  try {
    const candidate = new URL(candidateUrl);
    const target = new URL(targetOrigin);

    if (candidate.protocol !== 'http:' && candidate.protocol !== 'https:') {
      return false;
    }

    const cHost = candidate.hostname.toLowerCase();
    const tHost = target.hostname.toLowerCase();

    // Exact host match
    if (cHost === tHost) {
      return true;
    }

    // Subdomain matching if enabled
    if (includeSubdomains) {
      if (cHost.endsWith('.' + tHost)) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}
