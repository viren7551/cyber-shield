import tls from 'tls';
import net from 'net';

/**
 * CyberShield Web Security Scanner - TLS / SSL Configuration Analyzer
 * Safely connects via TLS socket to inspect certificate validity, expiration,
 * issuer, SANs, negotiated cipher, and protocol version.
 */

/**
 * Perform safe TLS connection inspection
 * @param {string} hostname
 * @param {number} port
 * @param {number} timeoutMs
 */
export async function analyzeTls(hostname, port = 443, timeoutMs = 8000) {
  const findings = [];

  return new Promise((resolve) => {
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        resolve({
          supported: false,
          error: `TLS handshake timed out after ${timeoutMs}ms`,
          findings: []
        });
      }
    }, timeoutMs);

    const socketOptions = {
      host: hostname,
      port: port || 443,
      servername: hostname, // SNI support
      rejectUnauthorized: false // Inspect even if expired/self-signed so we can generate accurate findings!
    };

    const socket = tls.connect(socketOptions, () => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);

      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol(); // e.g. TLSv1.3, TLSv1.2
        const cipher = socket.getCipher(); // { name, version }
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({
            supported: false,
            error: 'No peer certificate returned by server.',
            findings: []
          });
        }

        const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const now = new Date();
        const daysRemaining = validTo ? Math.round((validTo - now) / (1000 * 60 * 60 * 24)) : null;
        const isExpired = daysRemaining !== null && daysRemaining <= 0;

        // Subject Alternative Names (SAN)
        const altNames = cert.subjectaltname
          ? cert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/i, ''))
          : [];

        // Hostname match verification
        const cn = cert.subject?.CN || '';
        const allNames = [cn, ...altNames].filter(Boolean);
        const lowerHost = hostname.toLowerCase();

        const matchesHostname = allNames.some(name => {
          const lowerName = name.toLowerCase();
          if (lowerName === lowerHost) return true;
          if (lowerName.startsWith('*.')) {
            const wildcardDomain = lowerName.slice(2);
            return lowerHost.endsWith('.' + wildcardDomain) && !lowerHost.replace('.' + wildcardDomain, '').includes('.');
          }
          return false;
        });

        // Generate Security Findings

        // 1. Expired Certificate
        if (isExpired) {
          findings.push({
            ruleId: 'TLS_CERT_EXPIRED',
            title: 'TLS Certificate Is Expired',
            severity: 'Critical',
            confidence: 'High',
            category: 'TLS / Cryptography',
            url: `https://${hostname}`,
            description: `The SSL/TLS certificate for "${hostname}" expired on ${validTo?.toISOString() || 'Unknown'}.`,
            impact: 'All web browsers will display severe security warnings, blocking normal user access. Trust in the application is destroyed.',
            evidence: { validFrom, validTo, daysRemaining, status: 'EXPIRED' },
            recommendation: 'Immediately renew and replace the TLS certificate with a valid certificate from a trusted Certificate Authority.',
            cwe: 'CWE-298',
            owasp: 'A02:2021 - Cryptographic Failures',
            references: ['https://cwe.mitre.org/data/definitions/298.html']
          });
        } else if (daysRemaining !== null && daysRemaining <= 30) {
          findings.push({
            ruleId: 'TLS_CERT_EXPIRING_SOON',
            title: `TLS Certificate Expiring Soon (${daysRemaining} Days)`,
            severity: 'Low',
            confidence: 'High',
            category: 'TLS / Cryptography',
            url: `https://${hostname}`,
            description: `The SSL/TLS certificate will expire in ${daysRemaining} days (on ${validTo?.toLocaleDateString()}).`,
            impact: 'Risk of service outage or sudden browser security warnings if renewal is not automated.',
            evidence: { validTo, daysRemaining },
            recommendation: 'Renew the SSL/TLS certificate before expiration or verify automated ACME/Let\'s Encrypt renewal timers.',
            cwe: 'CWE-298',
            owasp: 'A02:2021 - Cryptographic Failures',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html']
          });
        }

        // 2. Hostname Mismatch
        if (!matchesHostname && allNames.length > 0) {
          findings.push({
            ruleId: 'TLS_CERT_HOSTNAME_MISMATCH',
            title: 'TLS Certificate Hostname Mismatch',
            severity: 'High',
            confidence: 'High',
            category: 'TLS / Cryptography',
            url: `https://${hostname}`,
            description: `The certificate presented does not match the requested hostname "${hostname}". Names on certificate: ${allNames.slice(0, 5).join(', ')}.`,
            impact: 'Browsers warn users of an invalid identity or potential Man-In-The-Middle (MITM) impersonation.',
            evidence: { targetHost: hostname, certCN: cn, altNames },
            recommendation: 'Issue a certificate whose Common Name (CN) or Subject Alternative Names (SAN) include this exact hostname or domain wildcard.',
            cwe: 'CWE-297',
            owasp: 'A02:2021 - Cryptographic Failures',
            references: ['https://cwe.mitre.org/data/definitions/297.html']
          });
        }

        // 3. Self-Signed or Untrusted CA
        if (!authorized && authError) {
          findings.push({
            ruleId: 'TLS_UNTRUSTED_ROOT_OR_SELF_SIGNED',
            title: 'TLS Certificate Chain Untrusted or Self-Signed',
            severity: 'Medium',
            confidence: 'High',
            category: 'TLS / Cryptography',
            url: `https://${hostname}`,
            description: `The TLS certificate validation returned: ${authError}.`,
            impact: 'Clients will encounter certificate authority validation errors unless the custom root CA is explicitly installed in client trust stores.',
            evidence: { authError, issuer: cert.issuer?.O || cert.issuer?.CN },
            recommendation: 'Use a publicly trusted certificate authority (e.g. Let\'s Encrypt, DigiCert, Cloudflare) for production web services.',
            cwe: 'CWE-295',
            owasp: 'A02:2021 - Cryptographic Failures',
            references: ['https://cwe.mitre.org/data/definitions/295.html']
          });
        }

        // 4. Deprecated TLS Protocol Version
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          findings.push({
            ruleId: 'TLS_DEPRECATED_PROTOCOL_VERSION',
            title: `Deprecated TLS Protocol Version (${protocol})`,
            severity: 'High',
            confidence: 'High',
            category: 'TLS / Cryptography',
            url: `https://${hostname}`,
            description: `The server negotiated ${protocol}. TLS 1.0 and TLS 1.1 have been deprecated by RFC 8996 and are vulnerable to known cryptographic attacks (BEAST, POODLE).`,
            impact: 'Exposes encrypted traffic to cryptographic downgrade and eavesdropping attacks.',
            evidence: { protocol, cipher: cipher?.name },
            recommendation: 'Disable TLS 1.0 and 1.1. Enforce TLS 1.2 and TLS 1.3 only.',
            cwe: 'CWE-326',
            owasp: 'A02:2021 - Cryptographic Failures',
            references: ['https://datatracker.ietf.org/doc/html/rfc8996']
          });
        }

        resolve({
          supported: true,
          protocol,
          cipher: cipher?.name || 'Unknown',
          authorized,
          authError: authError || null,
          subject: {
            commonName: cert.subject?.CN || 'Unknown',
            organization: cert.subject?.O || 'Not Specified',
            country: cert.subject?.C || ''
          },
          issuer: {
            commonName: cert.issuer?.CN || 'Unknown',
            organization: cert.issuer?.O || 'Not Specified',
            country: cert.issuer?.C || ''
          },
          validFrom: validFrom?.toISOString(),
          validTo: validTo?.toISOString(),
          daysRemaining,
          isExpired,
          matchesHostname,
          altNames,
          serialNumber: cert.serialNumber || '',
          fingerprint: cert.fingerprint256 || cert.fingerprint || '',
          findings
        });
      } catch (err) {
        socket.destroy();
        resolve({
          supported: false,
          error: `Error inspecting TLS certificate: ${err.message}`,
          findings: []
        });
      }
    });

    socket.on('error', (err) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({
        supported: false,
        error: `TLS Connection Error: ${err.message}`,
        findings: []
      });
    });
  });
}
