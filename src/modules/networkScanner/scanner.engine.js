import net from 'net';
import dns from 'dns/promises';

/**
 * Comprehensive Port & Service Risk Knowledge Matrix
 */
export const PORT_DATABASE = {
  21: { service: 'FTP', name: 'File Transfer Protocol', risk: 'Medium', desc: 'Unencrypted file transfer. Prone to cleartext credential interception & anonymous login abuse.' },
  22: { service: 'SSH', name: 'Secure Shell', risk: 'Low', desc: 'Encrypted remote administrative shell. Prone to brute-force dictionary attacks.' },
  23: { service: 'Telnet', name: 'Telnet Remote Console', risk: 'High', desc: 'Legacy unencrypted terminal protocol. All keystrokes and passwords transmitted in cleartext.' },
  25: { service: 'SMTP', name: 'Simple Mail Transfer', risk: 'Medium', desc: 'Mail routing protocol. May allow open-relay mail spoofing and user enumeration (VRFY/EXPN).' },
  53: { service: 'DNS', name: 'Domain Name System', risk: 'Low', desc: 'Domain name resolution. May permit unauthorized DNS zone transfers (AXFR) or amplification attacks.' },
  69: { service: 'TFTP', name: 'Trivial File Transfer Protocol', risk: 'High', desc: 'UDP-based file transfer without authentication. Often used in PXE boots and router firmware dumps.' },
  80: { service: 'HTTP', name: 'HyperText Transfer Protocol (Cleartext)', risk: 'Medium', desc: 'Unencrypted web traffic. Data in transit is vulnerable to eavesdropping and MITM attacks.' },
  110: { service: 'POP3', name: 'Post Office Protocol v3', risk: 'Medium', desc: 'Cleartext email retrieval. Susceptible to packet sniffing.' },
  111: { service: 'RPCBind', name: 'SUN RPC Portmapper', risk: 'Medium', desc: 'NFS & RPC service directory. Can leak system services and NFS export points.' },
  119: { service: 'NNTP', name: 'Network News Transfer Protocol', risk: 'Low', desc: 'Usenet newsgroup discussions.' },
  123: { service: 'NTP', name: 'Network Time Protocol', risk: 'Low', desc: 'Time synchronization. Historically abused in DDoS NTP monlist amplification.' },
  135: { service: 'MSRPC', name: 'Microsoft RPC Endpoint Mapper', risk: 'High', desc: 'Core Windows RPC subsystem. Prone to remote RPC enumeration and exploit vectors.' },
  137: { service: 'NetBIOS-NS', name: 'NetBIOS Name Service', risk: 'Medium', desc: 'Legacy Windows name resolution protocol. Susceptible to LLMNR/NBT-NS spoofing (Responder).' },
  138: { service: 'NetBIOS-DGM', name: 'NetBIOS Datagram Service', risk: 'Medium', desc: 'Windows NetBIOS browsing and announcements.' },
  139: { service: 'NetBIOS-SSN', name: 'NetBIOS Session Service', risk: 'High', desc: 'Windows legacy file sharing. Can disclose workgroup, domain, and user accounts.' },
  143: { service: 'IMAP', name: 'Internet Message Access Protocol', risk: 'Medium', desc: 'Cleartext email access protocol.' },
  161: { service: 'SNMP', name: 'Simple Network Management Protocol', risk: 'High', desc: 'Network device monitoring. Default community strings (public/private) permit configuration disclosure.' },
  162: { service: 'SNMP-Trap', name: 'SNMP Trap Receiver', risk: 'Low', desc: 'Asynchronous event alerts from network gear.' },
  389: { service: 'LDAP', name: 'Lightweight Directory Access Protocol', risk: 'Medium', desc: 'Directory service queries (Active Directory). Can disclose corporate user hierarchies.' },
  443: { service: 'HTTPS', name: 'HTTP over TLS/SSL', risk: 'Low', desc: 'Encrypted web transport. Secure default standard for modern web applications.' },
  445: { service: 'SMB', name: 'Microsoft Server Message Block', risk: 'Critical', desc: 'Direct-hosted Windows file sharing. High-priority target for ransomware and EternalBlue (MS17-010).' },
  465: { service: 'SMTPS', name: 'SMTP over SSL', risk: 'Low', desc: 'Secure mail submission protocol.' },
  514: { service: 'Syslog', name: 'System Logging Protocol', risk: 'Low', desc: 'Centralized server and device audit logs.' },
  515: { service: 'LPD', name: 'Line Printer Daemon', risk: 'Low', desc: 'Network printing services.' },
  587: { service: 'SMTP-Submission', name: 'Mail Message Submission', risk: 'Low', desc: 'Authenticated email transmission standard.' },
  636: { service: 'LDAPS', name: 'LDAP over SSL', risk: 'Low', desc: 'Encrypted directory queries.' },
  873: { service: 'Rsync', name: 'Rsync File Transfer', risk: 'High', desc: 'Remote file sync daemon. Often misconfigured without authentication, exposing complete filesystem backups.' },
  993: { service: 'IMAPS', name: 'IMAP over SSL/TLS', risk: 'Low', desc: 'Secure encrypted email synchronization.' },
  995: { service: 'POP3S', name: 'POP3 over SSL/TLS', risk: 'Low', desc: 'Secure encrypted email retrieval.' },
  1080: { service: 'SOCKS', name: 'SOCKS Proxy Server', risk: 'Medium', desc: 'Generic proxy service. Misconfigured open proxies allow threat actor traffic routing.' },
  1433: { service: 'MSSQL', name: 'Microsoft SQL Server', risk: 'High', desc: 'Relational database. Prone to SA account brute-forcing and xp_cmdshell execution.' },
  1521: { service: 'Oracle', name: 'Oracle Database Listener', risk: 'High', desc: 'Enterprise database system. Susceptible to TNS listener poisoning and SID enumeration.' },
  2049: { service: 'NFS', name: 'Network File System', risk: 'High', desc: 'Unix filesystem sharing. Misconfigured exports (`*` permissions) allow root remote mounting.' },
  2181: { service: 'ZooKeeper', name: 'Apache ZooKeeper', risk: 'Medium', desc: 'Distributed system coordination service.' },
  3000: { service: 'Node.js/Dev', name: 'Node.js / React / Grafana Dev Server', risk: 'Medium', desc: 'Common web application development port or Grafana monitoring console.' },
  3306: { service: 'MySQL', name: 'MySQL / MariaDB Database', risk: 'High', desc: 'Relational database engine. Should not be directly exposed to public WAN.' },
  3389: { service: 'RDP', name: 'Remote Desktop Protocol', risk: 'Critical', desc: 'Windows GUI remote management. Prone to password spraying, brute force, and BlueKeep (CVE-2019-0708).' },
  4444: { service: 'Metasploit', name: 'Metasploit / Reverse Shell Port', risk: 'Critical', desc: 'Default listener port for Metasploit payloads and backdoor implants.' },
  5000: { service: 'Flask/Docker', name: 'Python Flask / Docker Registry', risk: 'Medium', desc: 'API backend or internal container registry.' },
  5001: { service: 'CyberShield', name: 'CyberShield API / Synology DSM', risk: 'Info', desc: 'Backend application API service.' },
  5432: { service: 'PostgreSQL', name: 'PostgreSQL Relational Database', risk: 'High', desc: 'Enterprise SQL database. Dangerous if exposed with default `postgres` credentials.' },
  5900: { service: 'VNC', name: 'Virtual Network Computing', risk: 'High', desc: 'Graphical desktop sharing. Often configured with weak 8-character passwords or no encryption.' },
  5985: { service: 'WinRM-HTTP', name: 'Windows Remote Management (HTTP)', risk: 'High', desc: 'PowerShell remoting service. Used for Windows administrative command execution.' },
  5986: { service: 'WinRM-HTTPS', name: 'Windows Remote Management (HTTPS)', risk: 'Medium', desc: 'Encrypted PowerShell remoting endpoint.' },
  6379: { service: 'Redis', name: 'Redis In-Memory Key-Value Store', risk: 'Critical', desc: 'NoSQL caching store. Unauthenticated default setups allow remote file writing and SSH key implants.' },
  8000: { service: 'HTTP-Alt', name: 'Alternative HTTP / Django / Python SimpleHTTP', risk: 'Medium', desc: 'Common staging or administrative dashboard port.' },
  8080: { service: 'HTTP-Proxy', name: 'HTTP Proxy / Apache Tomcat / Jenkins', risk: 'Medium', desc: 'Web proxy or Java application container. Frequently exposes CI/CD build consoles.' },
  8443: { service: 'HTTPS-Alt', name: 'Alternative HTTPS / Tomcat SSL', risk: 'Low', desc: 'Secondary secure administrative portal.' },
  8888: { service: 'Jupyter', name: 'Jupyter Notebook / Web Control Panel', risk: 'High', desc: 'Data science environment or server control panel. Unprotected notebooks allow arbitrary bash execution.' },
  9000: { service: 'SonarQube/PHP-FPM', name: 'SonarQube / PHP FastCGI / MinIO', risk: 'Medium', desc: 'Application service or cloud object storage console.' },
  9200: { service: 'Elasticsearch', name: 'Elasticsearch REST API', risk: 'Critical', desc: 'Search and analytics engine. Unsecured clusters allow full database index exfiltration.' },
  11211: { service: 'Memcached', name: 'Memcached In-Memory Cache', risk: 'High', desc: 'Key-value cache. Historically weaponized in 50,000x UDP amplification DDoS attacks.' },
  27017: { service: 'MongoDB', name: 'MongoDB NoSQL Document Store', risk: 'Critical', desc: 'NoSQL database. Frequently targeted by ransomware when deployed without authentication.' }
};

// Common port scan presets
export const PRESET_PROFILES = {
  top20: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080],
  top100: [
    20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 873, 990, 993, 995, 1080, 1194,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2181, 3000, 3128, 3306, 3389, 3690, 4444,
    5000, 5001, 5432, 5672, 5900, 5901, 5985, 5986, 6000, 6379, 6667, 7001, 8000, 8080, 8081,
    8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9999, 10000, 11211, 27017, 27018, 50000
  ],
  web: [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 5001, 9000, 9090],
  database: [1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300, 11211, 27017, 27018],
  remote: [22, 23, 3389, 5900, 5901, 5985, 5986],
  mail: [25, 110, 143, 465, 587, 993, 995],
  infrastructure: [53, 67, 68, 69, 111, 123, 161, 162, 389, 636, 2049]
};

/**
 * Parses custom port strings like "80, 443, 8000-8010, 3000" into a sanitized sorted array
 */
export function parsePortList(inputString, preset = 'top20') {
  if (preset === 'custom' || (inputString && typeof inputString === 'string' && inputString.trim().length > 0)) {
    const ports = new Set();
    const chunks = (inputString || '').split(',').map((c) => c.trim()).filter(Boolean);

    for (const chunk of chunks) {
      if (chunk.includes('-')) {
        const [startStr, endStr] = chunk.split('-').map((s) => s.trim());
        const start = parseInt(startStr, 10);
        const end = parseInt(endStr, 10);
        if (!isNaN(start) && !isNaN(end) && start > 0 && end <= 65535 && start <= end) {
          const rangeSize = Math.min(end - start + 1, 1000);
          for (let i = 0; i < rangeSize; i++) {
            ports.add(start + i);
          }
        }
      } else {
        const p = parseInt(chunk, 10);
        if (!isNaN(p) && p > 0 && p <= 65535) {
          ports.add(p);
        }
      }
    }

    const sorted = Array.from(ports).sort((a, b) => a - b);
    if (sorted.length > 0) return sorted;
  }

  if (preset && PRESET_PROFILES[preset]) {
    return PRESET_PROFILES[preset];
  }

  return PRESET_PROFILES.top20;
}

/**
 * Probes a single TCP port on a target host with latency and optional banner grabbing
 */
export function probePort(host, port, timeoutMs = 800, grabBanner = true) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();
    let isResolved = false;
    let banner = '';

    const finalize = (status, errorReason = null) => {
      if (isResolved) return;
      isResolved = true;
      const latencyMs = Date.now() - startTime;
      socket.destroy();

      const serviceInfo = PORT_DATABASE[port] || {
        service: 'Unknown',
        name: `TCP Port ${port}`,
        risk: 'Info',
        desc: 'Unregistered or proprietary telecommunication port.'
      };

      resolve({
        port,
        status, // 'open' | 'closed' | 'filtered'
        latencyMs: status === 'open' ? latencyMs : null,
        service: serviceInfo.service,
        serviceName: serviceInfo.name,
        risk: serviceInfo.risk,
        description: serviceInfo.desc,
        banner: banner ? banner.trim() : null,
        error: errorReason
      });
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (!grabBanner) {
        return finalize('open');
      }

      // Banner Grabber logic: Send appropriate protocol handshake probe
      try {
        if ([80, 8080, 8000, 3000, 5000].includes(port)) {
          socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: CyberShield-Scanner\r\nConnection: close\r\n\r\n`);
        } else if (port === 6379) {
          socket.write('PING\r\n');
        } else if (port === 21 || port === 22 || port === 25 || port === 110) {
          // Servers send their banner immediately upon TCP connect
        } else {
          socket.write('\r\n\r\n');
        }
      } catch {}

      // Allow a brief window to collect banner bytes
      const bannerTimer = setTimeout(() => {
        finalize('open');
      }, Math.min(timeoutMs, 400));

      socket.on('data', (chunk) => {
        clearTimeout(bannerTimer);
        const chunkStr = chunk.toString('utf8', 0, Math.min(chunk.length, 512));
        // Remove non-printable binary characters
        banner += chunkStr.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, ' ');
        finalize('open');
      });
    });

    socket.on('timeout', () => finalize('filtered', 'Connection timed out'));
    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        finalize('closed', 'Connection refused (RST)');
      } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
        finalize('filtered', 'Host or network unreachable');
      } else if (err.code === 'ETIMEDOUT') {
        finalize('filtered', 'Connection timed out');
      } else {
        finalize('closed', err.code || 'Socket error');
      }
    });

    try {
      socket.connect(port, host);
    } catch (err) {
      finalize('closed', err.message);
    }
  });
}

/**
 * Worker pool scanner with concurrency throttling to prevent socket starvation
 */
export async function executePortScan(targetInput, options = {}) {
  const host = targetInput.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (!host) throw new Error('Please enter a valid target hostname or IP address.');

  const preset = options.preset || 'top20';
  const customPorts = options.customPorts || '';
  const portList = parsePortList(customPorts, preset);
  const timeoutMs = Math.min(Math.max(parseInt(options.timeoutMs, 10) || 800, 150), 3000);
  const concurrency = Math.min(Math.max(parseInt(options.concurrency, 10) || 30, 5), 100);
  const grabBanner = options.grabBanner !== false;

  const scanStartTime = Date.now();

  // Resolve Target IP & DNS
  let targetIp = host;
  let reverseHostname = null;
  let isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');

  try {
    const lookupResult = await dns.lookup(host);
    targetIp = lookupResult.address;
    if (isIp) {
      try {
        const ptrs = await dns.reverse(targetIp);
        if (ptrs && ptrs.length > 0) reverseHostname = ptrs[0];
      } catch {}
    } else {
      reverseHostname = host;
    }
  } catch (err) {
    if (!isIp) {
      throw new Error(`Unable to resolve hostname "${host}". Check target syntax or DNS connectivity.`);
    }
  }

  // Scan worker pool
  const results = [];
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < portList.length) {
      const port = portList[currentIndex++];
      const probeResult = await probePort(targetIp, port, timeoutMs, grabBanner);
      results.push(probeResult);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, portList.length) }, () => worker());
  await Promise.all(workers);

  const durationMs = Date.now() - scanStartTime;

  // Aggregate results
  const openPorts = results.filter((r) => r.status === 'open').sort((a, b) => a.port - b.port);
  const closedCount = results.filter((r) => r.status === 'closed').length;
  const filteredCount = results.filter((r) => r.status === 'filtered').length;

  // Compute risk score based on open ports
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;

  openPorts.forEach((p) => {
    if (p.risk === 'Critical') criticalCount++;
    else if (p.risk === 'High') highCount++;
    else if (p.risk === 'Medium') mediumCount++;
  });

  let overallThreat = 'Low';
  if (criticalCount > 0) overallThreat = 'Critical';
  else if (highCount > 0) overallThreat = 'High';
  else if (mediumCount > 0) overallThreat = 'Medium';

  // Heuristic OS Fingerprinting based on open services
  let estimatedOs = 'Unknown System';
  const openPortNumbers = new Set(openPorts.map((p) => p.port));

  if (openPortNumbers.has(135) || openPortNumbers.has(445) || openPortNumbers.has(3389)) {
    estimatedOs = 'Microsoft Windows / Windows Server';
  } else if (openPortNumbers.has(22)) {
    const sshPort = openPorts.find((p) => p.port === 22);
    if (sshPort && sshPort.banner) {
      if (sshPort.banner.toLowerCase().includes('ubuntu')) estimatedOs = 'Linux (Ubuntu)';
      else if (sshPort.banner.toLowerCase().includes('debian')) estimatedOs = 'Linux (Debian)';
      else if (sshPort.banner.toLowerCase().includes('centos')) estimatedOs = 'Linux (CentOS / RHEL)';
      else estimatedOs = 'Linux / Unix System';
    } else {
      estimatedOs = 'Linux / Unix System';
    }
  } else if (openPortNumbers.has(80) || openPortNumbers.has(443)) {
    estimatedOs = 'Web Appliance / Embedded Server';
  }

  const allPorts = results.sort((a, b) => a.port - b.port);

  return {
    target: host,
    targetIp,
    reverseHostname,
    durationMs,
    totalScanned: portList.length,
    openCount: openPorts.length,
    closedCount,
    filteredCount,
    overallThreat,
    criticalCount,
    highCount,
    mediumCount,
    estimatedOs,
    openPorts,
    ports: allPorts,
    scanOptions: {
      preset,
      timeoutMs,
      concurrency,
      grabBanner
    }
  };
}

/**
 * Interactive Deep Socket Probe for a single port with custom payload transmission
 */
export function deepSocketProbe(host, port, payload = '', timeoutMs = 2500) {
  return new Promise((resolve) => {
    const cleanHost = host.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const targetPort = parseInt(port, 10);
    if (!targetPort || targetPort < 1 || targetPort > 65535) {
      return resolve({ success: false, error: 'Invalid port number.' });
    }

    const startTime = Date.now();
    const socket = new net.Socket();
    let isFinished = false;
    let rawResponse = Buffer.alloc(0);

    const finalize = (success, errorMsg = null) => {
      if (isFinished) return;
      isFinished = true;
      const latency = Date.now() - startTime;
      socket.destroy();

      const ascii = rawResponse.toString('utf8');
      const hexDump = rawResponse.toString('hex').match(/.{1,2}/g)?.join(' ') || '';

      resolve({
        success,
        host: cleanHost,
        port: targetPort,
        latencyMs: latency,
        bytesReceived: rawResponse.length,
        asciiResponse: ascii.length > 0 ? ascii : null,
        hexResponse: hexDump.length > 0 ? hexDump : null,
        error: errorMsg
      });
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (payload) {
        try {
          socket.write(payload.replace(/\\r/g, '\r').replace(/\\n/g, '\n'));
        } catch (err) {
          finalize(false, `Payload write error: ${err.message}`);
        }
      }
    });

    socket.on('data', (data) => {
      rawResponse = Buffer.concat([rawResponse, data]);
      if (rawResponse.length >= 4096) {
        finalize(true);
      }
    });

    socket.on('timeout', () => {
      if (rawResponse.length > 0) finalize(true);
      else finalize(false, 'Socket response timed out');
    });

    socket.on('error', (err) => {
      if (rawResponse.length > 0) finalize(true);
      else finalize(false, err.code || err.message);
    });

    socket.on('end', () => finalize(true));

    try {
      socket.connect(targetPort, cleanHost);
    } catch (err) {
      finalize(false, err.message);
    }
  });
}

/**
 * Subnet Ping / Live Port Sweep
 * Probes common ports on an IPv4 CIDR range (e.g. 192.168.1.1 - 192.168.1.30)
 */
export async function sweepSubnetRange(baseSubnet, rangeLimit = 30) {
  const parts = baseSubnet.trim().split('.');
  if (parts.length < 3) throw new Error('Please enter a valid IPv4 subnet prefix (e.g. 192.168.1).');

  const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
  const hostsToScan = [];
  const limit = Math.min(Math.max(parseInt(rangeLimit, 10) || 20, 5), 50);

  for (let i = 1; i <= limit; i++) {
    hostsToScan.push(`${prefix}.${i}`);
  }

  const commonPorts = [80, 443, 22, 445, 135, 8080];
  const liveHosts = [];

  // Scan IPs in parallel chunks
  const sweepResults = await Promise.all(
    hostsToScan.map(async (ip) => {
      // Test the common ports concurrently for this IP with short 350ms timeout
      const portProbes = await Promise.all(
        commonPorts.map((p) => probePort(ip, p, 350, false))
      );

      const openOnHost = portProbes.filter((p) => p.status === 'open');
      if (openOnHost.length > 0) {
        return {
          ip,
          isLive: true,
          openPortCount: openOnHost.length,
          openPorts: openOnHost.map((p) => ({ port: p.port, service: p.service, latencyMs: p.latencyMs })),
          minLatency: Math.min(...openOnHost.map((p) => p.latencyMs || 999))
        };
      }
      return null;
    })
  );

  return {
    subnet: `${prefix}.0/24`,
    scannedHosts: hostsToScan.length,
    liveHostsCount: sweepResults.filter(Boolean).length,
    hosts: sweepResults.filter(Boolean).sort((a, b) => a.minLatency - b.minLatency)
  };
}
