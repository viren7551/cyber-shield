/**
 * CyberShield Multi-Format Log Parser
 * Parses Linux auth.log, syslog, Apache/Nginx access logs, Windows Event CSV/JSON,
 * Firewall (iptables/UFW) logs, JSON application logs, and generic log files.
 */

// Helper to parse syslog dates like "Sep 27 16:20:11" or "2026-09-27T16:20:11"
function parseLogTimestamp(dateStr) {
  if (!dateStr) return new Date().toISOString();

  // Try standard ISO or direct Date parse first
  const parsed = Date.parse(dateStr);
  if (!isNaN(parsed)) {
    return new Date(parsed).toISOString();
  }

  // Handle Syslog format: "Sep 27 16:20:11" or "Sep  7 16:20:11"
  const syslogRegex = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/;
  const match = dateStr.match(syslogRegex);
  if (match) {
    const months = {
      Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
      Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
    };
    const currentYear = new Date().getFullYear();
    const month = months[match[1]] !== undefined ? months[match[1]] : 8;
    const day = parseInt(match[2], 10);
    const hour = parseInt(match[3], 10);
    const minute = parseInt(match[4], 10);
    const second = parseInt(match[5], 10);

    const d = new Date(Date.UTC(currentYear, month, day, hour, minute, second));
    return d.toISOString();
  }

  // Handle Apache format: "27/Sep/2026:16:20:11 +0000"
  const clfRegex = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+\-]\d{4})/;
  const clfMatch = dateStr.match(clfRegex);
  if (clfMatch) {
    const months = {
      Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
      Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12'
    };
    const isoString = `${clfMatch[3]}-${months[clfMatch[2]] || '01'}-${clfMatch[1]}T${clfMatch[4]}:${clfMatch[5]}:${clfMatch[6]}${clfMatch[7] ? clfMatch[7].slice(0, 3) + ':' + clfMatch[7].slice(3) : 'Z'}`;
    const d = new Date(isoString);
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  return new Date().toISOString();
}

/**
 * Detect log format heuristic
 */
export function detectLogFormat(sampleLines = []) {
  const text = sampleLines.join('\n');

  if (text.includes('"GET ') || text.includes('"POST ') || text.includes('"PUT ') || text.includes('HTTP/1.')) {
    return 'APACHE_NGINX';
  }
  if (text.includes('sshd[') || text.includes('Failed password') || text.includes('Accepted password') || text.includes('sudo:') || text.includes('PAM:')) {
    return 'LINUX_AUTH';
  }
  if (text.includes('[UFW ') || text.includes('SRC=') && text.includes('DST=') && text.includes('PROTO=')) {
    return 'FIREWALL';
  }
  if (sampleLines.some(l => l.trim().startsWith('{') && l.trim().endsWith('}'))) {
    return 'JSON';
  }
  if (text.includes('4625') || text.includes('4624') || text.includes('Audit Failure') || text.includes('Audit Success') || text.includes('Microsoft-Windows-Security')) {
    return 'WINDOWS_EVENT';
  }
  if (sampleLines.some(l => /^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\w\.\-]+/.test(l))) {
    return 'LINUX_SYSLOG';
  }

  return 'GENERIC';
}

/**
 * 1. Parse Linux auth.log / secure log line
 */
function parseLinuxAuthLine(line, index) {
  // Typical: Sep 27 16:20:11 server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2
  // Or: Sep 27 16:20:25 server sshd[1237]: Accepted password for admin from 192.168.1.50 port 54321 ssh2
  // Or: Sep 27 16:21:00 server sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
  // Or: Sep 27 16:22:10 server su[2345]: pam_authenticate: Authentication failure for user root by admin
  // Or: Sep 27 16:23:45 server useradd[2400]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash
  const headerMatch = line.match(/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Z\+\-]\d{2}:?\d{2})?)\s+([\w\.\-]+)\s+([^:]+):\s+(.*)$/);

  let timestampStr = '';
  let host = 'localhost';
  let daemon = 'system';
  let message = line;

  if (headerMatch) {
    timestampStr = headerMatch[1];
    host = headerMatch[2];
    daemon = headerMatch[3].trim();
    message = headerMatch[4];
  } else {
    // Fallback extraction
    const tsMatch = line.match(/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    if (tsMatch) timestampStr = tsMatch[1];
  }

  const isoTime = parseLogTimestamp(timestampStr);
  const ipMatch = message.match(/\b(?:from|SRC=)?\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  const sourceIp = ipMatch ? ipMatch[1] : null;

  let port = null;
  const portMatch = message.match(/port\s+(\d+)/i);
  if (portMatch) port = parseInt(portMatch[1], 10);

  let user = null;
  let action = 'LOG_ENTRY';
  let status = 'INFO';
  let category = 'SYSTEM';
  let severity = 'LOW';

  // SSH Failed Password
  if (message.includes('Failed password for invalid user')) {
    action = 'AUTH_FAILED';
    status = 'FAILURE';
    category = 'AUTHENTICATION';
    severity = 'MEDIUM';
    const u = message.match(/Failed password for invalid user\s+([^\s]+)/);
    if (u) user = u[1];
  } else if (message.includes('Failed password for')) {
    action = 'AUTH_FAILED';
    status = 'FAILURE';
    category = 'AUTHENTICATION';
    severity = 'MEDIUM';
    const u = message.match(/Failed password for\s+([^\s]+)/);
    if (u) user = u[1];
  } else if (message.includes('Accepted password for') || message.includes('Accepted publickey for')) {
    action = 'AUTH_SUCCESS';
    status = 'SUCCESS';
    category = 'AUTHENTICATION';
    severity = 'INFO';
    const u = message.match(/Accepted (?:password|publickey) for\s+([^\s]+)/);
    if (u) user = u[1];
    if (user === 'root') severity = 'MEDIUM';
  } else if (message.includes('Invalid user')) {
    action = 'AUTH_INVALID_USER';
    status = 'FAILURE';
    category = 'AUTHENTICATION';
    severity = 'MEDIUM';
    const u = message.match(/Invalid user\s+([^\s]+)/);
    if (u) user = u[1];
  } else if (daemon.includes('sudo')) {
    category = 'SYSTEM';
    action = 'SUDO_EXEC';
    status = message.includes('authentication failure') ? 'FAILURE' : 'SUCCESS';
    severity = status === 'FAILURE' ? 'HIGH' : 'MEDIUM';
    const u = message.match(/^\s*([^\s:]+)\s*:/);
    if (u) user = u[1];
    if (message.includes('USER=root')) {
      action = 'SUDO_ROOT_EXEC';
    }
  } else if (daemon.includes('su') || message.includes('Authentication failure for user')) {
    category = 'SYSTEM';
    action = 'SU_ATTEMPT';
    status = message.includes('failure') ? 'FAILURE' : 'SUCCESS';
    severity = status === 'FAILURE' ? 'HIGH' : 'LOW';
    const u = message.match(/by\s+([^\s]+)/);
    if (u) user = u[1];
  } else if (daemon.includes('useradd') || message.includes('new user:')) {
    category = 'SYSTEM';
    action = 'USER_CREATE';
    status = 'SUCCESS';
    severity = 'HIGH';
    const u = message.match(/name=([^\s,]+)/);
    if (u) user = u[1];
  } else if (daemon.includes('userdel') || message.includes('delete user')) {
    category = 'SYSTEM';
    action = 'USER_DELETE';
    status = 'SUCCESS';
    severity = 'MEDIUM';
    const u = message.match(/user\s+'?([^\s,']+)'?/);
    if (u) user = u[1];
  }

  return {
    id: `entry-${index + 1}`,
    index: index + 1,
    timestamp: isoTime,
    hostname: host,
    service: daemon.replace(/\[\d+\]/, ''),
    sourceIp,
    targetIp: null,
    port,
    user,
    action,
    status,
    statusCode: null,
    method: null,
    path: null,
    category,
    severity,
    message: message.trim(),
    raw: line
  };
}

/**
 * 2. Parse Apache / Nginx Combined Log Format
 * Example: 192.168.1.50 - admin [27/Sep/2026:16:20:11 +0000] "GET /wp-login.php HTTP/1.1" 404 1234 "referrer" "user-agent"
 */
function parseApacheNginxLine(line, index) {
  const clfPattern = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)?(?:\s+([^"\s]+))?"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  const match = line.match(clfPattern);

  if (match) {
    const sourceIp = match[1] !== '-' ? match[1] : null;
    const user = match[2] !== '-' ? match[2] : null;
    const isoTime = parseLogTimestamp(match[3]);
    const method = match[4];
    const path = match[5] || '/';
    const statusCode = parseInt(match[7], 10);
    const bytes = match[8] !== '-' ? parseInt(match[8], 10) : 0;
    const referrer = match[9] !== '-' ? match[9] : null;
    const userAgent = match[10] !== '-' ? match[10] : null;

    let status = statusCode < 400 ? 'SUCCESS' : 'FAILURE';
    let severity = 'LOW';
    if (statusCode === 401 || statusCode === 403) severity = 'MEDIUM';
    if (statusCode >= 500) severity = 'MEDIUM';

    // Check for obvious injection markers directly for high severity label
    const rawLower = (path + ' ' + (referrer || '')).toLowerCase();
    if (
      rawLower.includes('union+select') ||
      rawLower.includes('union select') ||
      rawLower.includes("' or 1=1") ||
      rawLower.includes('/etc/passwd') ||
      rawLower.includes('../..') ||
      rawLower.includes('.env') ||
      rawLower.includes('<script')
    ) {
      severity = 'HIGH';
    }

    return {
      id: `entry-${index + 1}`,
      index: index + 1,
      timestamp: isoTime,
      hostname: 'web-server',
      service: 'httpd',
      sourceIp,
      targetIp: null,
      port: 80,
      user,
      action: `HTTP_${method}`,
      status,
      statusCode,
      method,
      path,
      bytes,
      referrer,
      userAgent,
      category: 'WEB',
      severity,
      message: `${method} ${path} -> ${statusCode} (${bytes} bytes)`,
      raw: line
    };
  }

  // Fallback if slightly non-standard HTTP log
  return parseGenericLine(line, index, 'WEB');
}

/**
 * 3. Parse Firewall Log (UFW / iptables)
 * Example: Sep 27 16:20:11 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=48212 DPT=22
 */
function parseFirewallLine(line, index) {
  const tsMatch = line.match(/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
  const timestamp = parseLogTimestamp(tsMatch ? tsMatch[1] : null);

  const srcMatch = line.match(/SRC=([\d\.]+)/);
  const dstMatch = line.match(/DST=([\d\.]+)/);
  const protoMatch = line.match(/PROTO=([\w]+)/);
  const dptMatch = line.match(/DPT=(\d+)/);
  const sptMatch = line.match(/SPT=(\d+)/);

  const isBlocked = line.includes('BLOCK') || line.includes('DROP') || line.includes('DENY');

  return {
    id: `entry-${index + 1}`,
    index: index + 1,
    timestamp,
    hostname: 'firewall',
    service: 'iptables',
    sourceIp: srcMatch ? srcMatch[1] : null,
    targetIp: dstMatch ? dstMatch[1] : null,
    port: dptMatch ? parseInt(dptMatch[1], 10) : null,
    srcPort: sptMatch ? parseInt(sptMatch[1], 10) : null,
    proto: protoMatch ? protoMatch[1] : 'TCP',
    user: null,
    action: isBlocked ? 'FIREWALL_DROP' : 'FIREWALL_ALLOW',
    status: isBlocked ? 'BLOCKED' : 'ALLOWED',
    statusCode: null,
    method: null,
    path: null,
    category: 'NETWORK',
    severity: isBlocked ? 'MEDIUM' : 'LOW',
    message: `${isBlocked ? 'Blocked' : 'Allowed'} ${protoMatch ? protoMatch[1] : 'TCP'} connection from ${srcMatch ? srcMatch[1] : 'unknown'} to port ${dptMatch ? dptMatch[1] : 'unknown'}`,
    raw: line
  };
}

/**
 * 4. Parse Windows Event Logs (CSV or line format)
 */
function parseWindowsEventLine(line, index) {
  // Check if comma-separated: 2026-09-27 16:20:11, Security, 4625, Audit Failure, Microsoft-Windows-Security-Auditing, Account: admin, Source: 192.168.1.50
  const parts = line.split(',');
  if (parts.length >= 4) {
    const timestamp = parseLogTimestamp(parts[0].trim().replace(/^"|"$/g, ''));
    const eventIdMatch = line.match(/\b(4624|4625|4672|4720|4726|7045|1102)\b/);
    const eventId = eventIdMatch ? eventIdMatch[1] : (parts[2] ? parts[2].trim() : null);

    const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const userMatch = line.match(/(?:Account Name|TargetUserName|Account|User):\s*([^\s,;]+)/i);

    let action = 'WINDOWS_EVENT';
    let status = line.includes('Failure') || line.includes('4625') ? 'FAILURE' : 'SUCCESS';
    let category = 'SYSTEM';
    let severity = 'LOW';

    if (eventId === '4625' || line.includes('Audit Failure')) {
      action = 'AUTH_FAILED';
      status = 'FAILURE';
      category = 'AUTHENTICATION';
      severity = 'MEDIUM';
    } else if (eventId === '4624') {
      action = 'AUTH_SUCCESS';
      status = 'SUCCESS';
      category = 'AUTHENTICATION';
    } else if (eventId === '4720') {
      action = 'USER_CREATE';
      category = 'SYSTEM';
      severity = 'HIGH';
    } else if (eventId === '4726') {
      action = 'USER_DELETE';
      category = 'SYSTEM';
      severity = 'MEDIUM';
    } else if (eventId === '4672') {
      action = 'PRIVILEGE_USE';
      category = 'SYSTEM';
      severity = 'MEDIUM';
    }

    return {
      id: `entry-${index + 1}`,
      index: index + 1,
      timestamp,
      hostname: 'windows-server',
      service: 'Security-Auditing',
      sourceIp: ipMatch ? ipMatch[1] : null,
      targetIp: null,
      port: null,
      user: userMatch ? userMatch[1] : null,
      action,
      status,
      statusCode: eventId ? parseInt(eventId, 10) : null,
      method: null,
      path: null,
      category,
      severity,
      message: line.trim(),
      raw: line
    };
  }

  return parseGenericLine(line, index, 'SYSTEM');
}

/**
 * 5. Parse JSON line log
 */
function parseJsonLine(line, index) {
  try {
    const obj = JSON.parse(line);
    const timestampStr = obj.timestamp || obj.time || obj['@timestamp'] || obj.date || obj.datetime;
    const isoTime = parseLogTimestamp(timestampStr);

    const sourceIp = obj.ip || obj.sourceIp || obj.client_ip || obj.src_ip || obj.remote_addr || null;
    const user = obj.user || obj.username || obj.account || null;
    const action = obj.action || obj.event || obj.type || 'LOG_ENTRY';
    const statusCode = obj.status_code || obj.statusCode || obj.code || null;

    let status = obj.status || (statusCode && statusCode >= 400 ? 'FAILURE' : 'SUCCESS');
    if (typeof status === 'string') status = status.toUpperCase();

    let category = obj.category || 'SYSTEM';
    if (obj.method || obj.path || obj.url) category = 'WEB';
    if (action.includes('AUTH') || user) category = 'AUTHENTICATION';

    let severity = (obj.level || obj.severity || 'LOW').toUpperCase();
    if (severity === 'WARN' || severity === 'WARNING') severity = 'MEDIUM';
    if (severity === 'ERR' || severity === 'ERROR') severity = 'HIGH';

    return {
      id: `entry-${index + 1}`,
      index: index + 1,
      timestamp: isoTime,
      hostname: obj.host || obj.hostname || 'app',
      service: obj.service || obj.app || 'json-logger',
      sourceIp,
      targetIp: obj.dest_ip || obj.targetIp || null,
      port: obj.port || null,
      user,
      action,
      status: status || 'INFO',
      statusCode,
      method: obj.method || null,
      path: obj.path || obj.url || null,
      category,
      severity,
      message: obj.message || obj.msg || JSON.stringify(obj),
      raw: line
    };
  } catch {
    return parseGenericLine(line, index, 'SYSTEM');
  }
}

/**
 * 6. Fallback Generic Line Parser
 */
function parseGenericLine(line, index, defaultCategory = 'SYSTEM') {
  const tsMatch = line.match(/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})/);
  const timestamp = parseLogTimestamp(tsMatch ? tsMatch[1] : null);

  const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  const sourceIp = ipMatch ? ipMatch[1] : null;

  const isFail = /fail|error|denied|invalid|refused|drop|block/i.test(line);
  const isWarn = /warn|warning|suspicious|alert/i.test(line);

  let severity = 'LOW';
  if (isFail) severity = 'HIGH';
  else if (isWarn) severity = 'MEDIUM';

  return {
    id: `entry-${index + 1}`,
    index: index + 1,
    timestamp,
    hostname: 'host',
    service: 'syslog',
    sourceIp,
    targetIp: null,
    port: null,
    user: null,
    action: isFail ? 'ERROR_EVENT' : 'SYSTEM_INFO',
    status: isFail ? 'FAILURE' : 'SUCCESS',
    statusCode: null,
    method: null,
    path: null,
    category: defaultCategory,
    severity,
    message: line.trim(),
    raw: line
  };
}

/**
 * Main parser entry point
 * Takes a raw log string, splits into lines, detects format, and returns parsed entries.
 */
export function parseRawLogs(rawText, userFormat = 'AUTO') {
  if (!rawText || typeof rawText !== 'string') {
    return { format: 'UNKNOWN', entries: [], lineCount: 0 };
  }

  // Filter out blank lines
  const lines = rawText
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0);

  if (lines.length === 0) {
    return { format: 'EMPTY', entries: [], lineCount: 0 };
  }

  // Detect format if AUTO
  const detectedFormat = (userFormat && userFormat !== 'AUTO')
    ? userFormat
    : detectLogFormat(lines.slice(0, 30));

  const entries = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let parsed = null;

    switch (detectedFormat) {
      case 'APACHE_NGINX':
        parsed = parseApacheNginxLine(line, i);
        break;
      case 'LINUX_AUTH':
      case 'LINUX_SYSLOG':
        parsed = parseLinuxAuthLine(line, i);
        break;
      case 'FIREWALL':
        parsed = parseFirewallLine(line, i);
        break;
      case 'WINDOWS_EVENT':
        parsed = parseWindowsEventLine(line, i);
        break;
      case 'JSON':
        parsed = parseJsonLine(line, i);
        break;
      default:
        // Try Linux auth first, then fallback
        if (line.includes('sshd') || line.includes('sudo') || line.includes('Failed') || line.includes('Accepted')) {
          parsed = parseLinuxAuthLine(line, i);
        } else if (line.includes('HTTP/1.') || line.includes('"GET ') || line.includes('"POST ')) {
          parsed = parseApacheNginxLine(line, i);
        } else {
          parsed = parseGenericLine(line, i);
        }
        break;
    }

    if (parsed) {
      entries.push(parsed);
    }
  }

  // Sort chronologically if timestamps are valid
  entries.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return {
    format: detectedFormat,
    entries,
    lineCount: lines.length
  };
}
