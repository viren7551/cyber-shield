/**
 * CyberShield Security Rules & Correlation Engine
 * Analyzes normalized log entries to detect attacks, brute-force chains,
 * credential compromise, web fuzzing, privilege escalations, and custom user rules.
 */

// Helper: Calculate elapsed seconds between two ISO date strings
function getDiffSeconds(dateA, dateB) {
  const tA = new Date(dateA).getTime();
  const tB = new Date(dateB).getTime();
  return Math.abs(Math.round((tA - tB) / 1000));
}

// SQL injection, path traversal, and sensitive file regex patterns
const INJECTION_PATTERNS = [
  { name: 'SQL Injection', regex: /(?:union\s+select|select\s+.*\s+from|'\s*or\s*'1'='1|--|;\s*drop\s+table|information_schema|sleep\(\d+\))/i },
  { name: 'Path Traversal', regex: /(?:\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i },
  { name: 'Sensitive File Access', regex: /(?:\.env|\.git\/|wp-config\.php|phpinfo\.php|web\.config|\/proc\/self\/)/i },
  { name: 'Cross-Site Scripting (XSS)', regex: /(?:<script|javascript:|onerror\s*=|onload\s*=|alert\(|prompt\()/i },
  { name: 'Command Injection', regex: /(?:;\s*cat\s+\/|\|\s*nc\s+|;\s*wget\s+|;\s*curl\s+|\$\(id\)|`id`)/i }
];

export function runRuleEngine(entries = [], activeRules = []) {
  const alerts = [];
  const rulesMap = new Map();
  activeRules.forEach(r => rulesMap.set(r.id, r));

  // Sort entries chronologically to ensure accurate window calculation
  const sorted = [...entries].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Group entries by Source IP for correlation
  const ipGroups = new Map();
  sorted.forEach(entry => {
    const ip = entry.sourceIp || 'unknown';
    if (!ipGroups.has(ip)) ipGroups.set(ip, []);
    ipGroups.get(ip).push(entry);
  });

  // Group entries by Username
  const userGroups = new Map();
  sorted.forEach(entry => {
    if (entry.user) {
      if (!userGroups.has(entry.user)) userGroups.set(entry.user, []);
      userGroups.get(entry.user).push(entry);
    }
  });

  // -------------------------------------------------------------
  // RULE 1: POST-BRUTE-FORCE SUCCESSFUL AUTH (COMPROMISED ACCOUNT)
  // (Multiple failed logins followed by successful authentication)
  // -------------------------------------------------------------
  const ruleCompromise = rulesMap.get('RULE_AUTH_COMPROMISED');
  if (ruleCompromise && ruleCompromise.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;

      let consecutiveFails = [];
      for (let i = 0; i < groupEntries.length; i++) {
        const item = groupEntries[i];

        if (item.action === 'AUTH_FAILED') {
          consecutiveFails.push(item);
        } else if (item.action === 'AUTH_SUCCESS') {
          if (consecutiveFails.length >= (ruleCompromise.failThreshold || 2)) {
            const firstFailTime = consecutiveFails[0].timestamp;
            const successTime = item.timestamp;
            const diffSeconds = getDiffSeconds(firstFailTime, successTime);

            if (diffSeconds <= (ruleCompromise.windowSeconds || 120)) {
              const targetUser = item.user || consecutiveFails[consecutiveFails.length - 1].user || 'Unknown';
              const alertId = `ALERT-COMPROMISE-${ip}-${item.id}`;

              alerts.push({
                id: alertId,
                ruleId: ruleCompromise.id,
                title: 'Multiple failed logins followed by successful authentication',
                category: 'AUTHENTICATION',
                severity: 'CRITICAL',
                riskScore: 95,
                mitre: ruleCompromise.mitre,
                description: `Potential Credential Compromise: Source IP ${ip} failed ${consecutiveFails.length} login attempt(s) for user '${targetUser}' before successfully authenticating within ${diffSeconds} seconds.`,
                remediation: ruleCompromise.remediation,
                sourceIp: ip,
                user: targetUser,
                evidence: {
                  sourceIp: ip,
                  username: targetUser,
                  failedAttempts: consecutiveFails.length,
                  successfulLogin: 'Yes',
                  timeRange: `${diffSeconds} seconds`,
                  triggerTimestamp: successTime,
                  relatedEventIds: [...consecutiveFails.map(f => f.id), item.id],
                  sampleLogs: [
                    ...consecutiveFails.slice(-3).map(f => f.raw || f.message),
                    item.raw || item.message
                  ]
                }
              });

              // Tag events with alert ID
              consecutiveFails.forEach(f => f.alertId = alertId);
              item.alertId = alertId;
            }
          }
          // Reset fails counter after success
          consecutiveFails = [];
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 2: AUTHENTICATION BRUTE FORCE (THRESHOLD OF FAILURES)
  // -------------------------------------------------------------
  const ruleBruteForce = rulesMap.get('RULE_AUTH_BRUTE_FORCE');
  if (ruleBruteForce && ruleBruteForce.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;

      const failedLogins = groupEntries.filter(e => e.action === 'AUTH_FAILED');
      if (failedLogins.length >= (ruleBruteForce.failThreshold || 3)) {
        // Sliding window check
        for (let i = 0; i <= failedLogins.length - ruleBruteForce.failThreshold; i++) {
          const start = failedLogins[i];
          const end = failedLogins[i + ruleBruteForce.failThreshold - 1];
          const diff = getDiffSeconds(start.timestamp, end.timestamp);

          if (diff <= (ruleBruteForce.windowSeconds || 60)) {
            // Check if this window was already flagged as compromise
            const alreadyCompromised = alerts.some(a => a.ruleId === 'RULE_AUTH_COMPROMISED' && a.sourceIp === ip);
            if (!alreadyCompromised) {
              const usersTargeted = [...new Set(failedLogins.map(f => f.user).filter(Boolean))];
              const alertId = `ALERT-BRUTEFORCE-${ip}-${start.id}`;

              alerts.push({
                id: alertId,
                ruleId: ruleBruteForce.id,
                title: 'Brute-force authentication pattern detected',
                category: 'AUTHENTICATION',
                severity: 'HIGH',
                riskScore: 82,
                mitre: ruleBruteForce.mitre,
                description: `IP address ${ip} generated ${failedLogins.length} failed login attempts targeting account(s): ${usersTargeted.join(', ') || 'unknown'}.`,
                remediation: ruleBruteForce.remediation,
                sourceIp: ip,
                user: usersTargeted.join(', ') || 'Multiple',
                evidence: {
                  sourceIp: ip,
                  username: usersTargeted.join(', ') || 'N/A',
                  failedAttempts: failedLogins.length,
                  successfulLogin: 'No',
                  timeRange: `${diff} seconds`,
                  triggerTimestamp: end.timestamp,
                  relatedEventIds: failedLogins.slice(i, i + ruleBruteForce.failThreshold).map(f => f.id),
                  sampleLogs: failedLogins.slice(i, i + 4).map(f => f.raw || f.message)
                }
              });

              failedLogins.forEach(f => { if (!f.alertId) f.alertId = alertId; });
              break; // One alert per IP window is sufficient
            }
          }
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 3: DIRECT ROOT REMOTE LOGIN
  // -------------------------------------------------------------
  const ruleRoot = rulesMap.get('RULE_ROOT_LOGIN');
  if (ruleRoot && ruleRoot.enabled !== false) {
    sorted.forEach(entry => {
      if (entry.action === 'AUTH_SUCCESS' && (entry.user === 'root' || entry.user === 'administrator')) {
        const isExternal = entry.sourceIp && !['127.0.0.1', 'localhost', '::1'].includes(entry.sourceIp);
        if (isExternal) {
          const alertId = `ALERT-ROOT-${entry.id}`;
          alerts.push({
            id: alertId,
            ruleId: ruleRoot.id,
            title: `Direct remote login into ${entry.user} account`,
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            riskScore: 78,
            mitre: ruleRoot.mitre,
            description: `Direct administrative remote authentication for privileged account '${entry.user}' from external IP ${entry.sourceIp}.`,
            remediation: ruleRoot.remediation,
            sourceIp: entry.sourceIp,
            user: entry.user,
            evidence: {
              sourceIp: entry.sourceIp,
              username: entry.user,
              failedAttempts: 0,
              successfulLogin: 'Yes',
              timeRange: 'Instant',
              triggerTimestamp: entry.timestamp,
              relatedEventIds: [entry.id],
              sampleLogs: [entry.raw || entry.message]
            }
          });
          entry.alertId = alertId;
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 4: CREDENTIAL STUFFING / USER ENUMERATION
  // -------------------------------------------------------------
  const ruleStuffing = rulesMap.get('RULE_CREDENTIAL_STUFFING');
  if (ruleStuffing && ruleStuffing.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;
      const fails = groupEntries.filter(e => e.action === 'AUTH_FAILED' || e.action === 'AUTH_INVALID_USER');
      const uniqueUsers = new Set(fails.map(e => e.user).filter(Boolean));

      if (uniqueUsers.size >= (ruleStuffing.userThreshold || 3)) {
        const alertId = `ALERT-STUFFING-${ip}`;
        // Avoid duplicate if already covered
        if (!alerts.some(a => a.ruleId === ruleStuffing.id && a.sourceIp === ip)) {
          alerts.push({
            id: alertId,
            ruleId: ruleStuffing.id,
            title: 'Credential stuffing / username enumeration pattern',
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            riskScore: 85,
            mitre: ruleStuffing.mitre,
            description: `Source IP ${ip} attempted logins against ${uniqueUsers.size} distinct usernames: [${Array.from(uniqueUsers).slice(0, 5).join(', ')}].`,
            remediation: ruleStuffing.remediation,
            sourceIp: ip,
            user: `${uniqueUsers.size} distinct users`,
            evidence: {
              sourceIp: ip,
              username: Array.from(uniqueUsers).join(', '),
              failedAttempts: fails.length,
              successfulLogin: 'No',
              timeRange: 'N/A',
              triggerTimestamp: fails[fails.length - 1].timestamp,
              relatedEventIds: fails.map(f => f.id),
              sampleLogs: fails.slice(0, 4).map(f => f.raw || f.message)
            }
          });
          fails.forEach(f => { if (!f.alertId) f.alertId = alertId; });
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 5: WEB APPLICATION ATTACK INJECTION (SQLi, Traversal, XSS, etc.)
  // -------------------------------------------------------------
  const ruleWebExploit = rulesMap.get('RULE_WEB_EXPLOIT');
  if (ruleWebExploit && ruleWebExploit.enabled !== false) {
    sorted.forEach(entry => {
      if (entry.category === 'WEB' || entry.path || entry.raw) {
        const textToScan = `${entry.path || ''} ${entry.raw || ''}`;

        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.regex.test(textToScan)) {
            const alertId = `ALERT-EXPLOIT-${pattern.name.replace(/\s+/g, '')}-${entry.id}`;
            alerts.push({
              id: alertId,
              ruleId: ruleWebExploit.id,
              title: `${pattern.name} attempt detected`,
              category: 'WEB',
              severity: 'CRITICAL',
              riskScore: 92,
              mitre: ruleWebExploit.mitre,
              description: `Malicious request payload matching ${pattern.name} signature detected from IP ${entry.sourceIp || 'unknown'}: ${entry.path || entry.message}`,
              remediation: ruleWebExploit.remediation,
              sourceIp: entry.sourceIp,
              user: entry.user || 'Web Visitor',
              evidence: {
                sourceIp: entry.sourceIp || 'N/A',
                username: entry.user || 'None',
                failedAttempts: 0,
                successfulLogin: 'N/A',
                attackType: pattern.name,
                payloadSample: entry.path || entry.message,
                triggerTimestamp: entry.timestamp,
                relatedEventIds: [entry.id],
                sampleLogs: [entry.raw || entry.message]
              }
            });
            entry.alertId = alertId;
            break;
          }
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 6: WEB DIRECTORY FUZZING / EXCESSIVE 404 & 403 STATUS CODES
  // -------------------------------------------------------------
  const ruleFuzzing = rulesMap.get('RULE_WEB_FUZZING');
  if (ruleFuzzing && ruleFuzzing.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;

      const notFoundOrForbidden = groupEntries.filter(e => [404, 403, 401].includes(e.statusCode));
      if (notFoundOrForbidden.length >= (ruleFuzzing.statusCodeThreshold || 5)) {
        const alertId = `ALERT-FUZZ-${ip}`;
        if (!alerts.some(a => a.ruleId === ruleFuzzing.id && a.sourceIp === ip)) {
          alerts.push({
            id: alertId,
            ruleId: ruleFuzzing.id,
            title: 'Excessive 404/403 responses (Automated directory discovery)',
            category: 'WEB',
            severity: 'MEDIUM',
            riskScore: 68,
            mitre: ruleFuzzing.mitre,
            description: `IP address ${ip} triggered ${notFoundOrForbidden.length} HTTP 404/403 responses, indicating automated directory brute-forcing or vulnerability scanning.`,
            remediation: ruleFuzzing.remediation,
            sourceIp: ip,
            user: 'Anonymous',
            evidence: {
              sourceIp: ip,
              username: 'N/A',
              failedAttempts: notFoundOrForbidden.length,
              successfulLogin: 'No',
              timeRange: `${getDiffSeconds(notFoundOrForbidden[0].timestamp, notFoundOrForbidden[notFoundOrForbidden.length - 1].timestamp)} seconds`,
              triggerTimestamp: notFoundOrForbidden[notFoundOrForbidden.length - 1].timestamp,
              relatedEventIds: notFoundOrForbidden.map(e => e.id),
              sampleLogs: notFoundOrForbidden.slice(0, 4).map(e => e.raw || e.message)
            }
          });
          notFoundOrForbidden.forEach(e => { if (!e.alertId) e.alertId = alertId; });
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 7: EXCESSIVE HTTP FLOOD / POTENTIAL DOS
  // -------------------------------------------------------------
  const ruleFlood = rulesMap.get('RULE_HTTP_FLOOD');
  if (ruleFlood && ruleFlood.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;
      const webRequests = groupEntries.filter(e => e.category === 'WEB');
      if (webRequests.length >= (ruleFlood.requestThreshold || 25)) {
        const diff = getDiffSeconds(webRequests[0].timestamp, webRequests[webRequests.length - 1].timestamp);
        if (diff <= (ruleFlood.windowSeconds || 30)) {
          const alertId = `ALERT-FLOOD-${ip}`;
          if (!alerts.some(a => a.ruleId === ruleFlood.id && a.sourceIp === ip)) {
            alerts.push({
              id: alertId,
              ruleId: ruleFlood.id,
              title: 'Excessive HTTP request rate / Request flood pattern',
              category: 'WEB',
              severity: 'MEDIUM',
              riskScore: 65,
              mitre: ruleFlood.mitre,
              description: `Source IP ${ip} dispatched ${webRequests.length} requests in ${diff}s, exceeding safety thresholds.`,
              remediation: ruleFlood.remediation,
              sourceIp: ip,
              user: 'N/A',
              evidence: {
                sourceIp: ip,
                username: 'N/A',
                failedAttempts: 0,
                successfulLogin: 'N/A',
                timeRange: `${diff} seconds`,
                triggerTimestamp: webRequests[webRequests.length - 1].timestamp,
                relatedEventIds: webRequests.map(r => r.id),
                sampleLogs: webRequests.slice(0, 3).map(r => r.raw || r.message)
              }
            });
            webRequests.forEach(r => { if (!r.alertId) r.alertId = alertId; });
          }
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 8: PORT SCANNING / NETWORK DROPS
  // -------------------------------------------------------------
  const rulePortScan = rulesMap.get('RULE_PORT_SCAN');
  if (rulePortScan && rulePortScan.enabled !== false) {
    ipGroups.forEach((groupEntries, ip) => {
      if (ip === 'unknown') return;
      const drops = groupEntries.filter(e => e.category === 'NETWORK' && (e.action === 'FIREWALL_DROP' || e.status === 'BLOCKED'));
      const distinctPorts = new Set(drops.map(e => e.port).filter(Boolean));

      if (distinctPorts.size >= (rulePortScan.portThreshold || 3)) {
        const alertId = `ALERT-PORTSCAN-${ip}`;
        if (!alerts.some(a => a.ruleId === rulePortScan.id && a.sourceIp === ip)) {
          alerts.push({
            id: alertId,
            ruleId: rulePortScan.id,
            title: 'Port-scan-like connection reconnaissance pattern',
            category: 'NETWORK',
            severity: 'MEDIUM',
            riskScore: 70,
            mitre: rulePortScan.mitre,
            description: `Host ${ip} systematically targeted ${distinctPorts.size} distinct ports [${Array.from(distinctPorts).join(', ')}].`,
            remediation: rulePortScan.remediation,
            sourceIp: ip,
            user: 'N/A',
            evidence: {
              sourceIp: ip,
              username: 'N/A',
              failedAttempts: drops.length,
              successfulLogin: 'No',
              targetedPorts: Array.from(distinctPorts),
              triggerTimestamp: drops[drops.length - 1].timestamp,
              relatedEventIds: drops.map(d => d.id),
              sampleLogs: drops.slice(0, 4).map(d => d.raw || d.message)
            }
          });
          drops.forEach(d => { if (!d.alertId) d.alertId = alertId; });
        }
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 9: PRIVILEGE ESCALATION (SUDO / SU)
  // -------------------------------------------------------------
  const rulePriv = rulesMap.get('RULE_PRIV_ESCALATION');
  if (rulePriv && rulePriv.enabled !== false) {
    sorted.forEach(entry => {
      if (entry.action === 'SUDO_ROOT_EXEC' || (entry.action === 'SU_ATTEMPT' && entry.status === 'FAILURE')) {
        const alertId = `ALERT-PRIV-${entry.id}`;
        alerts.push({
          id: alertId,
          ruleId: rulePriv.id,
          title: entry.action === 'SUDO_ROOT_EXEC' ? 'Root privilege command execution via sudo' : 'Unauthorized su root elevation attempt',
          category: 'SYSTEM',
          severity: entry.action === 'SUDO_ROOT_EXEC' ? 'HIGH' : 'HIGH',
          riskScore: 75,
          mitre: rulePriv.mitre,
          description: `Privilege boundary event: user '${entry.user || 'unknown'}' engaged in root privilege action: ${entry.message}`,
          remediation: rulePriv.remediation,
          sourceIp: entry.sourceIp || 'Localhost',
          user: entry.user || 'Unknown',
          evidence: {
            sourceIp: entry.sourceIp || '127.0.0.1',
            username: entry.user || 'Unknown',
            failedAttempts: entry.status === 'FAILURE' ? 1 : 0,
            successfulLogin: 'N/A',
            triggerTimestamp: entry.timestamp,
            relatedEventIds: [entry.id],
            sampleLogs: [entry.raw || entry.message]
          }
        });
        entry.alertId = alertId;
      }
    });
  }

  // -------------------------------------------------------------
  // RULE 10: ACCOUNT CREATION / DELETION
  // -------------------------------------------------------------
  const ruleAccount = rulesMap.get('RULE_ACCOUNT_CREATION');
  if (ruleAccount && ruleAccount.enabled !== false) {
    sorted.forEach(entry => {
      if (entry.action === 'USER_CREATE' || entry.action === 'USER_DELETE') {
        const alertId = `ALERT-ACCT-${entry.id}`;
        alerts.push({
          id: alertId,
          ruleId: ruleAccount.id,
          title: entry.action === 'USER_CREATE' ? 'System account created' : 'System account deleted',
          category: 'SYSTEM',
          severity: 'MEDIUM',
          riskScore: 60,
          mitre: ruleAccount.mitre,
          description: `User account modification observed: ${entry.action} for account '${entry.user || 'unknown'}'.`,
          remediation: ruleAccount.remediation,
          sourceIp: entry.sourceIp || 'Localhost',
          user: entry.user,
          evidence: {
            sourceIp: entry.sourceIp || '127.0.0.1',
            username: entry.user || 'N/A',
            failedAttempts: 0,
            successfulLogin: 'N/A',
            triggerTimestamp: entry.timestamp,
            relatedEventIds: [entry.id],
            sampleLogs: [entry.raw || entry.message]
          }
        });
        entry.alertId = alertId;
      }
    });
  }

  // -------------------------------------------------------------
  // USER-DEFINED CUSTOM RULES EVALUATION
  // -------------------------------------------------------------
  const customRules = activeRules.filter(r => r.id.startsWith('custom-') || r.isCustom);
  customRules.forEach(rule => {
    if (rule.enabled === false) return;

    const threshold = parseInt(rule.threshold || 1, 10);
    const windowSecs = parseInt(rule.windowSeconds || 60, 10);

    // Matching filter function
    const matchesRule = (entry) => {
      const fieldVal = entry[rule.field] !== undefined ? String(entry[rule.field]) : '';
      const targetVal = String(rule.value || '');

      switch (rule.operator) {
        case 'equals':
          return fieldVal.toLowerCase() === targetVal.toLowerCase();
        case 'contains':
          return fieldVal.toLowerCase().includes(targetVal.toLowerCase());
        case 'regex':
          try {
            return new RegExp(targetVal, 'i').test(fieldVal);
          } catch {
            return false;
          }
        case 'greater_than':
          return parseFloat(fieldVal) > parseFloat(targetVal);
        default:
          return fieldVal.toLowerCase().includes(targetVal.toLowerCase());
      }
    };

    if (rule.groupBy === 'sourceIp') {
      ipGroups.forEach((groupEntries, ip) => {
        if (ip === 'unknown') return;
        const matching = groupEntries.filter(matchesRule);
        if (matching.length >= threshold) {
          const alertId = `ALERT-${rule.id}-${ip}`;
          alerts.push({
            id: alertId,
            ruleId: rule.id,
            title: rule.name || 'Custom Security Alert',
            category: rule.category || 'CUSTOM',
            severity: rule.severity || 'HIGH',
            riskScore: rule.severity === 'CRITICAL' ? 90 : rule.severity === 'HIGH' ? 75 : 50,
            mitre: rule.mitre || 'Custom Rule',
            description: rule.description || `Custom rule triggered: ${matching.length} matching events from IP ${ip}.`,
            remediation: rule.remediation || 'Inspect matching event logs and source IP behavior.',
            sourceIp: ip,
            user: matching[0].user || 'N/A',
            evidence: {
              sourceIp: ip,
              username: matching[0].user || 'N/A',
              failedAttempts: matching.length,
              successfulLogin: 'N/A',
              triggerTimestamp: matching[matching.length - 1].timestamp,
              relatedEventIds: matching.map(m => m.id),
              sampleLogs: matching.slice(0, 3).map(m => m.raw || m.message)
            }
          });
          matching.forEach(m => { if (!m.alertId) m.alertId = alertId; });
        }
      });
    } else {
      // Global evaluation
      const matching = sorted.filter(matchesRule);
      if (matching.length >= threshold) {
        const alertId = `ALERT-${rule.id}-global`;
        alerts.push({
          id: alertId,
          ruleId: rule.id,
          title: rule.name || 'Custom Security Alert',
          category: rule.category || 'CUSTOM',
          severity: rule.severity || 'HIGH',
          riskScore: rule.severity === 'CRITICAL' ? 90 : rule.severity === 'HIGH' ? 75 : 50,
          mitre: rule.mitre || 'Custom Rule',
          description: rule.description || `Custom rule triggered with ${matching.length} matching event(s).`,
          remediation: rule.remediation || 'Investigate matching log events.',
          sourceIp: matching[0]?.sourceIp || 'Multiple',
          user: matching[0]?.user || 'Multiple',
          evidence: {
            sourceIp: matching[0]?.sourceIp || 'N/A',
            username: matching[0]?.user || 'N/A',
            failedAttempts: matching.length,
            successfulLogin: 'N/A',
            triggerTimestamp: matching[matching.length - 1]?.timestamp,
            relatedEventIds: matching.map(m => m.id),
            sampleLogs: matching.slice(0, 3).map(m => m.raw || m.message)
          }
        });
        matching.forEach(m => { if (!m.alertId) m.alertId = alertId; });
      }
    }
  });

  return {
    alerts,
    updatedEntries: sorted
  };
}
