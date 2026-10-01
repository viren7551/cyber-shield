/**
 * CyberShield Built-In Security Detection Rules Catalog
 * Maps patterns to MITRE ATT&CK techniques, severity levels, and remediation steps.
 */

export const DEFAULT_RULES = [
  {
    id: 'RULE_AUTH_COMPROMISED',
    name: 'Post-Brute-Force Successful Login (Compromised Account)',
    category: 'AUTHENTICATION',
    severity: 'CRITICAL',
    mitre: 'T1110 (Brute Force) & T1078 (Valid Accounts)',
    enabled: true,
    description: 'Multiple failed authentication attempts immediately followed by a successful login. Strong indicator of compromised credentials.',
    remediation: 'IMMEDIATE ACTION: Terminate active sessions for this user, force an emergency password reset, audit SSH authorized_keys, and quarantine the source IP.',
    type: 'CORRELATION_COMPROMISE',
    windowSeconds: 120,
    failThreshold: 2
  },
  {
    id: 'RULE_AUTH_BRUTE_FORCE',
    name: 'Authentication Brute Force Attempt',
    category: 'AUTHENTICATION',
    severity: 'HIGH',
    mitre: 'T1110.001 (Password Guessing)',
    enabled: true,
    description: 'Repeated failed logins detected from the same source IP address or targeting the same username.',
    remediation: 'Deploy Fail2ban/iptables rate-limiting, enforce SSH key-only authentication, and review target account locks.',
    type: 'THRESHOLD_FAILURES',
    windowSeconds: 60,
    failThreshold: 3
  },
  {
    id: 'RULE_ROOT_LOGIN',
    name: 'Direct Root Remote Login',
    category: 'AUTHENTICATION',
    severity: 'HIGH',
    mitre: 'T1078.003 (Local Accounts - Root)',
    enabled: true,
    description: 'Direct remote SSH/service login using the privileged root administrative account.',
    remediation: 'Set "PermitRootLogin no" in /etc/ssh/sshd_config and require standard user login followed by audited sudo.',
    type: 'ROOT_LOGIN',
    enabled: true
  },
  {
    id: 'RULE_CREDENTIAL_STUFFING',
    name: 'Credential Stuffing / User Enumeration',
    category: 'AUTHENTICATION',
    severity: 'HIGH',
    mitre: 'T1110.004 (Credential Stuffing)',
    enabled: true,
    description: 'Single source IP attempting logins with multiple different usernames within a short timeframe.',
    remediation: 'Apply IP-based rate limiting on authentication endpoints, introduce CAPTCHA, and notify targeted users.',
    type: 'MULTI_USER_FAILURES',
    windowSeconds: 90,
    userThreshold: 3
  },
  {
    id: 'RULE_WEB_EXPLOIT',
    name: 'Web Application Attack Injection (SQLi / Traversal / RCE)',
    category: 'WEB',
    severity: 'CRITICAL',
    mitre: 'T1190 (Exploit Public-Facing Application)',
    enabled: true,
    description: 'Signature-based detection of SQL injection, directory traversal (/etc/passwd, ../..), or sensitive credential probes (.env, wp-config).',
    remediation: 'Use parameterized queries, sanitize web inputs, block path traversal at the web server layer, and block the IP.',
    type: 'WEB_INJECTION',
    enabled: true
  },
  {
    id: 'RULE_WEB_FUZZING',
    name: 'Web Directory Fuzzing / Probing Spikes',
    category: 'WEB',
    severity: 'MEDIUM',
    mitre: 'T1595.002 (Active Scanning - Vulnerability Scanning)',
    enabled: true,
    description: 'High frequency of HTTP 404 / 403 status codes from a single IP indicating automated content discovery.',
    remediation: 'Implement automatic temporary IP banning via WAF, Nginx fail2ban filter, or Cloudflare rate limiting rules.',
    type: 'STATUS_SPIKE',
    windowSeconds: 60,
    statusCodeThreshold: 5,
    statusCodes: [404, 403, 401]
  },
  {
    id: 'RULE_HTTP_FLOOD',
    name: 'Excessive HTTP Request Rate / Potential DoS',
    category: 'WEB',
    severity: 'MEDIUM',
    mitre: 'T1499 (Endpoint Denial of Service)',
    enabled: true,
    description: 'Abnormally high volume of HTTP requests from a single source IP exceeding regular traffic limits.',
    remediation: 'Configure Nginx limit_req zone, enable Cloudflare Under Attack mode, or deploy web layer rate limits.',
    type: 'HIGH_RATE',
    windowSeconds: 30,
    requestThreshold: 25
  },
  {
    id: 'RULE_PORT_SCAN',
    name: 'Port Scanning / Network Reconnaissance',
    category: 'NETWORK',
    severity: 'MEDIUM',
    mitre: 'T1046 (Network Service Discovery)',
    enabled: true,
    description: 'Single IP address triggering multiple firewall drops or probing multiple distinct destination ports.',
    remediation: 'Drop source IP in upstream firewall/security group, review exposed port forwardings, and disable unneeded services.',
    type: 'PORT_SCAN',
    windowSeconds: 60,
    portThreshold: 3
  },
  {
    id: 'RULE_PRIV_ESCALATION',
    name: 'Privilege Escalation Activity (Sudo / Su)',
    category: 'SYSTEM',
    severity: 'HIGH',
    mitre: 'T1548.003 (Sudo and Sudo Caching)',
    enabled: true,
    description: 'Sensitive root command executed via sudo, or authentication failure attempting to switch to root user (su).',
    remediation: 'Review /etc/sudoers file, audit active sessions, inspect user bash history (.bash_history), and enforce MFA.',
    type: 'PRIVILEGE_USE',
    enabled: true
  },
  {
    id: 'RULE_ACCOUNT_CREATION',
    name: 'System Account Creation or Deletion',
    category: 'SYSTEM',
    severity: 'MEDIUM',
    mitre: 'T1136 (Create Account)',
    enabled: true,
    description: 'System user account creation or deletion event detected in logs (useradd, userdel, Windows Event 4720).',
    remediation: 'Confirm with DevOps/System administrators that this user creation was scheduled and authorized.',
    type: 'ACCOUNT_MGMT',
    enabled: true
  }
];
