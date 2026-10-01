/**
 * CyberShield Sample Logs Catalog
 * Provides authentic, high-fidelity sample logs for one-click testing and verification.
 */

export const SAMPLE_LOGS = [
  {
    id: 'sample-ssh-compromise',
    title: 'Linux SSH Brute Force & Compromise (Prompt Scenario)',
    format: 'LINUX_AUTH',
    description: 'Multiple failed password attempts followed immediately by accepted authentication for user admin, plus root escalation and credential stuffing.',
    expectedAlerts: ['Post-Brute-Force Successful Login', 'Credential Stuffing', 'Root privilege command execution'],
    raw: `Sep 27 16:20:11 server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2
Sep 27 16:20:15 server sshd[1235]: Failed password for admin from 192.168.1.50 port 54322 ssh2
Sep 27 16:20:18 server sshd[1236]: Failed password for admin from 192.168.1.50 port 54323 ssh2
Sep 27 16:20:25 server sshd[1237]: Accepted password for admin from 192.168.1.50 port 54324 ssh2
Sep 27 16:21:00 server sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Sep 27 16:21:10 server sshd[1240]: Failed password for invalid user oracle from 10.0.0.24 port 41201 ssh2
Sep 27 16:21:12 server sshd[1241]: Failed password for invalid user postgres from 10.0.0.24 port 41202 ssh2
Sep 27 16:21:15 server sshd[1242]: Failed password for invalid user deploy from 10.0.0.24 port 41203 ssh2
Sep 27 16:21:18 server sshd[1243]: Failed password for invalid user test from 10.0.0.24 port 41204 ssh2
Sep 27 16:22:05 server sshd[1250]: Accepted publickey for root from 172.16.0.15 port 39820 ssh2
Sep 27 16:23:45 server useradd[2400]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash`
  },
  {
    id: 'sample-nginx-attack',
    title: 'Nginx Web Server Attack & Directory Fuzzing',
    format: 'APACHE_NGINX',
    description: 'Automated directory fuzzing with repeated 404/403 responses, SQL Injection attack, path traversal exploit, and sensitive file probes (.env, .git).',
    expectedAlerts: ['SQL Injection attempt', 'Path Traversal attempt', 'Sensitive File Access', 'Excessive 404/403 responses'],
    raw: `192.168.1.50 - - [27/Sep/2026:16:20:10 +0000] "GET /index.html HTTP/1.1" 200 4521 "https://google.com" "Mozilla/5.0"
192.168.1.50 - - [27/Sep/2026:16:20:11 +0000] "GET /wp-login.php HTTP/1.1" 404 1234 "-" "curl/7.81.0"
192.168.1.50 - - [27/Sep/2026:16:20:12 +0000] "GET /admin.php HTTP/1.1" 404 1234 "-" "curl/7.81.0"
192.168.1.50 - - [27/Sep/2026:16:20:13 +0000] "GET /administrator/index.php HTTP/1.1" 404 1234 "-" "curl/7.81.0"
192.168.1.50 - - [27/Sep/2026:16:20:14 +0000] "GET /.env HTTP/1.1" 403 234 "-" "curl/7.81.0"
192.168.1.50 - - [27/Sep/2026:16:20:15 +0000] "GET /config.json HTTP/1.1" 404 1234 "-" "curl/7.81.0"
192.168.1.50 - - [27/Sep/2026:16:20:16 +0000] "GET /.git/HEAD HTTP/1.1" 403 234 "-" "curl/7.81.0"
10.0.0.24 - - [27/Sep/2026:16:20:20 +0000] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 892 "-" "sqlmap/1.6"
172.16.0.15 - - [27/Sep/2026:16:20:25 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 312 "-" "Mozilla/5.0"
172.16.0.15 - - [27/Sep/2026:16:20:30 +0000] "POST /feedback HTTP/1.1" 200 45 "http://site.com" "<script>alert('xss')</script>"`
  },
  {
    id: 'sample-firewall-recon',
    title: 'Firewall Network Port Scan & Reconnaissance',
    format: 'FIREWALL',
    description: 'Systematic TCP SYN port scan across multiple common service ports (FTP, SSH, Telnet, HTTP, HTTPS, RDP).',
    expectedAlerts: ['Port-scan-like connection reconnaissance pattern'],
    raw: `Sep 27 16:20:11 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51234 DPT=21 WINDOW=1024 SYN
Sep 27 16:20:12 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51235 DPT=22 WINDOW=1024 SYN
Sep 27 16:20:13 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51236 DPT=23 WINDOW=1024 SYN
Sep 27 16:20:14 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51237 DPT=80 WINDOW=1024 SYN
Sep 27 16:20:15 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51238 DPT=443 WINDOW=1024 SYN
Sep 27 16:20:16 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=51239 DPT=3389 WINDOW=1024 SYN`
  },
  {
    id: 'sample-windows-events',
    title: 'Windows Security Event Logs (Logon & User Management)',
    format: 'WINDOWS_EVENT',
    description: 'Event ID 4625 failed logons leading to 4624 successful logon, special privileges assignment (4672), and backdoor user creation (4720).',
    expectedAlerts: ['Post-Brute-Force Successful Login', 'System account created'],
    raw: `2026-09-27 16:20:11, Security, 4625, Audit Failure, Microsoft-Windows-Security-Auditing, An account failed to log on. Account: admin, Source Network Address: 192.168.1.50
2026-09-27 16:20:15, Security, 4625, Audit Failure, Microsoft-Windows-Security-Auditing, An account failed to log on. Account: admin, Source Network Address: 192.168.1.50
2026-09-27 16:20:18, Security, 4625, Audit Failure, Microsoft-Windows-Security-Auditing, An account failed to log on. Account: admin, Source Network Address: 192.168.1.50
2026-09-27 16:20:25, Security, 4624, Audit Success, Microsoft-Windows-Security-Auditing, An account was successfully logged on. Account: admin, Source Network Address: 192.168.1.50
2026-09-27 16:22:00, Security, 4720, Audit Success, User Account Management, A user account was created. Account: temp_backdoor
2026-09-27 16:23:00, Security, 4672, Audit Success, Privilege Use, Special privileges assigned to new logon. Account: admin`
  }
];
