/**
 * CyberShield Web Security Scanner - Comprehensive Report Generator
 * Exports security audit findings as Executive Summary, Technical Findings,
 * and Configuration Appendix in JSON, Print-Ready HTML, and Markdown formats.
 */

/**
 * Generate full JSON report
 */
export function generateJsonReport(scan, findings = [], endpoints = []) {
  return {
    metadata: {
      generator: 'CyberShield Web Security Scanner v1.0',
      timestamp: new Date().toISOString(),
      reportId: `CSR-${scan.id || Date.now()}`
    },
    executiveSummary: {
      targetUrl: scan.target,
      scanProfile: scan.profile,
      status: scan.status,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      durationMs: scan.duration,
      riskScore: scan.riskScore,
      statistics: scan.statistics
    },
    technicalFindings: findings.map(f => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      cwe: f.cwe,
      owasp: f.owasp,
      status: f.status,
      affectedUrls: f.affectedUrls,
      description: f.description,
      impact: f.impact,
      recommendation: f.recommendation,
      evidence: f.evidence,
      references: f.references
    })),
    appendix: {
      technologies: scan.targetInfo?.technologies || [],
      tls: scan.targetInfo?.tls || null,
      headers: scan.targetInfo?.headerAudit || null,
      cookies: scan.targetInfo?.cookies || [],
      workingEndpoints: endpoints.filter(e => (e.statusCode >= 200 && e.statusCode < 400) || e.isWorking).slice(0, 50),
      parameterizedUrls: (scan.targetInfo?.parameterizedUrls || endpoints.filter(e => e.isParameterized || (e.url && e.url.includes('?')))).slice(0, 50)
    }
  };
}

/**
 * Generate Markdown report
 */
export function generateMarkdownReport(scan, findings = [], endpoints = []) {
  const stats = scan.statistics || {};
  const counts = stats.counts || {};
  const workingEndpoints = endpoints.filter(e => (e.statusCode >= 200 && e.statusCode < 400) || e.isWorking);
  const parameterizedUrls = scan.targetInfo?.parameterizedUrls || endpoints.filter(e => e.isParameterized || (e.url && e.url.includes('?')));

  let md = `# CyberShield Web Security Audit Report\n\n`;
  md += `**Target URL:** ${scan.target}  \n`;
  md += `**Scan Profile:** ${scan.profile}  \n`;
  md += `**Date:** ${new Date(scan.startedAt).toUTCString()}  \n`;
  md += `**Overall Risk Score:** ${scan.riskScore}/100 (${stats.grade || 'N/A'})  \n`;
  md += `**Security Posture:** ${stats.posture || 'Audited'}  \n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `The target application **${scan.target}** was passively assessed for web security misconfigurations, missing protective headers, SSL/TLS flaws, and sensitive data leakage.\n\n`;
  md += `| Severity | Finding Count |\n`;
  md += `| :--- | :---: |\n`;
  md += `| 🔴 Critical | ${counts.Critical || 0} |\n`;
  md += `| 🟠 High | ${counts.High || 0} |\n`;
  md += `| 🟡 Medium | ${counts.Medium || 0} |\n`;
  md += `| 🔵 Low | ${counts.Low || 0} |\n`;
  md += `| ⚪ Informational | ${counts.Informational || 0} |\n`;
  md += `| **Total** | **${findings.length}** |\n\n`;

  md += `## 2. Technical Findings\n\n`;
  if (findings.length === 0) {
    md += `*No security findings discovered for this target.*\n\n`;
  } else {
    findings.forEach((f, idx) => {
      md += `### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      md += `- **Category:** ${f.category}\n`;
      md += `- **CWE:** ${f.cwe || 'N/A'}\n`;
      md += `- **OWASP:** ${f.owasp || 'N/A'}\n`;
      md += `- **Confidence:** ${f.confidence}\n`;
      md += `- **Affected Endpoints (${f.affectedUrls?.length || 1}):**\n`;
      (f.affectedUrls || [f.url]).slice(0, 10).forEach(u => {
        md += `  - \`${u}\`\n`;
      });
      md += `\n**Description:**  \n${f.description}\n\n`;
      md += `**Security Impact:**  \n${f.impact}\n\n`;
      md += `**Evidence:**  \n\`\`\`json\n${JSON.stringify(f.evidence, null, 2)}\n\`\`\`\n\n`;
      md += `**Remediation:**  \n${f.recommendation || f.remediation || 'Apply context-aware sanitization.'}\n\n`;
      if (f.references && f.references.length > 0) {
        md += `**References:**  \n`;
        f.references.forEach(r => { md += `- [${r}](${r})\n`; });
        md += `\n`;
      }
      md += `---\n\n`;
    });
  }

  md += `## 3. Appendix: Detected Technologies\n\n`;
  const techs = scan.targetInfo?.technologies || [];
  if (techs.length > 0) {
    techs.forEach(t => {
      md += `- **${t.name}** (${t.category}) - Confidence: ${t.confidence}\n`;
    });
  } else {
    md += `*No specific frameworks or server banners fingerprinted.*\n`;
  }
  md += `\n`;

  md += `## 4. Appendix: Verified Working Endpoints (${workingEndpoints.length})\n\n`;
  if (workingEndpoints.length === 0) {
    md += `*No reachable working endpoints verified.*\n\n`;
  } else {
    workingEndpoints.slice(0, 30).forEach(e => {
      md += `- \`${e.url}\` [Status: ${e.statusCode || '200 OK'} | Type: ${e.type || 'Page'}]\n`;
    });
  }
  md += `\n`;

  md += `## 5. Appendix: Discovered Parameterized URLs & Attack Surfaces (${parameterizedUrls.length})\n\n`;
  if (parameterizedUrls.length === 0) {
    md += `*No parameterized URLs found on target.*\n\n`;
  } else {
    parameterizedUrls.slice(0, 30).forEach(p => {
      const pNames = (p.parameters || []).map(param => param.name).join(', ') || p.paramNames?.join(', ') || 'N/A';
      md += `- \`${p.url}\` [Params: ${pNames} | Method: ${p.method || 'GET'} | Status: ${p.statusCode || 200}]\n`;
    });
  }

  return md;
}

/**
 * Generate print-ready standalone HTML report
 */
export function generateHtmlReport(scan, findings = [], endpoints = []) {
  const stats = scan.statistics || {};
  const counts = stats.counts || {};
  const techs = scan.targetInfo?.technologies || [];
  const workingEndpoints = endpoints.filter(e => (e.statusCode >= 200 && e.statusCode < 400) || e.isWorking);
  const parameterizedUrls = scan.targetInfo?.parameterizedUrls || endpoints.filter(e => e.isParameterized || (e.url && e.url.includes('?')));

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberShield Security Audit - ${scan.target}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; background: #fff; margin: 0; padding: 2.5rem; }
    .header { border-bottom: 3px solid #2563eb; padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 1.8rem; font-weight: 800; color: #0f172a; margin: 0; }
    .subtitle { color: #64748b; font-size: 0.95rem; margin-top: 0.3rem; }
    .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    .badge-high { background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }
    .badge-medium { background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
    .badge-low { background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }
    .badge-info { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
    .score-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; display: flex; gap: 2rem; align-items: center; }
    .score-circle { width: 80px; height: 80px; border-radius: 50%; background: #2563eb; color: #fff; font-size: 1.8rem; font-weight: 800; display: flex; align-items: center; justify-content: center; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; page-break-inside: avoid; }
    .card-title { font-size: 1.15rem; font-weight: 700; margin: 0 0 0.5rem 0; display: flex; align-items: center; gap: 0.75rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #e2e8f0; }
    th { background: #f8fafc; font-weight: 600; color: #475569; }
    pre { background: #0f172a; color: #f8fafc; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
    @media print {
      body { padding: 0; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 class="title">Web Security Scanner Audit Report</h1>
      <div class="subtitle">CyberShield Autonomous Security Engine</div>
      <div style="margin-top: 0.5rem; font-size: 0.85rem; color: #64748b;">
        Target: <strong>${scan.target}</strong> | Generated: ${new Date().toLocaleString()}
      </div>
    </div>
    <div style="text-align: right;">
      <button class="no-print" onclick="window.print()" style="padding: 0.5rem 1rem; background: #2563eb; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">Print / Save as PDF</button>
    </div>
  </div>

  <div class="score-card">
    <div class="score-circle">${scan.riskScore}</div>
    <div>
      <h2 style="margin: 0; font-size: 1.3rem;">Overall Security Risk: ${scan.riskScore} / 100</h2>
      <p style="margin: 0.25rem 0; color: #64748b;">${stats.posture || 'Audited'}</p>
      <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
        <span class="badge badge-critical">Critical: ${counts.Critical || 0}</span>
        <span class="badge badge-high">High: ${counts.High || 0}</span>
        <span class="badge badge-medium">Medium: ${counts.Medium || 0}</span>
        <span class="badge badge-low">Low: ${counts.Low || 0}</span>
        <span class="badge badge-info">Info: ${counts.Informational || 0}</span>
      </div>
    </div>
  </div>

  <h2>Technical Findings (${findings.length})</h2>
  ${findings.map((f, idx) => `
    <div class="card">
      <div class="card-title">
        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
        <span>${idx + 1}. ${f.title}</span>
      </div>
      <p style="margin: 0.5rem 0; font-size: 0.9rem;"><strong>Category:</strong> ${f.category} | <strong>CWE:</strong> ${f.cwe || 'N/A'} | <strong>OWASP:</strong> ${f.owasp || 'N/A'}</p>
      <p style="font-size: 0.95rem;">${f.description}</p>
      <p style="font-size: 0.95rem;"><strong>Security Impact:</strong> ${f.impact}</p>
      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.75rem; margin: 0.75rem 0;">
        <strong>Remediation:</strong> ${f.recommendation || f.remediation || 'Apply context-aware sanitization.'}
      </div>
      <div style="font-size: 0.85rem; color: #64748b;">
        <strong>Affected URLs (${f.affectedUrls?.length || 1}):</strong>
        <ul>
          ${(f.affectedUrls || [f.url]).slice(0, 10).map(u => `<li><code>${u}</code></li>`).join('')}
        </ul>
      </div>
    </div>
  `).join('')}

  <h2>Appendix: Fingerprinted Technologies</h2>
  <table>
    <thead><tr><th>Technology</th><th>Category</th><th>Confidence</th></tr></thead>
    <tbody>
      ${techs.length > 0 ? techs.map(t => `<tr><td><strong>${t.name}</strong></td><td>${t.category}</td><td>${t.confidence}</td></tr>`).join('') : '<tr><td colspan="3">None fingerprinted</td></tr>'}
    </tbody>
  </table>

  <h2>Appendix: Verified Working Scope Endpoints (${workingEndpoints.length})</h2>
  <table>
    <thead><tr><th>URL</th><th>Type</th><th>Status Code</th><th>Depth</th></tr></thead>
    <tbody>
      ${workingEndpoints.length > 0
        ? workingEndpoints.slice(0, 30).map(e => `<tr><td><code>${e.url}</code></td><td>${e.type || 'Page'}</td><td>${e.statusCode || '200'}</td><td>${e.depth || 0}</td></tr>`).join('')
        : '<tr><td colspan="4">No verified working endpoints</td></tr>'}
    </tbody>
  </table>

  <h2>Appendix: Discovered Parameterized URLs & Attack Surfaces (${parameterizedUrls.length})</h2>
  <table>
    <thead><tr><th>Parameterized URL</th><th>Parameters</th><th>Method</th><th>Status</th></tr></thead>
    <tbody>
      ${parameterizedUrls.length > 0
        ? parameterizedUrls.slice(0, 30).map(p => {
            const pNames = (p.parameters || []).map(param => param.name).join(', ') || p.paramNames?.join(', ') || 'N/A';
            return `<tr><td><code>${p.url}</code></td><td><strong>${pNames}</strong></td><td>${p.method || 'GET'}</td><td>${p.statusCode || 200}</td></tr>`;
          }).join('')
        : '<tr><td colspan="4">No parameterized URLs discovered</td></tr>'}
    </tbody>
  </table>
</body>
</html>`;
}
