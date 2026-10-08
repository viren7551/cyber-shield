/**
 * CyberShield Web Security Scanner - Finding Deduplication & Normalization Engine
 * Groups identical vulnerabilities across multiple crawled endpoints into a single
 * actionable primary finding while retaining the comprehensive list of affected URLs.
 */

/**
 * Deduplicate and group findings by ruleId / title
 * @param {Array<object>} rawFindings
 */
export function deduplicateFindings(rawFindings = []) {
  if (!Array.isArray(rawFindings)) return [];

  const grouped = new Map();

  for (const f of rawFindings) {
    if (!f || !f.title) continue;

    // Use ruleId or normalized title as grouping key
    const key = f.ruleId || f.title.toLowerCase().trim();

    if (!grouped.has(key)) {
      grouped.set(key, {
        id: 'find_' + Math.random().toString(36).substring(2, 9),
        ruleId: f.ruleId || 'CUSTOM_RULE',
        title: f.title,
        severity: f.severity || 'Medium',
        confidence: f.confidence || 'High',
        category: f.category || 'Web Security',
        url: f.url || '/',
        affectedUrls: [f.url || '/'],
        description: f.description || '',
        impact: f.impact || '',
        evidence: f.evidence || {},
        recommendation: f.recommendation || '',
        cwe: f.cwe || 'CWE-16',
        owasp: f.owasp || 'A05:2021 - Security Misconfiguration',
        references: Array.isArray(f.references) ? f.references : [],
        status: 'open',
        createdAt: new Date()
      });
    } else {
      const existing = grouped.get(key);
      const urlToAdd = f.url || '/';

      if (!existing.affectedUrls.includes(urlToAdd)) {
        existing.affectedUrls.push(urlToAdd);
      }

      // Elevate severity if higher severity observed
      const severityRank = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
      if ((severityRank[f.severity] || 0) > (severityRank[existing.severity] || 0)) {
        existing.severity = f.severity;
      }
    }
  }

  // Sort by severity (Critical -> High -> Medium -> Low -> Informational)
  const severityRank = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
  return Array.from(grouped.values()).sort((a, b) => {
    return (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
  });
}
