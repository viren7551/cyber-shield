/**
 * CyberShield Web Security Scanner - Transparent Risk Scoring Engine
 * Computes an objective 0-100 risk score based on severity weights,
 * confidence weighting, and affected endpoint exposure factors.
 */

const SEVERITY_WEIGHTS = {
  Critical: 30,
  High: 18,
  Medium: 8,
  Low: 3,
  Informational: 0
};

const CONFIDENCE_MULTIPLIERS = {
  High: 1.0,
  Medium: 0.8,
  Low: 0.5
};

/**
 * Calculate transparent risk score for a set of deduplicated findings
 * @param {Array<object>} findings
 * @param {number} totalPagesScanned
 */
export function calculateRiskScore(findings = [], totalPagesScanned = 1) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0
  };

  let rawWeightedSum = 0;

  for (const f of findings) {
    const sev = f.severity || 'Medium';
    const conf = f.confidence || 'High';

    if (counts[sev] !== undefined) {
      counts[sev]++;
    }

    const baseWeight = SEVERITY_WEIGHTS[sev] || 5;
    const confFactor = CONFIDENCE_MULTIPLIERS[conf] || 1.0;

    // Exposure multiplier: Findings affecting more endpoints increase risk
    const affectedCount = Array.isArray(f.affectedUrls) ? f.affectedUrls.length : 1;
    const exposureMultiplier = Math.min(1.0 + (affectedCount - 1) * 0.05, 1.35);

    rawWeightedSum += (baseWeight * confFactor * exposureMultiplier);
  }

  // Normalize to 0 - 100 scale using asymptotic curve
  // A single Critical easily produces ~40-60 risk; multiple Highs produce 70-85+; clean targets produce 0-15.
  let riskScore = 0;
  if (rawWeightedSum > 0) {
    riskScore = Math.min(100, Math.round(100 * (1 - Math.exp(-rawWeightedSum / 45))));
  }

  // Grade classification
  let grade = 'A';
  let posture = 'Strong Security Posture';
  let color = 'var(--success)';

  if (riskScore >= 75) {
    grade = 'F';
    posture = 'Severe Risk - Urgent Remediation Required';
    color = 'var(--danger)';
  } else if (riskScore >= 50) {
    grade = 'D';
    posture = 'High Risk - Elevated Vulnerability Profile';
    color = '#ea580c';
  } else if (riskScore >= 25) {
    grade = 'C';
    posture = 'Moderate Risk - Multiple Deficiencies Detected';
    color = 'var(--warning)';
  } else if (riskScore > 10) {
    grade = 'B';
    posture = 'Low Risk - Minor Hardening Opportunities';
    color = 'var(--primary)';
  }

  const explanation = `Score calculated using weighted severity model (Critical: 30pts, High: 18pts, Medium: 8pts, Low: 3pts) adjusted by confidence ratings and an endpoint exposure factor across ${totalPagesScanned} scanned URL(s).`;

  return {
    score: riskScore,
    grade,
    posture,
    color,
    counts,
    totalFindings: findings.length,
    explanation
  };
}
