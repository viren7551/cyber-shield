import { parseRawLogs } from './parser/logParser.js';
import { DEFAULT_RULES } from './rules/defaultRules.js';
import { runRuleEngine } from './rules/ruleEngine.js';
import { SAMPLE_LOGS } from './samples/sampleLogs.js';

/**
 * Build aggregated timeline buckets for chart visualization
 */
function buildTimeline(entries, alerts) {
  if (!entries || entries.length === 0) return [];

  // Group by minute or 10-second slots
  const buckets = new Map();

  entries.forEach(entry => {
    const d = new Date(entry.timestamp);
    if (isNaN(d.getTime())) return;

    // Minute bucket string: YYYY-MM-DD HH:mm
    const bucketKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    const timeLabel = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;

    if (!buckets.has(bucketKey)) {
      buckets.set(bucketKey, {
        bucketKey,
        timeLabel,
        total: 0,
        errors: 0,
        alerts: 0
      });
    }

    const b = buckets.get(bucketKey);
    b.total += 1;
    if (entry.status === 'FAILURE' || entry.status === 'BLOCKED' || (entry.statusCode && entry.statusCode >= 400)) {
      b.errors += 1;
    }
  });

  // Annotate alerts into buckets
  alerts.forEach(alert => {
    const alertTime = alert.evidence?.triggerTimestamp;
    if (alertTime) {
      const d = new Date(alertTime);
      if (!isNaN(d.getTime())) {
        const bucketKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
        if (buckets.has(bucketKey)) {
          buckets.get(bucketKey).alerts += 1;
        }
      }
    }
  });

  return Array.from(buckets.values()).slice(0, 30);
}

/**
 * Analyze Logs Endpoint Handler
 */
export async function analyzeLogsHandler(req, res, next) {
  try {
    let rawText = '';

    // File upload support
    if (req.file) {
      rawText = req.file.buffer.toString('utf8');
    } else if (req.body && req.body.logText) {
      rawText = req.body.logText;
    }

    if (!rawText || !rawText.trim()) {
      return res.status(400).json({
        success: false,
        error: 'No log content provided. Please upload a file or paste log text.'
      });
    }

    const userFormat = req.body.logFormat || 'AUTO';

    // Parse active custom & default rules
    let customRules = [];
    if (req.body.customRules) {
      try {
        customRules = typeof req.body.customRules === 'string'
          ? JSON.parse(req.body.customRules)
          : req.body.customRules;
      } catch {
        customRules = [];
      }
    }

    let disabledRuleIds = [];
    if (req.body.disabledRuleIds) {
      try {
        disabledRuleIds = typeof req.body.disabledRuleIds === 'string'
          ? JSON.parse(req.body.disabledRuleIds)
          : req.body.disabledRuleIds;
      } catch {
        disabledRuleIds = [];
      }
    }

    // Combine rules
    const activeRules = [
      ...DEFAULT_RULES.filter(r => !disabledRuleIds.includes(r.id)),
      ...customRules
    ];

    // 1. Parse & Normalize
    const { format: detectedFormat, entries, lineCount } = parseRawLogs(rawText, userFormat);

    // 2. Correlation & Security Rules Execution
    const { alerts, updatedEntries } = runRuleEngine(entries, activeRules);

    // 3. Compute Top Source IPs
    const sourceIpMap = new Map();
    let totalErrors = 0;
    const categoriesMap = { AUTHENTICATION: 0, WEB: 0, NETWORK: 0, SYSTEM: 0, OTHER: 0 };

    updatedEntries.forEach(entry => {
      const isErr = entry.status === 'FAILURE' || entry.status === 'BLOCKED' || (entry.statusCode && entry.statusCode >= 400);
      if (isErr) totalErrors++;

      const cat = entry.category || 'OTHER';
      categoriesMap[cat] = (categoriesMap[cat] || 0) + 1;

      if (entry.sourceIp) {
        if (!sourceIpMap.has(entry.sourceIp)) {
          sourceIpMap.set(entry.sourceIp, {
            ip: entry.sourceIp,
            count: 0,
            errors: 0,
            alertCount: 0,
            user: entry.user || null,
            categories: new Set()
          });
        }
        const data = sourceIpMap.get(entry.sourceIp);
        data.count++;
        if (isErr) data.errors++;
        if (entry.user && !data.user) data.user = entry.user;
        data.categories.add(entry.category);
      }
    });

    // Count alerts per IP
    alerts.forEach(alert => {
      if (alert.sourceIp && sourceIpMap.has(alert.sourceIp)) {
        sourceIpMap.get(alert.sourceIp).alertCount += 1;
      }
    });

    const topSources = Array.from(sourceIpMap.values())
      .map(item => ({
        ...item,
        categories: Array.from(item.categories),
        riskScore: item.alertCount > 0 ? (item.alertCount * 25 + 20) : (item.errors > 2 ? 30 : 5)
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);

    // 4. Overall Risk Assessment
    let overallRiskLevel = 'CLEAN';
    const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
    const highCount = alerts.filter(a => a.severity === 'HIGH').length;
    const mediumCount = alerts.filter(a => a.severity === 'MEDIUM').length;
    const lowCount = alerts.filter(a => a.severity === 'LOW').length;

    if (criticalCount > 0) overallRiskLevel = 'CRITICAL';
    else if (highCount > 0) overallRiskLevel = 'HIGH';
    else if (mediumCount > 0) overallRiskLevel = 'MEDIUM';
    else if (lowCount > 0) overallRiskLevel = 'LOW';

    // 5. Timeline Chart Buckets
    const timeline = buildTimeline(updatedEntries, alerts);

    return res.status(200).json({
      success: true,
      data: {
        summary: {
          totalEvents: updatedEntries.length,
          rawLines: lineCount,
          totalAlerts: alerts.length,
          criticalAlerts: criticalCount,
          highAlerts: highCount,
          mediumAlerts: mediumCount,
          lowAlerts: lowCount,
          uniqueSources: sourceIpMap.size,
          totalErrors,
          detectedFormat,
          overallRiskLevel,
          analyzedAt: new Date().toISOString()
        },
        alerts,
        topSources,
        timeline,
        categories: categoriesMap,
        entries: updatedEntries.slice(0, 500) // Send up to 500 normalized entries for snappy UI
      }
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Get Built-In Sample Logs
 */
export function getSampleLogsHandler(req, res) {
  res.status(200).json({
    success: true,
    samples: SAMPLE_LOGS
  });
}

/**
 * Get Rules Catalog
 */
export function getRulesCatalogHandler(req, res) {
  res.status(200).json({
    success: true,
    rules: DEFAULT_RULES
  });
}

/**
 * Test Custom Rule against Log Snippet
 */
export function testCustomRuleHandler(req, res) {
  const { rule, logText } = req.body;
  if (!rule || !logText) {
    return res.status(400).json({
      success: false,
      error: 'Please provide both rule definition and logText to test.'
    });
  }

  const { entries } = parseRawLogs(logText, 'AUTO');
  const customRule = { ...rule, id: rule.id || `custom-${Date.now()}`, isCustom: true, enabled: true };
  const { alerts, updatedEntries } = runRuleEngine(entries, [customRule]);

  res.status(200).json({
    success: true,
    ruleId: customRule.id,
    matchesCount: alerts.length,
    alerts,
    matchedEntries: updatedEntries.filter(e => e.alertId)
  });
}
