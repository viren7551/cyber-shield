import {
  calculateEntropy,
  estimateCrackTime,
  computeScore,
  checkBreachKAnonymity,
  generatePassword
} from './passwordAudit.service.js';
import { PasswordAuditLogService } from './passwordAudit.model.js';

export const analyzePassword = async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'Please provide a password string to analyze.' });
    }

    const { entropyBits, poolSize, uniqueChars } = calculateEntropy(password);
    const crackTimes = estimateCrackTime(entropyBits);
    const breachInfo = await checkBreachKAnonymity(password);
    const scoreResult = computeScore(password, entropyBits, breachInfo.isBreached);

    // Character analysis checklist
    const checklist = {
      length: password.length,
      hasMinLength: password.length >= 12,
      hasRecommendedLength: password.length >= 16,
      hasLower: /[a-z]/.test(password),
      hasUpper: /[A-Z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[^a-zA-Z0-9]/.test(password),
      uniqueCharacters: uniqueChars
    };

    // Specific actionable cybersecurity recommendations
    const recommendations = [];
    if (password.length < 12) recommendations.push('Increase password length to at least 12–16 characters.');
    if (!checklist.hasUpper) recommendations.push('Add uppercase letters (A–Z).');
    if (!checklist.hasLower) recommendations.push('Add lowercase letters (a–z).');
    if (!checklist.hasNumber) recommendations.push('Include numbers (0–9).');
    if (!checklist.hasSpecial) recommendations.push('Add special symbols (!@#$%^&*).');
    if (breachInfo.isBreached) {
      recommendations.unshift(`CRITICAL: This password was exposed ${breachInfo.breachCount.toLocaleString()} times in known breaches. Stop using it immediately.`);
    }

    // Save privacy-safe audit metrics to MongoDB
    await PasswordAuditLogService.createLog({
      auditType: 'SINGLE',
      score: scoreResult.score,
      grade: scoreResult.grade,
      strength: scoreResult.strength,
      entropyBits,
      crackTimeFastGpu: crackTimes.offlineFast,
      isBreached: breachInfo.isBreached,
      breachCount: breachInfo.breachCount,
      length: password.length,
      summary: `Score: ${scoreResult.score}/100 (${scoreResult.strength}), Breached: ${breachInfo.isBreached}`
    });

    return res.status(200).json({
      success: true,
      analysis: {
        score: scoreResult.score,
        grade: scoreResult.grade,
        strength: scoreResult.strength,
        entropyBits,
        poolSize,
        crackTimes,
        checklist,
        breachInfo,
        recommendations
      }
    });
  } catch (err) {
    console.error('[PasswordAudit Analyze Error]:', err);
    return res.status(500).json({ success: false, error: err.message || 'Audit analysis failed.' });
  }
};

export const batchAudit = async (req, res) => {
  try {
    const { passwords } = req.body;
    if (!Array.isArray(passwords) || passwords.length === 0) {
      return res.status(400).json({ error: 'Please provide an array of passwords to audit.' });
    }

    // Cap batch size at 100 for performance
    const batch = passwords.slice(0, 100);
    const results = [];
    let totalScore = 0;
    let breachedCount = 0;
    let weakCount = 0;

    for (let i = 0; i < batch.length; i++) {
      const pwd = String(batch[i] || '');
      const { entropyBits } = calculateEntropy(pwd);
      const crackTimes = estimateCrackTime(entropyBits);
      const breachInfo = await checkBreachKAnonymity(pwd);
      const scoreResult = computeScore(pwd, entropyBits, breachInfo.isBreached);

      if (breachInfo.isBreached) breachedCount++;
      if (scoreResult.score < 50) weakCount++;
      totalScore += scoreResult.score;

      results.push({
        id: i + 1,
        length: pwd.length,
        score: scoreResult.score,
        grade: scoreResult.grade,
        strength: scoreResult.strength,
        entropyBits,
        isBreached: breachInfo.isBreached,
        breachCount: breachInfo.breachCount,
        crackTime: crackTimes.offlineFast
      });
    }

    const averageScore = Math.round(totalScore / batch.length);

    await PasswordAuditLogService.createLog({
      auditType: 'BATCH',
      score: averageScore,
      grade: averageScore >= 75 ? 'A' : averageScore >= 50 ? 'C' : 'F',
      strength: averageScore >= 75 ? 'Strong' : averageScore >= 50 ? 'Fair' : 'Weak',
      length: batch.length,
      summary: `Batch audit: ${batch.length} credentials (${breachedCount} breached, ${weakCount} weak)`
    });

    return res.status(200).json({
      success: true,
      batchSummary: {
        totalAudited: batch.length,
        averageScore,
        breachedCount,
        weakCount,
        healthyCount: batch.length - breachedCount - weakCount
      },
      results
    });
  } catch (err) {
    console.error('[PasswordAudit Batch Error]:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const generatePasswordHandler = (req, res) => {
  try {
    const { length, uppercase, lowercase, numbers, symbols, excludeAmbiguous } = req.query;
    const generated = generatePassword({
      length: length ? parseInt(length, 10) : 16,
      uppercase: uppercase !== 'false',
      lowercase: lowercase !== 'false',
      numbers: numbers !== 'false',
      symbols: symbols !== 'false',
      excludeAmbiguous: excludeAmbiguous === 'true'
    });

    const { entropyBits } = calculateEntropy(generated);
    const crackTimes = estimateCrackTime(entropyBits);
    const scoreResult = computeScore(generated, entropyBits, false);

    return res.status(200).json({
      success: true,
      password: generated,
      metrics: {
        length: generated.length,
        entropyBits,
        score: scoreResult.score,
        grade: scoreResult.grade,
        crackTime: crackTimes.offlineFast
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const getAuditLogs = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 30;
    const logs = await PasswordAuditLogService.getRecentLogs(limit);
    return res.status(200).json({ success: true, logs });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const clearAuditLogs = async (req, res) => {
  try {
    await PasswordAuditLogService.clearLogs();
    return res.status(200).json({ success: true, message: 'Password audit logs cleared.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};
