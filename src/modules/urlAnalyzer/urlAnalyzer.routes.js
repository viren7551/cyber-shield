import express from 'express';
import {
  analyzeUrl,
  normalizeUrlOnly,
  traceRedirectsOnly,
  inspectCertOnly,
  batchAnalyze,
  getPresets
} from './urlAnalyzer.controller.js';

const router = express.Router();

/**
 * CyberShield URL & Phishing Analyzer Routes
 */
router.post('/analyze', analyzeUrl);
router.post('/normalize', normalizeUrlOnly);
router.post('/redirects', traceRedirectsOnly);
router.post('/cert', inspectCertOnly);
router.post('/batch', batchAnalyze);
router.get('/presets', getPresets);

export default router;
