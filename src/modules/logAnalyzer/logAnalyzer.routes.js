import express from 'express';
import multer from 'multer';
import {
  analyzeLogsHandler,
  getSampleLogsHandler,
  getRulesCatalogHandler,
  testCustomRuleHandler
} from './logAnalyzer.controller.js';

const router = express.Router();

// Support file uploads up to 50MB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

router.post('/analyze', upload.single('logFile'), analyzeLogsHandler);
router.get('/samples', getSampleLogsHandler);
router.get('/rules', getRulesCatalogHandler);
router.post('/test-rule', testCustomRuleHandler);

export default router;
