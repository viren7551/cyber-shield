import express from 'express';
import {
  analyzePassword,
  batchAudit,
  generatePasswordHandler,
  getAuditLogs,
  clearAuditLogs
} from './passwordAudit.controller.js';

const router = express.Router();

router.post('/analyze', analyzePassword);
router.post('/batch', batchAudit);
router.get('/generate', generatePasswordHandler);
router.get('/logs', getAuditLogs);
router.delete('/logs', clearAuditLogs);

export default router;
