import express from 'express';
import {
  createScanHandler,
  listScansHandler,
  getScanHandler,
  cancelScanHandler,
  getFindingsHandler,
  getEndpointsHandler,
  getTechnologiesHandler,
  updateFindingStatusHandler,
  deleteScanHandler,
  getReportHandler,
  subscribeScanEventsHandler,
  getPresetsHandler,
  probeEndpointsHandler,
  crawlParameterizedUrlsHandler,
  auditXssHandler,
  verifyXssFindingHandler,
  getParameterInventoryHandler
} from './webScanner.controller.js';

const router = express.Router();

/**
 * CyberShield Web Security Scanner - API Routes
 */

// Presets
router.get('/presets', getPresetsHandler);

// Scans CRUD & Operations
router.post('/', createScanHandler);
router.get('/', listScansHandler);
router.get('/:id', getScanHandler);
router.delete('/:id', deleteScanHandler);
router.post('/:id/cancel', cancelScanHandler);

// Real-time SSE Progress Stream
router.get('/:id/events', subscribeScanEventsHandler);

// Report Generation (JSON, HTML, Markdown)
router.get('/:id/report', getReportHandler);

// Discovered Assets & Telemetry
router.get('/:id/findings', getFindingsHandler);
router.patch('/:id/findings/:findingId', updateFindingStatusHandler);
router.get('/:id/endpoints', getEndpointsHandler);
router.post('/:id/endpoints/probe', probeEndpointsHandler);
router.post('/:id/endpoints/crawl-parameterized', crawlParameterizedUrlsHandler);
router.post('/:id/crawl-parameters', crawlParameterizedUrlsHandler);
router.get('/:id/technologies', getTechnologiesHandler);
router.post('/:id/xss/audit', auditXssHandler);
router.post('/:id/xss/verify', verifyXssFindingHandler);
router.get('/:id/xss/inventory', getParameterInventoryHandler);

export default router;
