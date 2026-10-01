import express from 'express';
import {
  executeScanHandler,
  deepProbeHandler,
  subnetSweepHandler,
  getKnowledgeDatabaseHandler
} from './scanner.controller.js';

const router = express.Router();

/**
 * Network Scanner API Routes
 */

// Port Scan endpoints (support both POST and GET for flexibility)
router.post('/scan', executeScanHandler);
router.get('/scan', executeScanHandler);

// Interactive raw socket / banner probe
router.post('/probe', deepProbeHandler);

// Local / Subnet live host sweep
router.post('/sweep', subnetSweepHandler);
router.get('/sweep', subnetSweepHandler);

// Port dictionary & presets reference
router.get('/database', getKnowledgeDatabaseHandler);

export default router;
