import express from 'express';
import stegoRoutes from './steganography/stego.routes.js';
import passwordAuditRoutes from './passwordAudit/passwordAudit.routes.js';
import metadataRoutes from './metadataSanitizer/metadata.routes.js';
import osintRoutes from './osint/osint.routes.js';
import scannerRoutes from './networkScanner/scanner.routes.js';
import logAnalyzerRoutes from './logAnalyzer/logAnalyzer.routes.js';
import urlAnalyzerRoutes from './urlAnalyzer/urlAnalyzer.routes.js';
import webScannerRoutes from './webScanner/webScanner.routes.js';

const router = express.Router();

/**
 * CyberShield Modular Architecture Registry
 * Easily plug in future security modules here!
 */
router.use('/stego', stegoRoutes);
router.use('/password-audit', passwordAuditRoutes);
router.use('/metadata', metadataRoutes);
router.use('/osint', osintRoutes);
router.use('/scanner', scannerRoutes);
router.use('/log-analyzer', logAnalyzerRoutes);
router.use('/url-analyzer', urlAnalyzerRoutes);
router.use('/security-scans', webScannerRoutes);
router.use('/web-scanner', webScannerRoutes);

export default router;

