import express from 'express';
import {
  verifyPayloadsHandler,
  verifyPayloadsStreamHandler,
  getSamplePayloadsHandler
} from './xssVerifier.controller.js';

const router = express.Router();

/**
 * CyberShield - XSS Injection Verifier API Routes
 */

// Verify an array of custom user-supplied payloads against target (standard JSON)
router.post('/verify', verifyPayloadsHandler);

// Real-time streaming verification with live progress events (SSE)
router.post('/verify-stream', verifyPayloadsStreamHandler);

// Retrieve preconfigured safe test payload presets
router.get('/sample-payloads', getSamplePayloadsHandler);

// Built-in Local Test Lab Endpoints (for demonstration, testing, and training)
router.all('/lab/search', (req, res) => {
  const q = req.query.q || req.body?.q || '';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><title>Search Results</title></head><body><h1>Search Query</h1><div id="results">You searched for: ${q}</div></body></html>`);
});

router.all('/lab/safe-search', (req, res) => {
  const q = req.query.q || req.body?.q || '';
  const safe = String(q)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><title>Safe Search</title></head><body><h1>Search Results</h1><div id="results">You searched for: ${safe}</div></body></html>`);
});

router.all('/lab/no-reflection', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><title>Search Results</title></head><body><h1>Search</h1><p>Results found: 0 items.</p></body></html>`);
});

export default router;
