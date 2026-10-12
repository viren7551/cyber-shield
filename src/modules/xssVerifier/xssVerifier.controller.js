import { verifyCustomPayloads, getSamplePayloads } from './xssVerifier.service.js';

/**
 * Controller: Run XSS Verification on User-Provided Payloads
 * POST /api/xss-verifier/verify
 */
export async function verifyPayloadsHandler(req, res) {
  try {
    const {
      targetUrl,
      parameterName,
      httpMethod = 'GET',
      payloads = [],
      options = {}
    } = req.body;

    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Target URL is required. Please specify the target endpoint.'
      });
    }

    if (!Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No payloads provided. Please upload a payload file or enter test payloads.'
      });
    }

    // Sanitize and filter all payloads (scans the entire user list without arbitrary 200 cap)
    const maxLimit = options.maxPayloads ? parseInt(options.maxPayloads, 10) : Infinity;
    const sanitizedPayloads = payloads
      .map(p => String(p || '').trim())
      .filter(p => p.length > 0)
      .slice(0, maxLimit || Infinity);

    if (sanitizedPayloads.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Payload list is empty after removing blank lines.'
      });
    }

    const verificationResult = await verifyCustomPayloads({
      targetUrl,
      parameterName,
      httpMethod,
      payloads: sanitizedPayloads,
      options: {
        rateLimitMs: Math.max(10, parseInt(options.rateLimitMs, 10) || 40),
        timeoutMs: Math.max(1000, parseInt(options.timeoutMs, 10) || 4500),
        customHeaders: options.headers || {}
      }
    });

    return res.status(200).json({
      success: true,
      data: verificationResult
    });
  } catch (err) {
    console.error('[XssVerifier Error]:', err.message);
    return res.status(500).json({
      success: false,
      error: err.message || 'Internal error executing payload verification.'
    });
  }
}

/**
 * Controller: Get Standard Sample Payloads
 * GET /api/xss-verifier/sample-payloads
 */
export function getSamplePayloadsHandler(req, res) {
  try {
    const samples = getSamplePayloads();
    return res.status(200).json({
      success: true,
      samples
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

/**
 * Controller: Stream XSS Verification Progress in Real-Time (Server-Sent Events)
 * POST /api/xss-verifier/verify-stream
 */
export async function verifyPayloadsStreamHandler(req, res) {
  try {
    const {
      targetUrl,
      parameterName,
      httpMethod = 'GET',
      payloads = [],
      options = {}
    } = req.body;

    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Target URL is required. Please specify the target endpoint.'
      });
    }

    if (!Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No payloads provided. Please upload a payload file or enter test payloads.'
      });
    }

    // Sanitize and filter all payloads (scans the entire user list without arbitrary 200 cap)
    const maxLimit = options.maxPayloads ? parseInt(options.maxPayloads, 10) : Infinity;
    const sanitizedPayloads = payloads
      .map(p => String(p || '').trim())
      .filter(p => p.length > 0)
      .slice(0, maxLimit || Infinity);

    if (sanitizedPayloads.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Payload list is empty after removing blank lines.'
      });
    }

    // Set SSE Headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') {
      res.flushHeaders();
    }

    const abortController = new AbortController();
    res.on('close', () => {
      if (!res.writableEnded) {
        abortController.abort();
      }
    });

    const sendEvent = (event, data) => {
      try {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
      } catch {}
    };

    sendEvent('start', {
      total: sanitizedPayloads.length,
      targetUrl,
      parameterName
    });

    const verificationResult = await verifyCustomPayloads({
      targetUrl,
      parameterName,
      httpMethod,
      payloads: sanitizedPayloads,
      options: {
        rateLimitMs: Math.max(10, parseInt(options.rateLimitMs, 10) || 40),
        timeoutMs: Math.max(1000, parseInt(options.timeoutMs, 10) || 4500),
        customHeaders: options.headers || {},
        abortSignal: abortController.signal,
        onProgress: (progressData) => {
          sendEvent('progress', progressData);
        }
      }
    });

    sendEvent('complete', {
      success: true,
      data: verificationResult
    });
    res.end();
  } catch (err) {
    console.error('[XssVerifier Stream Error]:', err.message);
    try {
      res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
      res.end();
    } catch {}
  }
}

