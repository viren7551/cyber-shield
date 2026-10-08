/**
 * CyberShield Web Security Scanner - Safe HTTP Client
 * Handles HTTP/HTTPS requests with timeouts, size limits, redirect tracking,
 * custom headers, and immediate cancellation support.
 */

const DEFAULT_TIMEOUT_MS = 10000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB limit
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 CyberShield-Security-Auditor/1.0';

/**
 * Perform a safe, controlled HTTP request
 * @param {string} targetUrl
 * @param {object} options
 */
export async function safeRequest(targetUrl, options = {}) {
  const {
    method = 'GET',
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    userAgent = DEFAULT_USER_AGENT,
    maxRedirects = 5,
    followRedirects = true,
    abortSignal = null,
    body = null
  } = options;

  let currentUrl = targetUrl;
  const redirectChain = [];
  let hopCount = 0;
  const startTime = Date.now();

  const customController = new AbortController();
  const timeoutId = setTimeout(() => {
    customController.abort(new Error(`Request timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  // Link external abort signal if provided
  if (abortSignal) {
    if (abortSignal.aborted) {
      clearTimeout(timeoutId);
      throw new Error('Scan aborted by user.');
    }
    abortSignal.addEventListener('abort', () => {
      customController.abort(new Error('Scan aborted by user.'));
    });
  }

  try {
    while (hopCount <= maxRedirects) {
      const reqHeaders = {
        'User-Agent': userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        ...headers
      };

      const fetchOptions = {
        method,
        headers: reqHeaders,
        redirect: 'manual', // Manual redirection so we record every hop and headers!
        signal: customController.signal
      };

      if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
        fetchOptions.body = body;
      }

      const res = await fetch(currentUrl, fetchOptions);
      const statusCode = res.status;

      // Extract headers into a clean dictionary
      const responseHeaders = {};
      const setCookies = [];
      res.headers.forEach((val, key) => {
        const lower = key.toLowerCase();
        if (lower === 'set-cookie') {
          setCookies.push(val);
        } else {
          responseHeaders[lower] = val;
        }
      });
      if (setCookies.length > 0) {
        responseHeaders['set-cookie'] = setCookies;
      }

      // Check if this response is a redirect (301, 302, 303, 307, 308)
      const location = res.headers.get('location');
      const isRedirect = [301, 302, 303, 307, 308].includes(statusCode) && location;

      if (isRedirect && followRedirects) {
        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).toString();
        } catch {
          nextUrl = location;
        }

        redirectChain.push({
          from: currentUrl,
          to: nextUrl,
          statusCode,
          headers: responseHeaders
        });

        currentUrl = nextUrl;
        hopCount++;
        continue;
      }

      // Final response reached or redirection disabled
      let responseText = '';
      const contentType = responseHeaders['content-type'] || '';
      const isTextOrHtml = contentType.includes('text') || contentType.includes('html') || contentType.includes('json') || contentType.includes('xml') || contentType.includes('javascript') || contentType.includes('ecmascript');

      if (isTextOrHtml && method.toUpperCase() !== 'HEAD') {
        try {
          // Read chunk-by-chunk up to MAX_RESPONSE_BYTES
          const reader = res.body?.getReader();
          if (reader) {
            const chunks = [];
            let totalBytes = 0;
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              chunks.push(value);
              totalBytes += value.length;
              if (totalBytes >= MAX_RESPONSE_BYTES) {
                reader.cancel();
                break;
              }
            }
            const fullBuf = Buffer.concat(chunks.map(c => Buffer.from(c)));
            responseText = fullBuf.toString('utf8');
          } else {
            responseText = await res.text();
          }
        } catch {
          responseText = '';
        }
      }

      const durationMs = Date.now() - startTime;

      clearTimeout(timeoutId);

      return {
        success: true,
        url: currentUrl,
        requestedUrl: targetUrl,
        statusCode,
        statusText: res.statusText,
        headers: responseHeaders,
        body: responseText,
        contentType,
        contentLength: responseHeaders['content-length'] ? parseInt(responseHeaders['content-length'], 10) : responseText.length,
        durationMs,
        redirectChain,
        isRedirected: redirectChain.length > 0
      };
    }

    throw new Error(`Exceeded maximum redirect depth (${maxRedirects})`);
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      success: false,
      url: currentUrl,
      requestedUrl: targetUrl,
      error: err.message,
      code: err.code || 'REQUEST_FAILED',
      redirectChain,
      durationMs: Date.now() - startTime
    };
  }
}
