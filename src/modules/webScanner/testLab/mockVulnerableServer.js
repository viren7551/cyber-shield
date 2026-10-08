import http from 'http';

/**
 * CyberShield Web Security Scanner - Local Test Lab
 * An intentionally misconfigured mock HTTP server providing reproducible, safe
 * test endpoints for automated testing and local validation without attacking real systems.
 */

export function createMockLabServer() {
  let storedSafeComment = 'Initial safe note';
  let storedVulnComment = 'Initial unescaped note';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    const pathname = url.pathname;

    // Enable CORS test handling
    if (req.method === 'OPTIONS') {
      res.writeHead(200, {
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, TRACE, PUT',
        'Access-Control-Allow-Headers': 'Content-Type, X-Probe-Test',
        'Allow': 'GET, POST, OPTIONS, TRACE'
      });
      return res.end();
    }

    if (req.method === 'TRACE') {
      res.writeHead(200, { 'Content-Type': 'message/http' });
      return res.end(`TRACE ${req.url} HTTP/1.1\r\nX-Probe-Test: CyberShield-Audit\r\n`);
    }

    // 1. Root page: Missing CSP, Missing HSTS, Server banner disclosure, weak session cookie, password form without CSRF
    if (pathname === '/') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1',
        'X-Powered-By': 'PHP/8.0.2',
        'Set-Cookie': ['insecure_session=admin_secret_token_12345; Path=/; Domain=localhost']
      });

      return res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Test Lab - Home</title>
          <meta name="generator" content="WordPress 5.8">
        </head>
        <body>
          <h1>Welcome to CyberShield Test Lab</h1>
          <p>This is an intentionally misconfigured testing target.</p>
          <a href="/login">Go to Login</a>
          <a href="/cors-test">CORS Test</a>
          <a href="/redirect-step-1">Redirect Test</a>
          <a href="/search?q=test">Search Test</a>
          <a href="/safe-search?q=test">Safe Search Test</a>
          <a href="/plain-reflection?q=test">Plain Reflection Test</a>
          <a href="/no-reflection?q=test">No Reflection Test</a>
          <a href="/comment">Comment Form</a>
          <a href="/stored-safe">Stored Safe Endpoint</a>
          <a href="/stored-vuln">Stored Vuln Endpoint</a>
          <a href="/dom-xss">DOM XSS Test</a>
          <a href="/dom-safe">DOM Safe Test</a>
          <script src="/static/test.js"></script>
        </body>
        </html>
      `);
    }

    // 2. Login page
    if (pathname === '/login') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'nginx/1.18.0',
        'Cache-Control': 'public, max-age=3600'
      });

      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Login Page</title></head>
        <body>
          <h2>User Login</h2>
          <form action="/auth-submit" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Sign In</button>
          </form>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // 3. CORS misconfiguration endpoint
    if (pathname === '/cors-test') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Credentials': 'true'
      });
      return res.end(JSON.stringify({ status: 'cors_exposed', secretData: 'Confidential Internal Telemetry' }));
    }

    // 4. Redirect Chain
    if (pathname === '/redirect-step-1') {
      res.writeHead(302, { 'Location': '/redirect-step-2' });
      return res.end();
    }
    if (pathname === '/redirect-step-2') {
      res.writeHead(302, { 'Location': '/redirect-final' });
      return res.end();
    }
    if (pathname === '/redirect-final') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><body><h3>Redirect Chain Reached</h3><a href="/">Home</a></body></html>');
    }

    // ------------------------------------------------------------------------
    // TEST 1: Input is NOT reflected
    // ------------------------------------------------------------------------
    if (pathname === '/no-reflection') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>No Reflection</title></head>
        <body>
          <h2>Catalog Listing</h2>
          <p>Query parameters are completely ignored by the server.</p>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 2: Input is reflected as plain HTML text (Reflection Only, NOT XSS)
    // Strips or filters dangerous HTML tags/syntax so it's strictly reflection only
    // ------------------------------------------------------------------------
    if (pathname === '/plain-reflection') {
      const rawQ = url.searchParams.get('q') || '';
      // Strips < and > to prevent alteration of parsing context, while reflecting the token
      const plainQ = rawQ.replace(/[<>]/g, '');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Plain Reflection</title></head>
        <body>
          <h1>Search results for '${plainQ}'</h1>
          <p>Found 0 matching records.</p>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 3: Input is HTML encoded (Encoded Reflection, NOT XSS)
    // ------------------------------------------------------------------------
    if (pathname === '/safe-search') {
      const rawQ = url.searchParams.get('q') || '';
      const safeQ = rawQ
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Safe Search</title></head>
        <body>
          <h2>Search Results for: ${safeQ}</h2>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 4: Input reaches dangerous HTML context without encoding (Reflected XSS)
    // ------------------------------------------------------------------------
    if (pathname === '/search') {
      const q = url.searchParams.get('q') || '';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Search</title></head>
        <body>
          <h2>Search Results for: ${q}</h2>
          <p>Total items found: 0</p>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 5: Stored input saved but safely encoded when displayed
    // ------------------------------------------------------------------------
    if (pathname === '/stored-safe') {
      if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          const params = new URLSearchParams(body);
          if (params.get('comment')) {
            storedSafeComment = params.get('comment');
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end('Comment saved successfully.');
        });
        return;
      }

      const safeComment = storedSafeComment
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Stored Safe Forum</title></head>
        <body>
          <h2>Stored Safe Comments</h2>
          <div class="user-comment">${safeComment}</div>
          <form action="/stored-safe" method="POST">
            <textarea name="comment"></textarea>
            <button type="submit">Post</button>
          </form>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 6: Stored input retrieved into unsafe context (Stored XSS)
    // ------------------------------------------------------------------------
    if (pathname === '/stored-vuln') {
      if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          const params = new URLSearchParams(body);
          if (params.get('comment')) {
            storedVulnComment = params.get('comment');
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end('Comment saved unescaped.');
        });
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Stored Vuln Forum</title></head>
        <body>
          <h2>Community Feed</h2>
          <div class="user-comment">${storedVulnComment}</div>
          <form action="/stored-vuln" method="POST">
            <textarea name="comment"></textarea>
            <button type="submit">Post</button>
          </form>
        </body>
        </html>
      `);
    }

    // Generic Stored candidate form
    if (pathname === '/comment') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>User Feedback & Comments</title></head>
        <body>
          <h2>Leave a Public Comment</h2>
          <form action="/comment" method="POST">
            <input type="text" name="author" placeholder="Your Name">
            <textarea name="comment" placeholder="Your Comment Here"></textarea>
            <button type="submit">Submit Comment</button>
          </form>
          <a href="/">Back Home</a>
        </body>
        </html>
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 7: DOM source reaches dangerous sink without sanitization
    // ------------------------------------------------------------------------
    if (pathname === '/static/dom-test.js' || pathname === '/static/dom-vuln.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(`
        // Vulnerable DOM source-to-sink flow
        window.addEventListener('DOMContentLoaded', function() {
          var userPayload = location.hash.substring(1);
          if (userPayload) {
            document.getElementById('output').innerHTML = userPayload;
          }
        });
      `);
    }

    // ------------------------------------------------------------------------
    // TEST 8: DOM source is safely sanitized before sink
    // ------------------------------------------------------------------------
    if (pathname === '/static/dom-safe.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(`
        // Safely sanitized DOM flow using textContent and DOMPurify
        window.addEventListener('DOMContentLoaded', function() {
          var userPayload = location.hash.substring(1);
          if (userPayload) {
            document.getElementById('output').textContent = userPayload;
          }
        });
      `);
    }

    if (pathname === '/dom-xss') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>DOM XSS Lab</title></head>
        <body>
          <div id="output">Default Content</div>
          <script src="/static/dom-test.js"></script>
        </body>
        </html>
      `);
    }

    if (pathname === '/dom-safe') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>DOM Safe Lab</title></head>
        <body>
          <div id="output">Default Content</div>
          <script src="/static/dom-safe.js"></script>
        </body>
        </html>
      `);
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  return server;
}
