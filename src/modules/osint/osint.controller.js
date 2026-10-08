import * as OsintEngine from './osint.engine.js';

export const domainIntelHandler = async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ success: false, error: 'Target domain is required.' });
    const data = await OsintEngine.lookupDomainIntel(domain);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const subdomainsHandler = async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ success: false, error: 'Target domain is required.' });
    const data = await OsintEngine.discoverSubdomains(domain);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const whoisHandler = async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ success: false, error: 'Target domain is required.' });
    const data = await OsintEngine.lookupWhoisRdap(domain);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const ipIntelHandler = async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) return res.status(400).json({ success: false, error: 'IP or domain query is required.' });
    const data = await OsintEngine.lookupIpIntel(query);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const dnsMapHandler = async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ success: false, error: 'Target domain is required.' });
    const data = await OsintEngine.buildDnsMapData(domain);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const usernameSearchHandler = async (req, res) => {
  try {
    const { username, scope = 'all' } = req.query;
    if (!username) return res.status(400).json({ success: false, error: 'Target username is required.' });
    const data = await OsintEngine.searchUsername(username, { scope });
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const usernameStreamHandler = async (req, res) => {
  const { username, scope = 'all' } = req.query;
  if (!username) {
    return res.status(400).json({ success: false, error: 'Target username is required.' });
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
  req.on('close', () => {
    abortController.abort();
  });

  const sendEvent = (event, data) => {
    try {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      if (typeof res.flush === 'function') res.flush();
    } catch {}
  };

  try {
    const summary = await OsintEngine.searchUsername(username, {
      scope,
      signal: abortController.signal,
      onProgress: (progress) => {
        if (progress.result && progress.result.exists) {
          sendEvent('found', progress.result);
        }
        sendEvent('progress', {
          scanned: progress.scanned,
          total: progress.total,
          percent: progress.percent,
          foundCount: progress.foundCount,
          currentPlatform: progress.result?.platform
        });
      }
    });

    sendEvent('complete', summary);
  } catch (err) {
    if (!abortController.signal.aborted) {
      sendEvent('error', { error: err.message });
    }
  } finally {
    res.end();
  }
};

export const emailIntelHandler = async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ success: false, error: 'Email address is required.' });
    const data = await OsintEngine.analyzeEmail(email);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const techDetectionHandler = async (req, res) => {
  try {
    const { target } = req.query;
    if (!target) return res.status(400).json({ success: false, error: 'Target URL or domain is required.' });
    const data = await OsintEngine.detectTechnologies(target);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const dorkBuilderHandler = async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ success: false, error: 'Target domain is required.' });
    const data = OsintEngine.generateDorks(domain);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const newsMonitorHandler = async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) return res.status(400).json({ success: false, error: 'Query is required.' });
    const data = await OsintEngine.monitorNewsAndLeaks(query);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};
