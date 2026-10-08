/**
 * CyberShield Web Security Scanner - Normalized Parameter Inventory
 * Discovers and indexes all input-accepting parameters from query strings,
 * HTML forms (GET/POST), REST endpoints, and static pages within scope.
 */

/**
 * Build a normalized parameter inventory from crawled endpoints and forms.
 * @param {Array<object>} endpoints - Discovered in-scope endpoints from crawler
 * @param {Array<object>} forms - Discovered forms from form analyzer
 * @param {string} targetUrl - Root target application URL
 * @returns {Array<object>} - Normalized parameter inventory entries
 */
export function buildParameterInventory(endpoints = [], forms = [], targetUrl = '') {
  const inventoryMap = new Map(); // key: `${method}:${endpointUrl}` -> inventoryEntry

  // Helper to get or create entry
  function getOrCreateEntry(url, method = 'GET', contentType = 'text/html', source = 'Crawler') {
    let cleanUrl = url;
    try {
      const parsed = new URL(url);
      cleanUrl = `${parsed.origin}${parsed.pathname}`;
    } catch {}

    const key = `${method.toUpperCase()}:${cleanUrl}`;
    if (!inventoryMap.has(key)) {
      inventoryMap.set(key, {
        endpoint: cleanUrl,
        fullUrl: url,
        method: method.toUpperCase(),
        parameters: new Map(), // name -> paramObj
        source,
        contentType: contentType || 'text/html',
        discoveredAt: new Date().toISOString()
      });
    }
    return inventoryMap.get(key);
  }

  // 1. Extract from crawled endpoints with query strings
  for (const ep of endpoints) {
    if (!ep || !ep.url) continue;
    try {
      const parsed = new URL(ep.url);
      const keys = Array.from(parsed.searchParams.keys());
      if (keys.length > 0) {
        const entry = getOrCreateEntry(ep.url, 'GET', ep.contentType || 'text/html', 'QueryString');
        for (const key of keys) {
          if (!entry.parameters.has(key)) {
            entry.parameters.set(key, {
              name: key,
              type: 'query',
              location: 'Query String',
              sampleValue: parsed.searchParams.get(key) || '',
              source: 'URL Query'
            });
          }
        }
      }
    } catch {}
  }

  // 2. Extract from discovered forms
  for (const form of forms) {
    if (!form) continue;
    const actionUrl = form.action || form.rawAction || targetUrl;
    if (!actionUrl) continue;

    const method = (form.method || 'GET').toUpperCase();
    const entry = getOrCreateEntry(actionUrl, method, 'application/x-www-form-urlencoded', 'HTML Form');

    for (const input of form.inputs || []) {
      if (!input || !input.name) continue;
      // Skip csrf tokens and password fields from general reflection injection probes
      const isCsrf = /csrf|xsrf|_token|nonce/i.test(input.name);
      if (!entry.parameters.has(input.name)) {
        entry.parameters.set(input.name, {
          name: input.name,
          type: input.type || 'text',
          location: method === 'GET' ? 'Query String' : 'Request Body',
          sampleValue: '',
          source: input.type === 'textarea' ? 'Form Textarea' : input.type === 'select' ? 'Form Select' : 'Form Input',
          isCsrf
        });
      }
    }
  }

  // 3. Ensure root URL and common search pages have candidate reflection parameters
  const rootTargets = [];
  if (targetUrl) rootTargets.push(targetUrl);
  for (const ep of endpoints.slice(0, 5)) {
    if (ep && ep.url && !ep.url.includes('?') && (ep.type === 'HTML Page' || ep.contentType?.includes('html'))) {
      rootTargets.push(ep.url);
    }
  }

  const COMMON_CANDIDATE_PARAMS = ['search', 'q', 'query', 'keyword', 'name', 'id', 'msg'];
  for (const rUrl of rootTargets) {
    const entry = getOrCreateEntry(rUrl, 'GET', 'text/html', 'Crawler');
    if (entry.parameters.size === 0) {
      for (const p of COMMON_CANDIDATE_PARAMS.slice(0, 4)) {
        entry.parameters.set(p, {
          name: p,
          type: 'text',
          location: 'Query String',
          sampleValue: '',
          source: 'Standard Input Candidate'
        });
      }
    }
  }

  // Convert map to serializable array
  const finalInventory = [];
  for (const entry of inventoryMap.values()) {
    finalInventory.push({
      endpoint: entry.endpoint,
      fullUrl: entry.fullUrl,
      method: entry.method,
      source: entry.source,
      contentType: entry.contentType,
      parameters: Array.from(entry.parameters.values()),
      discoveredAt: entry.discoveredAt
    });
  }

  return finalInventory;
}
