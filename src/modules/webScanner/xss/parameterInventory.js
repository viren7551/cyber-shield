/**
 * CyberShield Web Security Scanner - Normalized Parameter Inventory
 * Discovers and indexes all input-accepting parameters from query strings,
 * HTML forms (GET/POST), REST endpoints, and static pages within scope.
 */

/**
 * Build a normalized parameter inventory from crawled endpoints, forms, and input fields.
 * Strictly tests real input fields and authentic parameterized URLs.
 * Never guesses phantom parameters on static pages without input fields.
 * @param {Array<object>} endpoints - Discovered in-scope endpoints from crawler
 * @param {Array<object>} forms - Discovered forms from form analyzer
 * @param {string} targetUrl - Root target application URL
 * @param {Array<object>} inputFields - Discovered input fields from pages
 * @returns {Array<object>} - Normalized parameter inventory entries
 */
export function buildParameterInventory(endpoints = [], forms = [], targetUrl = '', inputFields = []) {
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

  // 1. Extract from crawled endpoints with real query strings
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
              source: 'URL Query',
              targetEndpoint: ep.url,
              pageUrl: ep.url,
              isInputField: false
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
          source: input.type === 'textarea' ? 'Form Textarea' : input.type === 'select' ? 'Form Select' : 'Form Input Field',
          isCsrf,
          isInputField: true,
          pageUrl: form.pageUrl || input.pageUrl || targetUrl,
          formAction: actionUrl,
          formMethod: method,
          placeholder: input.placeholder || '',
          htmlSnippet: input.htmlSnippet || `<input type="${input.type || 'text'}" name="${input.name}">`
        });
      }
    }
  }

  // 3. Extract from standalone input fields discovered on pages
  for (const inp of inputFields) {
    if (!inp || !inp.name) continue;
    const isCsrf = /csrf|xsrf|_token|nonce/i.test(inp.name);
    if (isCsrf) continue;

    const targetAction = inp.formAction || inp.pageUrl || targetUrl;
    if (!targetAction) continue;

    const method = (inp.formMethod || 'GET').toUpperCase();
    const entry = getOrCreateEntry(targetAction, method, 'text/html', inp.source || 'HTML Input Field');

    if (!entry.parameters.has(inp.name)) {
      entry.parameters.set(inp.name, {
        name: inp.name,
        type: inp.type || 'text',
        location: method === 'GET' ? 'Query String' : 'Request Body',
        sampleValue: '',
        source: inp.source || 'Standalone Input Field',
        isCsrf: false,
        isInputField: true,
        pageUrl: inp.pageUrl || targetUrl,
        formAction: targetAction,
        formMethod: method,
        placeholder: inp.placeholder || '',
        htmlSnippet: inp.htmlSnippet || `<input type="${inp.type || 'text'}" name="${inp.name}">`
      });
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
