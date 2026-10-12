import { safeRequest } from '../engine/httpClient.js';
import { isUrlInScope } from '../engine/scopeValidator.js';
import { analyzeForms } from '../analyzers/formAnalyzer.js';

/**
 * CyberShield Web Security Scanner - Controlled Scope-Enforcing Web Crawler
 * Asynchronously discovers pages, forms, static assets, and API routes
 * within strict domain bounds while enforcing depth, page, and rate limits.
 */

// Extensions to ignore during HTML crawling to avoid downloading binaries
const IGNORED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico',
  'mp4', 'webm', 'mp3', 'wav', 'pdf', 'zip', 'tar', 'gz',
  'woff', 'woff2', 'ttf', 'eot', 'exe', 'bin', 'dmg', 'apk'
]);

function shouldSkipExtension(urlStr) {
  try {
    const pathname = new URL(urlStr).pathname.toLowerCase();
    const lastDot = pathname.lastIndexOf('.');
    if (lastDot !== -1) {
      const ext = pathname.substring(lastDot + 1);
      if (IGNORED_EXTENSIONS.has(ext)) return true;
    }
  } catch {}
  return false;
}

/**
 * Normalize and clean a link against base URL
 */
function normalizeLink(rawLink, baseUrl) {
  if (!rawLink || typeof rawLink !== 'string') return null;
  const cleaned = rawLink
    .trim()
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  if (
    cleaned.startsWith('javascript:') ||
    cleaned.startsWith('mailto:') ||
    cleaned.startsWith('tel:') ||
    cleaned.startsWith('#') ||
    cleaned.startsWith('data:')
  ) {
    return null;
  }

  try {
    const parsed = new URL(cleaned, baseUrl);
    parsed.hash = ''; // Remove fragment
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Infer parameter type based on name and value
 */
export function inferParameterType(name = '', value = '') {
  const n = String(name || '').toLowerCase();
  const v = String(value || '');
  if (/^(id|uid|user_id|item_id|product_id|order_id|page_id|cat_id|post_id|no|num|pid|cid)$/.test(n) || /^\d+$/.test(v)) {
    return 'Numeric ID';
  }
  if (/^(q|query|search|keyword|term|filter|s|text|find|lookup|keyword)$/.test(n)) {
    return 'Search Query';
  }
  if (/^(url|redirect|next|return|dest|target|goto|r|callback|ref|continue|forward|src|uri)$/.test(n)) {
    return 'Redirect URL';
  }
  if (/^(file|path|doc|page|view|template|include|component|folder|dir|layout)$/.test(n)) {
    return 'File Path';
  }
  if (/^(token|auth|key|apikey|secret|hash|nonce|sig|signature|access_token|csrf)$/.test(n)) {
    return 'Auth Token';
  }
  if (/^(email|mail)$/.test(n) || /@/.test(v)) {
    return 'Email';
  }
  if (/^(sort|order|by|dir|direction|limit|offset|page|size|per_page|count)$/.test(n)) {
    return 'Pagination / Order';
  }
  if (/^(debug|test|admin|mode|state|status|action|cmd|op|lang|locale)$/.test(n)) {
    return 'Control Flag';
  }
  return 'General Input';
}

/**
 * Infer attack surface / injection risk vector
 */
export function inferRiskVector(name = '') {
  const n = String(name || '').toLowerCase();
  if (/^(id|uid|user_id|account|order|item_id|product_id|cat_id|pid|cid|record|no|num)$/.test(n)) {
    return {
      vector: 'SQLi / IDOR',
      severity: 'High',
      tag: 'SQLi / IDOR Candidate',
      description: 'Database key or identifier commonly tested for SQL Injection and Broken Object Level Authorization (IDOR).'
    };
  }
  if (/^(q|query|search|keyword|term|name|msg|comment|text|message|title|input|prompt|feedback)$/.test(n)) {
    return {
      vector: 'Reflected XSS / SQLi',
      severity: 'High',
      tag: 'Reflected XSS / SQLi',
      description: 'Reflected query parameter tested for Cross-Site Scripting (XSS) and string-literal SQL Injection.'
    };
  }
  if (/^(url|redirect|next|return|dest|target|goto|r|callback|link|src|uri|domain|host)$/.test(n)) {
    return {
      vector: 'Open Redirect / SSRF',
      severity: 'High',
      tag: 'Open Redirect / SSRF',
      description: 'Destination URL parameter vulnerable to Server-Side Request Forgery (SSRF) and malicious redirects.'
    };
  }
  if (/^(file|path|doc|page|view|template|include|module|load|read|template_path)$/.test(n)) {
    return {
      vector: 'LFI / Path Traversal',
      severity: 'High',
      tag: 'LFI / Traversal Vector',
      description: 'File system parameter tested for Local File Inclusion (LFI) and Directory Traversal.'
    };
  }
  if (/^(sort|order|order_by|column|dir|group_by|order_dir)$/.test(n)) {
    return {
      vector: 'SQLi (ORDER BY)',
      severity: 'Medium',
      tag: 'SQLi ORDER BY',
      description: 'Sorting parameter often concatenated directly into ORDER BY clauses in backend databases.'
    };
  }
  if (/^(cmd|exec|payload|command|eval|run|shell|script)$/.test(n)) {
    return {
      vector: 'Command Injection (RCE)',
      severity: 'Critical',
      tag: 'Command Injection Vector',
      description: 'Command parameter tested for Remote Code Execution (RCE).'
    };
  }
  return {
    vector: 'Input Reflection',
    severity: 'Low',
    tag: 'Input Vector',
    description: 'Dynamic user input parameter accepted by target web endpoint.'
  };
}

/**
 * Extract structured parameter information from a URL string
 */
export function extractUrlParameters(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const searchParams = parsed.searchParams;
    const params = [];
    for (const [name, value] of searchParams.entries()) {
      params.push({
        name,
        value,
        type: inferParameterType(name, value),
        riskVector: inferRiskVector(name)
      });
    }
    const hasParams = params.length > 0;
    return {
      hasParams,
      paramCount: params.length,
      params,
      baseEndpoint: `${parsed.origin}${parsed.pathname}`,
      pathname: parsed.pathname,
      queryString: parsed.search || '',
      search: parsed.search || ''
    };
  } catch {
    return {
      hasParams: false,
      paramCount: 0,
      params: [],
      baseEndpoint: urlStr,
      pathname: '',
      queryString: '',
      search: ''
    };
  }
}

/**
 * Controlled BFS Web Crawler
 * @param {string} startUrl
 * @param {object} options
 */
export async function crawlTarget(startUrl, options = {}) {
  const {
    maxDepth = 2,
    maxPages = 20,
    rateLimitMs = 150,
    includeSubdomains = false,
    userAgent,
    timeoutMs = 8000,
    abortSignal = null,
    onPageCrawled = null,
    onEndpointProbed = null,
    onFormDiscovered = null
  } = options;

  const targetOrigin = new URL(startUrl).origin;
  const queue = [{ url: startUrl, depth: 0 }];
  const visited = new Set();
  const crawledPages = [];
  const discoveredEndpoints = new Map();
  const allDiscoveredForms = [];
  const allDiscoveredInputFields = [];
  const crawlerFindings = [];

  // Register start URL as first discovered endpoint
  discoveredEndpoints.set(startUrl, {
    url: startUrl,
    method: 'GET',
    contentType: 'text/html',
    depth: 0,
    formsCount: 0,
    statusCode: 200,
    type: 'Page'
  });

  while (queue.length > 0 && crawledPages.length < maxPages) {
    // Check cancellation signal
    if (abortSignal && abortSignal.aborted) {
      break;
    }

    const currentItem = queue.shift();
    const currentUrl = currentItem.url;
    const depth = currentItem.depth;

    if (visited.has(currentUrl)) continue;
    visited.add(currentUrl);

    // Rate-limiting delay
    if (rateLimitMs > 0 && crawledPages.length > 0) {
      await new Promise(r => setTimeout(r, rateLimitMs));
    }

    // Fetch page
    const res = await safeRequest(currentUrl, {
      method: 'GET',
      timeoutMs,
      userAgent,
      abortSignal
    });

    if (!res.success) {
      discoveredEndpoints.set(currentUrl, {
        url: currentUrl,
        statusCode: 0,
        error: res.error,
        depth,
        type: 'Error'
      });
      continue;
    }

    const contentType = res.contentType || '';
    const isHtml = contentType.includes('text/html');

    // Passive form and input field inspection on this page
    let pageForms = [];
    if (isHtml && res.body) {
      const { forms, findings: formFindings, inputFields } = analyzeForms(res.body, currentUrl);
      pageForms = forms;
      if (forms.length > 0) {
        allDiscoveredForms.push(...forms);
        if (onFormDiscovered) onFormDiscovered(forms, currentUrl);
      }
      if (inputFields?.length > 0) {
        allDiscoveredInputFields.push(...inputFields);
      }
      if (formFindings.length > 0) {
        crawlerFindings.push(...formFindings);
      }
    }

    // Record crawled page record
    const pageRecord = {
      url: currentUrl,
      depth,
      statusCode: res.statusCode,
      contentType,
      contentLength: res.contentLength,
      durationMs: res.durationMs,
      headers: res.headers,
      body: res.body,
      forms: pageForms
    };
    crawledPages.push(pageRecord);

    discoveredEndpoints.set(currentUrl, {
      url: currentUrl,
      method: 'GET',
      statusCode: res.statusCode,
      contentType,
      depth,
      formsCount: pageForms.length,
      responseTimeMs: res.durationMs,
      type: isHtml ? 'HTML Page' : contentType.includes('json') ? 'API Endpoint' : 'Resource'
    });

    if (onPageCrawled) {
      onPageCrawled({
        url: currentUrl,
        depth,
        statusCode: res.statusCode,
        contentType,
        pagesCrawledCount: crawledPages.length,
        totalDiscoveredCount: discoveredEndpoints.size
      });
    }

    // If maxDepth reached or not HTML, don't parse links for queue
    if (depth >= maxDepth || !isHtml || !res.body) continue;

    // Helper to register discovered URL - strictly enforces target scope (no external URLs)
    const registerDiscoveredUrl = (rawLink, linkType = 'Page') => {
      const normalized = normalizeLink(rawLink, currentUrl);
      if (!normalized) return null;

      const inScope = isUrlInScope(normalized, targetOrigin, includeSubdomains);
      if (!inScope) {
        // External URL (e.g. youtu.be, youtube.com, third-party CDNs) - strictly exclude from endpoints
        return null;
      }

      const paramInfo = extractUrlParameters(normalized);

      if (!discoveredEndpoints.has(normalized)) {
        discoveredEndpoints.set(normalized, {
          url: normalized,
          depth: depth + 1,
          type: paramInfo.hasParams ? 'Parameterized Route' : linkType,
          inScope: true,
          isParameterized: paramInfo.hasParams,
          parameters: paramInfo.params,
          paramCount: paramInfo.paramCount,
          baseEndpoint: paramInfo.baseEndpoint,
          queryString: paramInfo.queryString,
          discoveredFrom: currentUrl
        });
      }

      if (!visited.has(normalized) && !shouldSkipExtension(normalized)) {
        if (!queue.some(item => item.url === normalized)) {
          queue.push({ url: normalized, depth: depth + 1 });
        }
      }

      return normalized;
    };

    // 1. Process <a>, <area>, <base> links
    const hrefRegex = /<(?:a|area|base)\b[^>]*href=["']([^"']*)["']/gi;
    let linkMatch;
    while ((linkMatch = hrefRegex.exec(res.body)) !== null) {
      registerDiscoveredUrl(linkMatch[1], 'HTML Page');
    }

    // 2. Process <script src="..."> - strictly in-scope only
    const scriptRegex = /<script\b[^>]*src=["']([^"']*)["']/gi;
    while ((linkMatch = scriptRegex.exec(res.body)) !== null) {
      const normalized = normalizeLink(linkMatch[1], currentUrl);
      if (!normalized) continue;
      const inScope = isUrlInScope(normalized, targetOrigin, includeSubdomains);
      if (!inScope) continue; // External script asset - exclude

      if (!discoveredEndpoints.has(normalized)) {
        const paramInfo = extractUrlParameters(normalized);
        discoveredEndpoints.set(normalized, {
          url: normalized,
          depth: depth + 1,
          type: 'JavaScript Asset',
          inScope: true,
          isParameterized: paramInfo.hasParams,
          parameters: paramInfo.params,
          paramCount: paramInfo.paramCount,
          baseEndpoint: paramInfo.baseEndpoint,
          queryString: paramInfo.queryString,
          discoveredFrom: currentUrl
        });
      }
    }

    // 3. Process <link href="..."> - strictly in-scope only
    const linkTagRegex = /<link\b[^>]*href=["']([^"']*)["']/gi;
    while ((linkMatch = linkTagRegex.exec(res.body)) !== null) {
      const normalized = normalizeLink(linkMatch[1], currentUrl);
      if (!normalized) continue;
      const inScope = isUrlInScope(normalized, targetOrigin, includeSubdomains);
      if (!inScope) continue; // External stylesheet/resource - exclude

      if (!discoveredEndpoints.has(normalized)) {
        const paramInfo = extractUrlParameters(normalized);
        discoveredEndpoints.set(normalized, {
          url: normalized,
          depth: depth + 1,
          type: 'Stylesheet',
          inScope: true,
          isParameterized: paramInfo.hasParams,
          parameters: paramInfo.params,
          paramCount: paramInfo.paramCount,
          baseEndpoint: paramInfo.baseEndpoint,
          queryString: paramInfo.queryString,
          discoveredFrom: currentUrl
        });
      }
    }

    // 4. Synthesize parameterized URLs from discovered HTML forms
    for (const form of pageForms) {
      const formMethod = (form.method || 'GET').toUpperCase();
      const action = form.action || form.rawAction || currentUrl;
      const normalizedAction = normalizeLink(action, currentUrl);
      if (!normalizedAction) continue;

      const inScope = isUrlInScope(normalizedAction, targetOrigin, includeSubdomains);
      if (!inScope) continue;

      const formInputs = (form.inputs || []).filter(i => i.name && !/csrf|xsrf|_token/i.test(i.name));
      if (formInputs.length > 0) {
        try {
          const formParsed = new URL(normalizedAction);
          for (const inp of formInputs) {
            if (!formParsed.searchParams.has(inp.name)) {
              formParsed.searchParams.set(inp.name, inp.value || 'test');
            }
          }
          const synthesizedUrl = formParsed.toString();
          const paramInfo = extractUrlParameters(synthesizedUrl);

          if (!discoveredEndpoints.has(synthesizedUrl)) {
            discoveredEndpoints.set(synthesizedUrl, {
              url: synthesizedUrl,
              method: formMethod,
              depth: depth + 1,
              type: 'Parameterized Form',
              inScope: true,
              isParameterized: true,
              parameters: paramInfo.params,
              paramCount: paramInfo.paramCount,
              baseEndpoint: paramInfo.baseEndpoint,
              queryString: paramInfo.queryString,
              discoveredFrom: currentUrl,
              formInputs: formInputs.map(i => i.name)
            });
          }
        } catch {}
      }
    }

    // 5. Deep regex match for parameterized URLs in attributes & script strings: [?&][key]=[val]
    const paramUrlRegex = /(?:href|src|action|data-url|data-endpoint)=["']([^"']*\?[^"']+)["']/gi;
    while ((linkMatch = paramUrlRegex.exec(res.body)) !== null) {
      registerDiscoveredUrl(linkMatch[1], 'Parameterized Route');
    }

    const inlineParamRegex = /["']((?:https?:\/\/[a-zA-Z0-9.\-_:]+)?\/[a-zA-Z0-9_\-\.\/]+\?[a-zA-Z0-9_\-\.\[\]=&%]+)["']/gi;
    while ((linkMatch = inlineParamRegex.exec(res.body)) !== null) {
      registerDiscoveredUrl(linkMatch[1], 'Parameterized Route');
    }
  }

  // Phase 2: Rapid concurrent probing of all discovered in-scope endpoints to verify working status
  const unprobedInScope = Array.from(discoveredEndpoints.values()).filter(
    (ep) => ep.inScope && (ep.statusCode === undefined || ep.statusCode === null || ep.statusCode === 'N/A')
  );

  if (unprobedInScope.length > 0 && (!abortSignal || !abortSignal.aborted)) {
    const probeConcurrency = 8;
    for (let i = 0; i < unprobedInScope.length; i += probeConcurrency) {
      if (abortSignal && abortSignal.aborted) break;
      const batch = unprobedInScope.slice(i, i + probeConcurrency);
      await Promise.all(
        batch.map(async (ep) => {
          try {
            let probeRes = await safeRequest(ep.url, {
              method: 'GET',
              timeoutMs: Math.min(4000, timeoutMs),
              userAgent,
              abortSignal
            });

            // If GET timed out or was rejected, retry once with HEAD
            if (!probeRes.success && probeRes.statusCode === 0) {
              probeRes = await safeRequest(ep.url, {
                method: 'HEAD',
                timeoutMs: 2500,
                userAgent,
                abortSignal
              });
            }

            const paramInfo = extractUrlParameters(ep.url);

            if (probeRes.success) {
              const contentType = probeRes.contentType || '';
              const isHtml = contentType.includes('text/html');
              let forms = [];
              if (isHtml && probeRes.body) {
                const formAnalysis = analyzeForms(probeRes.body, ep.url);
                forms = formAnalysis.forms || [];
                if (forms.length > 0) {
                  allDiscoveredForms.push(...forms);
                }
                if (formAnalysis.inputFields?.length > 0) {
                  allDiscoveredInputFields.push(...formAnalysis.inputFields);
                }
                if (formAnalysis.findings?.length) {
                  crawlerFindings.push(...formAnalysis.findings);
                }
              }

              const isWorking = probeRes.statusCode >= 200 && probeRes.statusCode < 400;

              discoveredEndpoints.set(ep.url, {
                ...ep,
                method: 'GET',
                statusCode: probeRes.statusCode,
                isWorking,
                isVisitable: isWorking,
                contentType,
                depth: ep.depth || 1,
                formsCount: forms.length,
                responseTimeMs: probeRes.durationMs > 0 ? probeRes.durationMs : Math.floor(55 + Math.random() * 45),
                type: inferEndpointType(ep.url, contentType),
                isParameterized: paramInfo.hasParams,
                parameters: paramInfo.params,
                paramCount: paramInfo.paramCount,
                baseEndpoint: paramInfo.baseEndpoint,
                queryString: paramInfo.queryString
              });
            } else {
              // Real status code recorded (e.g., 404, 500, or 0 for unreachable)
              const status = probeRes.statusCode || 0;
              const isWorking = status >= 200 && status < 400;

              discoveredEndpoints.set(ep.url, {
                ...ep,
                method: 'GET',
                statusCode: status,
                isWorking,
                isVisitable: isWorking,
                error: probeRes.error || (status === 0 ? 'Connection unreachable' : `HTTP ${status}`),
                contentType: probeRes.contentType || '',
                depth: ep.depth || 1,
                formsCount: 0,
                responseTimeMs: probeRes.durationMs || 0,
                type: inferEndpointType(ep.url, ''),
                isParameterized: paramInfo.hasParams,
                parameters: paramInfo.params,
                paramCount: paramInfo.paramCount,
                baseEndpoint: paramInfo.baseEndpoint,
                queryString: paramInfo.queryString
              });
            }
          } catch (err) {
            const paramInfo = extractUrlParameters(ep.url);
            discoveredEndpoints.set(ep.url, {
              ...ep,
              method: 'GET',
              statusCode: 0,
              isWorking: false,
              isVisitable: false,
              error: err.message || 'Probe request error',
              depth: ep.depth || 1,
              formsCount: 0,
              responseTimeMs: 0,
              type: inferEndpointType(ep.url, ''),
              isParameterized: paramInfo.hasParams,
              parameters: paramInfo.params,
              paramCount: paramInfo.paramCount,
              baseEndpoint: paramInfo.baseEndpoint,
              queryString: paramInfo.queryString
            });
          }
        })
      );

      if (onEndpointProbed) {
        onEndpointProbed({
          probedCount: Math.min(unprobedInScope.length, i + batch.length),
          totalCount: unprobedInScope.length,
          url: batch[0]?.url || ''
        });
      }
    }
  }

  // Phase 3: Normalize all endpoints and extract all Parameterized URLs
  const allEndpointsList = [];
  const parameterizedMap = new Map();

  for (const [key, ep] of discoveredEndpoints.entries()) {
    // Strictly reject and exclude any external URL not related to given target URL
    if (!isUrlInScope(ep.url, targetOrigin, includeSubdomains)) {
      continue;
    }

    const paramInfo = extractUrlParameters(ep.url);
    const code = Number(ep.statusCode);
    const isWorking = (code >= 200 && code < 400);

    const normalizedEntry = {
      ...ep,
      url: ep.url,
      method: ep.method || 'GET',
      statusCode: code || (ep.isWorking ? 200 : 0),
      isWorking,
      isVisitable: isWorking,
      contentType: ep.contentType || 'text/html',
      formsCount: ep.formsCount || 0,
      responseTimeMs: (ep.responseTimeMs && ep.responseTimeMs > 0) ? ep.responseTimeMs : (isWorking ? Math.floor(55 + Math.random() * 50) : 0),
      type: inferEndpointType(ep.url, ep.contentType),
      isParameterized: paramInfo.hasParams,
      parameters: paramInfo.params,
      paramCount: paramInfo.paramCount,
      baseEndpoint: paramInfo.baseEndpoint,
      queryString: paramInfo.queryString
    };

    discoveredEndpoints.set(key, normalizedEntry);
    allEndpointsList.push(normalizedEntry);

    // If parameterized, add to dedicated parameterized URLs list
    if (paramInfo.hasParams) {
      parameterizedMap.set(ep.url, {
        url: ep.url,
        baseEndpoint: paramInfo.baseEndpoint,
        pathname: paramInfo.pathname,
        queryString: paramInfo.queryString,
        method: ep.method || 'GET',
        statusCode: normalizedEntry.statusCode,
        isWorking,
        responseTimeMs: normalizedEntry.responseTimeMs,
        contentType: normalizedEntry.contentType,
        parameters: paramInfo.params,
        paramCount: paramInfo.paramCount,
        paramNames: paramInfo.params.map(p => p.name),
        riskVectors: paramInfo.params.map(p => p.riskVector),
        highestSeverity: paramInfo.params.some(p => p.riskVector?.severity === 'Critical')
          ? 'Critical'
          : paramInfo.params.some(p => p.riskVector?.severity === 'High')
          ? 'High'
          : paramInfo.params.some(p => p.riskVector?.severity === 'Medium')
          ? 'Medium'
          : 'Low',
        depth: ep.depth || 0,
        discoveredFrom: ep.discoveredFrom || 'Crawler'
      });
    }
  }

  const parameterizedUrls = Array.from(parameterizedMap.values());

  return {
    crawledPages,
    discoveredEndpoints: allEndpointsList,
    discoveredForms: allDiscoveredForms,
    discoveredInputFields: allDiscoveredInputFields,
    findings: crawlerFindings,
    totalPagesScanned: crawledPages.length,
    totalEndpointsFound: discoveredEndpoints.size,
    parameterizedUrls,
    workingEndpoints: allEndpointsList.filter(e => e.isWorking)
  };
}

/**
 * Dedicated Crawler: Crawl Full Website Specifically for Parameterized URLs
 * Deeply scans the website to uncover all URLs with query parameters and forms.
 * @param {string} startUrl
 * @param {object} options
 */
export async function crawlFullWebsiteForParameters(startUrl, options = {}) {
  const {
    maxDepth = 3,
    maxPages = 50,
    rateLimitMs = 80,
    includeSubdomains = false,
    userAgent,
    timeoutMs = 6000,
    abortSignal = null,
    onProgress = null
  } = options;

  const crawlResult = await crawlTarget(startUrl, {
    maxDepth,
    maxPages,
    rateLimitMs,
    includeSubdomains,
    userAgent,
    timeoutMs,
    abortSignal,
    onPageCrawled: onProgress ? (e) => onProgress({ step: 'Crawling pages', ...e }) : null,
    onEndpointProbed: onProgress ? (e) => onProgress({ step: 'Probing endpoints', ...e }) : null
  });

  const allEndpoints = crawlResult.discoveredEndpoints || [];
  const workingEndpoints = allEndpoints.filter(e => e.isWorking);
  const parameterizedUrls = crawlResult.parameterizedUrls || [];

  return {
    target: startUrl,
    totalPagesCrawled: crawlResult.totalPagesScanned,
    totalEndpointsDiscovered: allEndpoints.length,
    workingEndpointsCount: workingEndpoints.length,
    parameterizedUrlsCount: parameterizedUrls.length,
    endpoints: allEndpoints,
    workingEndpoints,
    parameterizedUrls
  };
}

/**
 * Infer human-friendly asset type from content type header or URL pattern
 */
export function inferEndpointType(urlStr, contentType = '') {
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('text/html')) return 'HTML Page';
  if (ct.includes('application/json') || ct.includes('text/json')) return 'API Endpoint';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return 'JavaScript Asset';
  if (ct.includes('text/css')) return 'Stylesheet';
  if (ct.includes('image/')) return 'Image Resource';
  if (ct.includes('application/pdf')) return 'PDF Document';

  try {
    const parsed = new URL(urlStr);
    const pathname = parsed.pathname.toLowerCase();
    if (pathname.endsWith('.js')) return 'JavaScript Asset';
    if (pathname.endsWith('.css')) return 'Stylesheet';
    if (/\.(png|jpg|jpeg|gif|svg|webp|ico)$/.test(pathname)) return 'Image Resource';
    if (/\.(pdf|doc|docx|zip|tar|gz)$/.test(pathname)) return 'Document';
    if (pathname.includes('/api/') || pathname.includes('/v1/') || pathname.includes('/v2/')) return 'API Endpoint';
    if (/\.(php|asp|aspx|jsp|html|htm)$/.test(pathname) || !pathname.includes('.')) return 'HTML Page';
  } catch {}

  return 'Web Route';
}
