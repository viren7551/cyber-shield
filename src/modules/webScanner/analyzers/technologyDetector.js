/**
 * CyberShield Web Security Scanner - Passive Technology Fingerprinter
 * Identifies web servers, frontend frameworks, backend runtimes, CMS, and CDNs
 * using multi-factor passive heuristics with confidence ratings.
 */

// Heuristic rule definitions for web technologies
const TECH_RULES = [
  // 1. Next.js
  {
    name: 'Next.js',
    category: 'Fullstack Framework',
    indicators: [
      { type: 'header', key: 'x-nextjs-cache', confidence: 'High' },
      { type: 'header', key: 'x-nextjs-matched-path', confidence: 'High' },
      { type: 'html', pattern: /id="__next"/i, confidence: 'High' },
      { type: 'html', pattern: /\/_next\/static\//i, confidence: 'High' },
      { type: 'script', pattern: /\/_next\/static\//i, confidence: 'High' }
    ]
  },
  // 2. React
  {
    name: 'React',
    category: 'Frontend Library',
    indicators: [
      { type: 'html', pattern: /data-reactroot/i, confidence: 'High' },
      { type: 'html', pattern: /id="root"/i, confidence: 'Medium' },
      { type: 'script', pattern: /react(?:\.production|\.development)?(?:\.min)?\.js/i, confidence: 'High' },
      { type: 'html', pattern: /_jsx|__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED/i, confidence: 'High' }
    ]
  },
  // 3. Vue.js
  {
    name: 'Vue.js',
    category: 'Frontend Framework',
    indicators: [
      { type: 'html', pattern: /data-v-[a-f0-9]{6,8}/i, confidence: 'High' },
      { type: 'script', pattern: /vue(?:\.runtime)?(?:\.esm-bundler)?(?:\.min)?\.js/i, confidence: 'High' },
      { type: 'html', pattern: /id="app"/i, confidence: 'Low' }
    ]
  },
  // 4. Angular
  {
    name: 'Angular',
    category: 'Frontend Framework',
    indicators: [
      { type: 'html', pattern: /<app-root/i, confidence: 'High' },
      { type: 'html', pattern: /ng-version=/i, confidence: 'High' },
      { type: 'html', pattern: /ng-reflect-/i, confidence: 'High' },
      { type: 'script', pattern: /angular(?:\.min)?\.js/i, confidence: 'High' }
    ]
  },
  // 5. Express / Node.js
  {
    name: 'Express (Node.js)',
    category: 'Web Framework',
    indicators: [
      { type: 'header', key: 'x-powered-by', valuePattern: /express/i, confidence: 'High' },
      { type: 'cookie', namePattern: /^connect\.sid$/i, confidence: 'High' }
    ]
  },
  // 6. Nginx
  {
    name: 'Nginx',
    category: 'Web Server / Reverse Proxy',
    indicators: [
      { type: 'header', key: 'server', valuePattern: /nginx/i, confidence: 'High' }
    ]
  },
  // 7. Apache HTTP Server
  {
    name: 'Apache',
    category: 'Web Server',
    indicators: [
      { type: 'header', key: 'server', valuePattern: /apache/i, confidence: 'High' }
    ]
  },
  // 8. PHP
  {
    name: 'PHP',
    category: 'Programming Language',
    indicators: [
      { type: 'header', key: 'x-powered-by', valuePattern: /php/i, confidence: 'High' },
      { type: 'cookie', namePattern: /^phpsessid$/i, confidence: 'High' },
      { type: 'html', pattern: /\.php(?:\?|")/i, confidence: 'Medium' }
    ]
  },
  // 9. WordPress
  {
    name: 'WordPress',
    category: 'Content Management System',
    indicators: [
      { type: 'meta', name: 'generator', valuePattern: /wordpress/i, confidence: 'High' },
      { type: 'html', pattern: /\/wp-content\//i, confidence: 'High' },
      { type: 'html', pattern: /\/wp-includes\//i, confidence: 'High' },
      { type: 'cookie', namePattern: /^wordpress_/i, confidence: 'High' }
    ]
  },
  // 10. Laravel
  {
    name: 'Laravel',
    category: 'Web Framework',
    indicators: [
      { type: 'cookie', namePattern: /^laravel_session$/i, confidence: 'High' },
      { type: 'header', key: 'x-powered-by', valuePattern: /laravel/i, confidence: 'High' }
    ]
  },
  // 11. Django
  {
    name: 'Django',
    category: 'Web Framework',
    indicators: [
      { type: 'cookie', namePattern: /^(?:csrftoken|sessionid)$/i, confidence: 'Medium' },
      { type: 'html', pattern: /csrfmiddlewaretoken/i, confidence: 'High' }
    ]
  },
  // 12. ASP.NET
  {
    name: 'ASP.NET',
    category: 'Web Framework',
    indicators: [
      { type: 'header', key: 'x-powered-by', valuePattern: /asp\.net/i, confidence: 'High' },
      { type: 'header', key: 'x-aspnet-version', confidence: 'High' },
      { type: 'cookie', namePattern: /^asp\.net_sessionid$/i, confidence: 'High' },
      { type: 'html', pattern: /__viewstate/i, confidence: 'High' }
    ]
  },
  // 13. Cloudflare
  {
    name: 'Cloudflare',
    category: 'CDN / DDoS Defense',
    indicators: [
      { type: 'header', key: 'cf-ray', confidence: 'High' },
      { type: 'header', key: 'server', valuePattern: /cloudflare/i, confidence: 'High' }
    ]
  },
  // 14. Bootstrap
  {
    name: 'Bootstrap',
    category: 'UI Framework',
    indicators: [
      { type: 'html', pattern: /bootstrap(?:\.min)?\.(?:css|js)/i, confidence: 'High' },
      { type: 'html', pattern: /class="[^"]*(?:container-fluid|col-md-|navbar-brand)[^"]*"/i, confidence: 'Medium' }
    ]
  },
  // 15. Tailwind CSS
  {
    name: 'Tailwind CSS',
    category: 'UI Framework',
    indicators: [
      { type: 'html', pattern: /class="[^"]*(?:flex\s+items-center|grid\s+grid-cols-|text-gray-|bg-slate-)[^"]*"/i, confidence: 'Medium' }
    ]
  }
];

/**
 * Detect technologies given HTTP headers, HTML body, and cookies
 * @param {object} headers
 * @param {string} htmlBody
 * @param {Array} cookies
 */
export function detectTechnologies(headers = {}, htmlBody = '', cookies = []) {
  const detected = [];
  const normalizedHtml = typeof htmlBody === 'string' ? htmlBody : '';

  // Extract meta tags from HTML
  const metaTags = [];
  const metaRegex = /<meta\s+([^>]*?)>/gi;
  let match;
  while ((match = metaRegex.exec(normalizedHtml)) !== null) {
    const metaAttrs = match[1];
    const nameMatch = metaAttrs.match(/(?:name|property)=["']([^"']*)["']/i);
    const contentMatch = metaAttrs.match(/content=["']([^"']*)["']/i);
    if (nameMatch && contentMatch) {
      metaTags.push({ name: nameMatch[1].toLowerCase(), content: contentMatch[1] });
    }
  }

  // Iterate over technology rules
  for (const rule of TECH_RULES) {
    const evidences = [];
    let highPoints = 0;
    let medPoints = 0;
    let lowPoints = 0;

    for (const ind of rule.indicators) {
      if (ind.type === 'header') {
        const val = headers[ind.key.toLowerCase()];
        if (val) {
          if (!ind.valuePattern || ind.valuePattern.test(val)) {
            evidences.push(`HTTP Header "${ind.key}": "${val}"`);
            if (ind.confidence === 'High') highPoints++;
            else if (ind.confidence === 'Medium') medPoints++;
            else lowPoints++;
          }
        }
      } else if (ind.type === 'cookie') {
        const matchingCookie = cookies.find(c => ind.namePattern.test(c.name));
        if (matchingCookie) {
          evidences.push(`Session Cookie "${matchingCookie.name}"`);
          if (ind.confidence === 'High') highPoints++;
          else if (ind.confidence === 'Medium') medPoints++;
          else lowPoints++;
        }
      } else if (ind.type === 'html' || ind.type === 'script') {
        if (ind.pattern.test(normalizedHtml)) {
          evidences.push(`HTML / Script fingerprint pattern "${ind.pattern.source}"`);
          if (ind.confidence === 'High') highPoints++;
          else if (ind.confidence === 'Medium') medPoints++;
          else lowPoints++;
        }
      } else if (ind.type === 'meta') {
        const tag = metaTags.find(m => m.name === ind.name.toLowerCase());
        if (tag && ind.valuePattern.test(tag.content)) {
          evidences.push(`Meta Tag <meta name="${tag.name}" content="${tag.content}">`);
          if (ind.confidence === 'High') highPoints++;
          else if (ind.confidence === 'Medium') medPoints++;
          else lowPoints++;
        }
      }
    }

    if (evidences.length > 0) {
      let finalConfidence = 'Low';
      if (highPoints >= 1) finalConfidence = 'High';
      else if (medPoints >= 1 || evidences.length >= 2) finalConfidence = 'Medium';

      detected.push({
        name: rule.name,
        category: rule.category,
        confidence: finalConfidence,
        evidences
      });
    }
  }

  return detected;
}
