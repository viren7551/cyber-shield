import dns from 'dns/promises';

/**
 * 1. Domain Intelligence: DNS records, nameservers, MX, TXT, A/AAAA, SOA

 */
export async function lookupDomainIntel(rawDomain) {
  const domain = cleanDomain(rawDomain);
  const results = {
    domain,
    timestamp: new Date().toISOString(),
    a: [],
    aaaa: [],
    mx: [],
    ns: [],
    txt: [],
    soa: null,
    cname: [],
    securityAudit: {
      hasSpf: false,
      spfRecord: null,
      hasDmarc: false,
      dmarcRecord: null,
      hasMx: false,
      hasDnssec: false
    }
  };

  const safeResolve = async (fn, fallback = []) => {
    try {
      return await fn();
    } catch {
      return fallback;
    }
  };

  const [a, aaaa, mx, ns, txt, soa, cname, dmarcTxt] = await Promise.all([
    safeResolve(() => dns.resolve4(domain)),
    safeResolve(() => dns.resolve6(domain)),
    safeResolve(() => dns.resolveMx(domain)),
    safeResolve(() => dns.resolveNs(domain)),
    safeResolve(() => dns.resolveTxt(domain)),
    safeResolve(() => dns.resolveSoa(domain), null),
    safeResolve(() => dns.resolveCname(domain)),
    safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`))
  ]);

  results.a = a;
  results.aaaa = aaaa;
  results.mx = mx.sort((x, y) => x.priority - y.priority);
  results.ns = ns;
  results.txt = txt.map((chunk) => (Array.isArray(chunk) ? chunk.join(' ') : chunk));
  results.soa = soa;
  results.cname = cname;

  // Security checks
  const spf = results.txt.find((t) => t.toLowerCase().startsWith('v=spf1'));
  if (spf) {
    results.securityAudit.hasSpf = true;
    results.securityAudit.spfRecord = spf;
  }

  const dmarcFlat = dmarcTxt.map((chunk) => (Array.isArray(chunk) ? chunk.join(' ') : chunk));
  const dmarc = dmarcFlat.find((t) => t.toLowerCase().startsWith('v=dmarc1'));
  if (dmarc) {
    results.securityAudit.hasDmarc = true;
    results.securityAudit.dmarcRecord = dmarc;
  }

  results.securityAudit.hasMx = results.mx.length > 0;

  return results;
}

/**
 * 2. Subdomain Discovery: Multi-source intelligence combining:
 *    - crt.name Subdomain Index (High-speed Certificate Transparency & passive datasets)
 *    - CertSpotter Certificate Transparency API
 *    - HackerTarget Passive Host Search
 *    - 80+ High-Frequency DNS Prefix Active Probing
 *    - Automated IP & Live Host Verification
 */
export async function discoverSubdomains(rawDomain) {
  const domain = cleanDomain(rawDomain);
  const subMap = new Map();
  const sourceStats = [];

  const addSub = (name, source, ip = null, firstSeen = null) => {
    if (!name) return;
    let clean = name.trim().toLowerCase();
    if (clean.startsWith('*.')) clean = clean.slice(2);
    if (clean.startsWith('.')) clean = clean.slice(1);
    clean = clean.replace(/:\d+$/, '');
    if (clean && clean.endsWith('.' + domain) && clean !== domain) {
      if (!subMap.has(clean)) {
        subMap.set(clean, {
          subdomain: clean,
          ip: ip || null,
          isLive: Boolean(ip),
          sources: [source],
          firstSeen: firstSeen || null
        });
      } else {
        const item = subMap.get(clean);
        if (!item.sources.includes(source)) item.sources.push(source);
        if (!item.ip && ip) {
          item.ip = ip;
          item.isLive = true;
        }
        if (!item.firstSeen && firstSeen) {
          item.firstSeen = firstSeen;
        }
      }
    }
  };

  // 1. crt.name Subdomain Index API (High-speed indexed CT & DNS datasets)
  const p1 = (async () => {
    let crtNameSuccess = false;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(`https://crt.name/v1/search?apex=${encodeURIComponent(domain)}&format=json&dates=1`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'CyberShield-Recon/1.0' }
      });
      clearTimeout(timeout);
      if (res.ok) {
        const data = await res.json();
        let crtCount = 0;
        if (Array.isArray(data)) {
          for (const item of data) {
            const sub = item.sub || item.subdomain || item.name;
            if (sub) {
              addSub(sub, 'crt.name Index', null, item.first_seen || null);
              crtCount++;
            }
          }
        }
        if (crtCount > 0) {
          sourceStats.push(`crt.name: ${crtCount} subdomains`);
          crtNameSuccess = true;
        }
      }
    } catch {}

    // Fallback to crt.sh if crt.name had 0 records or encountered rate limits
    if (!crtNameSuccess) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberShield' }
        });
        clearTimeout(timeout);
        if (res.ok) {
          const data = await res.json();
          let crtCount = 0;
          if (Array.isArray(data)) {
            for (const item of data) {
              const names = (item.name_value || '').split('\n');
              for (const name of names) {
                addSub(name, 'crt.sh Archive');
                crtCount++;
              }
            }
          }
          if (crtCount > 0) sourceStats.push(`crt.sh CT: ${crtCount} logs`);
        }
      } catch {}
    }
  })();

  // 2. HackerTarget Host Search
  const p2 = (async () => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 7000);
      const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'CyberShield-Recon/1.0' }
      });
      clearTimeout(timeout);
      if (res.ok) {
        const text = await res.text();
        let htCount = 0;
        for (const line of text.split('\n')) {
          const parts = line.split(',');
          if (parts[0] && parts[0].includes('.')) {
            addSub(parts[0], 'HackerTarget', parts[1]?.trim() || null);
            htCount++;
          }
        }
        if (htCount > 0) sourceStats.push(`HackerTarget: ${htCount} records`);
      }
    } catch {}
  })();

  // 3. CertSpotter Certificate Transparency API
  const p3 = (async () => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'CyberShield-Recon/1.0' }
      });
      clearTimeout(timeout);
      if (res.ok) {
        const data = await res.json();
        let csCount = 0;
        if (Array.isArray(data)) {
          for (const item of data) {
            if (Array.isArray(item.dns_names)) {
              for (const name of item.dns_names) {
                addSub(name, 'CertSpotter CT');
                csCount++;
              }
            }
          }
        }
        if (csCount > 0) sourceStats.push(`CertSpotter CT: ${csCount} certificates`);
      }
    } catch {}
  })();

  // 4. High-Density Active DNS Prefix Probing (80+ Common Prefixes)
  const commonPrefixes = [
    'www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'vpn', 'remote',
    'app', 'portal', 'auth', 'cloud', 'cdn', 'blog', 'shop', 'git', 'secure',
    'status', 'docs', 'help', 'assets', 'media', 'support', 'internal', 'corp',
    'sso', 'billing', 'accounts', 'raw', 'gist', 'pages', 'education', 'desktop',
    'classroom', 'collector', 'codeload', 'central', 'alive', 'render', 'beta',
    'preview', 'static', 'images', 'img', 'upload', 'download', 'files', 'share',
    'gateway', 'connect', 'login', 'id', 'registry', 'proxy', 'relay', 'lb',
    'mx', 'ns1', 'ns2', 'ns3', 'ftp', 'webmail', 'm', 'forum', 'store', 'pay',
    'checkout', 'dashboard', 'jira', 'jenkins', 'ci', 'cd', 'qa', 'uat', 'sandbox',
    'demo', 'direct', 'router', 'edge', 'node', 'cluster', 'db'
  ];

  const p4 = Promise.all(
    commonPrefixes.map(async (prefix) => {
      const sub = `${prefix}.${domain}`;
      try {
        const ips = await dns.resolve4(sub);
        if (ips && ips.length > 0) {
          addSub(sub, 'Active DNS Probe', ips[0]);
        }
      } catch {}
    })
  );

  await Promise.allSettled([p1, p2, p3, p4]);

  const allSubs = Array.from(subMap.values());

  // Concurrently resolve IPs for up to 60 subdomains that lack IP addresses
  const unresolved = allSubs.filter((s) => !s.ip).slice(0, 60);
  await Promise.all(
    unresolved.map(async (item) => {
      try {
        const ips = await dns.resolve4(item.subdomain);
        if (ips && ips.length > 0) {
          item.ip = ips[0];
          item.isLive = true;
        }
      } catch {}
    })
  );

  // Sort: Live/resolved subdomains first, then alphabetically
  allSubs.sort((a, b) => {
    if (a.isLive !== b.isLive) return a.isLive ? -1 : 1;
    return a.subdomain.localeCompare(b.subdomain);
  });

  const liveCount = allSubs.filter((s) => s.isLive).length;

  return {
    domain,
    count: allSubs.length,
    liveCount,
    subdomains: allSubs.slice(0, 1500),
    sources: sourceStats
  };
}

/**
 * 3. WHOIS / RDAP Lookup: Official ICANN REST RDAP protocol
 */
export async function lookupWhoisRdap(rawDomain) {
  const domain = cleanDomain(rawDomain);
  const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(rdapUrl, {
      signal: controller.signal,
      headers: { Accept: 'application/rdap+json, application/json' }
    });
    clearTimeout(timeout);

    if (!res.ok) {
      throw new Error(`RDAP query returned status ${res.status}`);
    }

    const data = await res.json();

    let registrar = 'Unknown';
    let registrantOrg = null;
    let registrantCountry = null;

    if (Array.isArray(data.entities)) {
      for (const ent of data.entities) {
        if (ent.roles?.includes('registrar')) {
          registrar = ent.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || ent.handle || registrar;
        }
        if (ent.roles?.includes('registrant')) {
          registrantOrg = ent.vcardArray?.[1]?.find((v) => v[0] === 'org')?.[3] || null;
          const adr = ent.vcardArray?.[1]?.find((v) => v[0] === 'adr');
          if (adr && Array.isArray(adr[3])) {
            registrantCountry = adr[3][6] || null;
          }
        }
      }
    }

    const events = {};
    if (Array.isArray(data.events)) {
      for (const ev of data.events) {
        events[ev.eventAction] = ev.eventDate;
      }
    }

    const nameservers = (data.nameservers || []).map((ns) => ns.ldhName || ns.handle);

    return {
      domain,
      handle: data.handle || domain,
      status: data.status || [],
      registrar,
      registrantOrg,
      registrantCountry,
      creationDate: events.registration || events.transfer || null,
      expirationDate: events.expiration || null,
      updatedDate: events['last changed'] || events['last update'] || null,
      nameservers,
      source: 'ICANN RDAP Official Service'
    };
  } catch (err) {
    // Fallback: DNS-derived minimal whois
    let ns = [];
    try {
      ns = await dns.resolveNs(domain);
    } catch {}

    return {
      domain,
      handle: domain,
      status: ['Active (DNS Verified)'],
      registrar: 'Public Registry (RDAP privacy protected)',
      registrantOrg: 'Privacy Protected',
      registrantCountry: 'Global',
      creationDate: null,
      expirationDate: null,
      nameservers: ns,
      error: err.message,
      source: 'DNS Fallback'
    };
  }
}

/**
 * 4. IP Intelligence: ASN, ISP, Geolocation, Reverse DNS
 */
export async function lookupIpIntel(query) {
  let targetIp = query.trim();

  // If input is a domain, resolve to first IPv4
  if (!isIpAddress(targetIp)) {
    const domain = cleanDomain(targetIp);
    const ips = await dns.resolve4(domain);
    if (!ips || ips.length === 0) throw new Error(`Could not resolve IP for domain: ${domain}`);
    targetIp = ips[0];
  }

  // Reverse DNS PTR
  let reverseDns = null;
  try {
    const hostnames = await dns.reverse(targetIp);
    if (hostnames.length > 0) reverseDns = hostnames[0];
  } catch {}

  // Free IP Geolocation via ip-api
  const geoRes = await fetch(`http://ip-api.com/json/${encodeURIComponent(targetIp)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
  const geo = await geoRes.json();

  if (geo.status !== 'success') {
    throw new Error(geo.message || 'Failed to query IP intelligence.');
  }

  return {
    ip: targetIp,
    reverseDns,
    country: geo.country,
    countryCode: geo.countryCode,
    region: geo.regionName,
    city: geo.city,
    zip: geo.zip,
    latitude: geo.lat,
    longitude: geo.lon,
    timezone: geo.timezone,
    isp: geo.isp,
    organization: geo.org,
    asn: geo.as,
    mapsUrl: `https://www.google.com/maps?q=${geo.lat},${geo.lon}`
  };
}

/**
 * 5. DNS Map: Graph node-link structure (Domain -> NS / MX / A / IP)
 */
export async function buildDnsMapData(rawDomain) {
  const domain = cleanDomain(rawDomain);
  const nodes = [{ id: domain, type: 'domain', label: domain }];
  const links = [];

  try {
    const [aRecords, mxRecords, nsRecords] = await Promise.all([
      dns.resolve4(domain).catch(() => []),
      dns.resolveMx(domain).catch(() => []),
      dns.resolveNs(domain).catch(() => [])
    ]);

    // A Records
    aRecords.forEach((ip, idx) => {
      const ipId = `ip_${ip}`;
      if (!nodes.some((n) => n.id === ipId)) {
        nodes.push({ id: ipId, type: 'ip', label: `IPv4: ${ip}`, ip });
      }
      links.push({ source: domain, target: ipId, label: 'A Record' });
    });

    // MX Records
    mxRecords.forEach((mx) => {
      const mxId = `mx_${mx.exchange}`;
      nodes.push({ id: mxId, type: 'mx', label: `MX (${mx.priority}): ${mx.exchange}` });
      links.push({ source: domain, target: mxId, label: 'Mail Exchanger' });
    });

    // NS Records
    nsRecords.forEach((ns) => {
      const nsId = `ns_${ns}`;
      nodes.push({ id: nsId, type: 'ns', label: `NS: ${ns}` });
      links.push({ source: domain, target: nsId, label: 'Name Server' });
    });
  } catch (err) {
    // Return minimal node on error
  }

  return { domain, nodes, links };
}

/**
 * 6. Username Search (Sherlock-style reconnaissance)
 */
export async function searchUsername(rawUsername) {
  const username = rawUsername.trim().replace(/^@/, '');
  if (!username) throw new Error('Please provide a valid username.');

  const platforms = [
    { name: 'GitHub', url: `https://github.com/${username}`, check: `https://api.github.com/users/${username}`, method: 'API' },
    { name: 'Reddit', url: `https://www.reddit.com/user/${username}`, check: `https://www.reddit.com/user/${username}/about.json`, method: 'API' },
    { name: 'Twitter / X', url: `https://x.com/${username}` },
    { name: 'Instagram', url: `https://www.instagram.com/${username}/` },
    { name: 'TikTok', url: `https://www.tiktok.com/@${username}` },
    { name: 'Pinterest', url: `https://www.pinterest.com/${username}/` },
    { name: 'Telegram', url: `https://t.me/${username}` },
    { name: 'Steam', url: `https://steamcommunity.com/id/${username}` },
    { name: 'GitLab', url: `https://gitlab.com/${username}` },
    { name: 'Medium', url: `https://medium.com/@${username}` },
    { name: 'Dev.to', url: `https://dev.to/${username}` },
    { name: 'SoundCloud', url: `https://soundcloud.com/${username}` },
    { name: 'Twitch', url: `https://www.twitch.tv/${username}` },
    { name: 'YouTube', url: `https://www.youtube.com/@${username}` },
    { name: 'Pastebin', url: `https://pastebin.com/u/${username}` },
    { name: 'Linktree', url: `https://linktr.ee/${username}` }
  ];

  const results = await Promise.all(
    platforms.map(async (p) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4500);

        if (p.method === 'API') {
          const res = await fetch(p.check, {
            signal: controller.signal,
            headers: { 'User-Agent': 'CyberShield-Sherlock/1.0' }
          });
          clearTimeout(timeout);
          return {
            platform: p.name,
            url: p.url,
            exists: res.status === 200,
            status: res.status === 200 ? 'Claimed' : 'Available / Unverified'
          };
        }

        // Generic HTTP status probe
        const res = await fetch(p.url, {
          signal: controller.signal,
          method: 'HEAD',
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        clearTimeout(timeout);

        const exists = res.status >= 200 && res.status < 400;
        return {
          platform: p.name,
          url: p.url,
          exists,
          status: exists ? 'Claimed' : res.status === 404 ? 'Available' : 'Uncertain'
        };
      } catch {
        return {
          platform: p.name,
          url: p.url,
          exists: false,
          status: 'Timeout / Protected'
        };
      }
    })
  );

  const foundCount = results.filter((r) => r.exists).length;

  return {
    username,
    scanned: results.length,
    foundCount,
    platforms: results
  };
}

/**
 * 7. Email Intelligence: Format check, MX deliverability, disposable domain, Gravatar
 */
export async function analyzeEmail(rawEmail) {
  const email = rawEmail.trim().toLowerCase();
  const emailRegex = /^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;
  const match = email.match(emailRegex);

  if (!match) {
    return {
      email,
      validSyntax: false,
      error: 'Invalid RFC 5322 email syntax.'
    };
  }

  const domain = match[1];
  const user = email.split('@')[0];

  // Disposable domain list
  const disposableDomains = new Set([
    'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
    'yopmail.com', 'trashmail.com', 'dispostable.com', 'sharklasers.com',
    'getairmail.com', 'throwawaymail.com', 'fakeinbox.com', 'mytemp.email'
  ]);

  const isDisposable = disposableDomains.has(domain);

  // Check MX records
  let mxRecords = [];
  let acceptsMail = false;
  try {
    mxRecords = await dns.resolveMx(domain);
    acceptsMail = mxRecords.length > 0;
  } catch {}

  // MD5 hash for Gravatar avatar existence check
  const crypto = await import('crypto');
  const hash = crypto.createHash('md5').update(email).digest('hex');
  const gravatarUrl = `https://www.gravatar.com/avatar/${hash}?d=404`;

  let hasGravatar = false;
  try {
    const gravRes = await fetch(gravatarUrl, { method: 'HEAD' });
    hasGravatar = gravRes.status === 200;
  } catch {}

  return {
    email,
    user,
    domain,
    validSyntax: true,
    isDisposable,
    acceptsMail,
    mxRecords: mxRecords.map((m) => `${m.exchange} (pri ${m.priority})`),
    gravatar: {
      hasAvatar: hasGravatar,
      avatarUrl: hasGravatar ? `https://www.gravatar.com/avatar/${hash}?s=200` : null
    },
    breachSearchUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`
  };
}

/**
 * 8. Technology Detection: HTTP headers, meta tags, and JavaScript signatures
 */
export async function detectTechnologies(target) {
  let url = target.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  const detected = [];
  const securityHeaders = {
    contentSecurityPolicy: false,
    strictTransportSecurity: false,
    xFrameOptions: false,
    xContentTypeOptions: false
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CyberShield-Scanner'
      },
      redirect: 'follow'
    });
    clearTimeout(timeout);

    const headers = Object.fromEntries(res.headers.entries());
    const html = await res.text();

    // Web Server & CDN from headers
    if (headers['server']) detected.push({ category: 'Web Server', name: headers['server'] });
    if (headers['x-powered-by']) detected.push({ category: 'Backend Framework', name: headers['x-powered-by'] });
    if (headers['cf-ray'] || headers['server']?.toLowerCase().includes('cloudflare')) {
      detected.push({ category: 'CDN / Reverse Proxy', name: 'Cloudflare' });
    }
    if (headers['x-github-request-id']) detected.push({ category: 'Hosting', name: 'GitHub Pages' });
    if (headers['x-vercel-id']) detected.push({ category: 'Hosting / Cloud', name: 'Vercel' });
    if (headers['x-netlify-id']) detected.push({ category: 'Hosting / Cloud', name: 'Netlify' });

    // Security headers check
    if (headers['content-security-policy']) securityHeaders.contentSecurityPolicy = true;
    if (headers['strict-transport-security']) securityHeaders.strictTransportSecurity = true;
    if (headers['x-frame-options']) securityHeaders.xFrameOptions = true;
    if (headers['x-content-type-options']) securityHeaders.xContentTypeOptions = true;

    // HTML / Script signatures
    const htmlLower = html.toLowerCase();
    if (htmlLower.includes('wp-content') || htmlLower.includes('wp-includes')) {
      detected.push({ category: 'CMS', name: 'WordPress' });
    }
    if (htmlLower.includes('shopify') || htmlLower.includes('cdn.shopify.com')) {
      detected.push({ category: 'E-Commerce', name: 'Shopify' });
    }
    if (htmlLower.includes('__next') || htmlLower.includes('_next/static')) {
      detected.push({ category: 'JavaScript Framework', name: 'Next.js' });
    }
    if (htmlLower.includes('react') || htmlLower.includes('data-reactroot')) {
      detected.push({ category: 'UI Library', name: 'React' });
    }
    if (htmlLower.includes('vue') || htmlLower.includes('data-v-')) {
      detected.push({ category: 'UI Library', name: 'Vue.js' });
    }
    if (htmlLower.includes('tailwind') || htmlLower.includes('tw-')) {
      detected.push({ category: 'CSS Framework', name: 'Tailwind CSS' });
    }
    if (htmlLower.includes('bootstrap')) {
      detected.push({ category: 'CSS Framework', name: 'Bootstrap' });
    }
    if (htmlLower.includes('google-analytics.com') || htmlLower.includes('googletagmanager.com')) {
      detected.push({ category: 'Analytics', name: 'Google Analytics / GTM' });
    }

    return {
      url,
      httpStatus: res.status,
      technologies: detected,
      securityHeaders,
      rawHeaders: headers
    };
  } catch (err) {
    throw new Error(`Failed to probe target website: ${err.message}`);
  }
}

/**
 * 10. Google & Bing Dork Builder
 */
export function generateDorks(rawDomain) {
  const domain = cleanDomain(rawDomain);
  const dorks = [
    { title: 'Exposed Environment Files (.env)', query: `site:${domain} filetype:env | inurl:.env` },
    { title: 'Database Dumps & SQL Backups', query: `site:${domain} filetype:sql | filetype:db | filetype:sqlite` },
    { title: 'Open Directory Indexes', query: `site:${domain} intitle:"index of" | intitle:"index of /"` },
    { title: 'Admin & Portal Login Pages', query: `site:${domain} inurl:admin | inurl:login | inurl:dashboard | inurl:cpanel` },
    { title: 'Exposed Log Files', query: `site:${domain} filetype:log | inurl:access.log | inurl:error.log` },
    { title: 'Public Configuration Files', query: `site:${domain} filetype:xml | filetype:conf | filetype:cnf | filetype:yaml` },
    { title: 'Git Repositories Exposed', query: `site:${domain} inurl:/.git | intitle:"index of /.git"` },
    { title: 'PHP Info & Server Diagnostic', query: `site:${domain} inurl:phpinfo.php | inurl:info.php` },
    { title: 'Backup Archives (.zip, .tar, .bak)', query: `site:${domain} filetype:zip | filetype:tar | filetype:gz | filetype:bak` },
    { title: 'Sensitive Documents (PDFs, Excel)', query: `site:${domain} filetype:pdf | filetype:xlsx | filetype:docx confidential` }
  ];

  return {
    domain,
    dorks: dorks.map((d) => ({
      ...d,
      googleUrl: `https://www.google.com/search?q=${encodeURIComponent(d.query)}`,
      bingUrl: `https://www.bing.com/search?q=${encodeURIComponent(d.query)}`,
      duckUrl: `https://duckduckgo.com/?q=${encodeURIComponent(d.query)}`
    }))
  };
}

/**
 * 11. News & Leak Monitor
 */
export async function monitorNewsAndLeaks(query) {
  const term = query.trim();
  const searchUrl = `https://news.google.com/rss/search?q=${encodeURIComponent(term)}+security+OR+breach+OR+leak&hl=en-US&gl=US&ceid=US:en`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(searchUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 CyberShield-News/1.0' }
    });
    clearTimeout(timeout);

    const xml = await res.text();
    const items = [];
    const itemMatches = xml.matchAll(/<item>[\s\S]*?<title>(.*?)<\/title>[\s\S]*?<link>(.*?)<\/link>[\s\S]*?<pubDate>(.*?)<\/pubDate>[\s\S]*?<\/item>/gi);

    for (const m of itemMatches) {
      if (items.length >= 10) break;
      items.push({
        title: cleanHtmlEntities(m[1]),
        link: m[2],
        pubDate: m[3]
      });
    }

    return {
      query: term,
      resultsCount: items.length,
      articles: items,
      threatFeeds: [
        { name: 'HaveIBeenPwned Domain Search', url: `https://haveibeenpwned.com/DomainSearch` },
        { name: 'Google Transparency Report', url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(term)}` },
        { name: 'URLhaus Malware Database', url: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(term)}` }
      ]
    };
  } catch (err) {
    return {
      query: term,
      resultsCount: 0,
      articles: [],
      error: 'News feed currently unreachable',
      threatFeeds: [
        { name: 'HaveIBeenPwned Domain Search', url: `https://haveibeenpwned.com/DomainSearch` }
      ]
    };
  }
}

// Helpers
function cleanDomain(input) {
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/^www\./i, '');
  return domain;
}

function isIpAddress(ip) {
  const ipv4 = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4.test(ip) || ip.includes(':');
}

function cleanHtmlEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/<!\[CDATA\[(.*?)\]\]>/g, '$1');
}
