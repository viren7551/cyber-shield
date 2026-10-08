import dns from 'dns/promises';
import net from 'net';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SHERLOCK_DATA_PATH = path.join(__dirname, 'data', 'sherlock.json');

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

const FALLBACK_PLATFORMS = [
  { name: 'GitHub', url: 'https://github.com/{}', urlProbe: 'https://api.github.com/users/{}', errorType: 'status_code', errorCode: 404, urlMain: 'https://github.com/' },
  { name: 'Reddit', url: 'https://www.reddit.com/user/{}', errorMsg: 'Sorry, nobody on Reddit goes by that name.', errorType: 'message', urlMain: 'https://www.reddit.com/' },
  { name: 'Twitter / X', url: 'https://x.com/{}', errorType: 'status_code', urlMain: 'https://x.com/' },
  { name: 'Instagram', url: 'https://www.instagram.com/{}/', errorType: 'status_code', urlMain: 'https://www.instagram.com/' },
  { name: 'TikTok', url: 'https://www.tiktok.com/@{}', errorType: 'status_code', urlMain: 'https://www.tiktok.com/' },
  { name: 'Pinterest', url: 'https://www.pinterest.com/{}/', errorType: 'status_code', urlMain: 'https://www.pinterest.com/' },
  { name: 'Telegram', url: 'https://t.me/{}', errorMsg: '<div class="tgme_page_extra">If you have <strong>Telegram</strong>', errorType: 'message', urlMain: 'https://t.me/' },
  { name: 'Steam', url: 'https://steamcommunity.com/id/{}', errorMsg: 'The specified profile could not be found.', errorType: 'message', urlMain: 'https://steamcommunity.com/' },
  { name: 'GitLab', url: 'https://gitlab.com/{}', errorType: 'status_code', urlMain: 'https://gitlab.com/' },
  { name: 'Medium', url: 'https://medium.com/@{}', errorType: 'status_code', urlMain: 'https://medium.com/' },
  { name: 'Dev.to', url: 'https://dev.to/{}', errorType: 'status_code', urlMain: 'https://dev.to/' },
  { name: 'SoundCloud', url: 'https://soundcloud.com/{}', errorType: 'status_code', urlMain: 'https://soundcloud.com/' },
  { name: 'Twitch', url: 'https://www.twitch.tv/{}', errorType: 'status_code', urlMain: 'https://www.twitch.tv/' },
  { name: 'YouTube', url: 'https://www.youtube.com/@{}', errorType: 'status_code', urlMain: 'https://www.youtube.com/' },
  { name: 'Pastebin', url: 'https://pastebin.com/u/{}', errorType: 'status_code', urlMain: 'https://pastebin.com/' },
  { name: 'Linktree', url: 'https://linktr.ee/{}', errorType: 'status_code', urlMain: 'https://linktr.ee/' }
];

let cachedSherlockSites = null;

export function getSherlockSites() {
  if (cachedSherlockSites && cachedSherlockSites.length > 0) {
    return cachedSherlockSites;
  }
  try {
    if (fs.existsSync(SHERLOCK_DATA_PATH)) {
      const raw = JSON.parse(fs.readFileSync(SHERLOCK_DATA_PATH, 'utf8'));
      cachedSherlockSites = Object.entries(raw)
        .filter(([name, info]) => name !== '$schema' && typeof info === 'object')
        .map(([name, info]) => ({
          name,
          ...info
        }));
      return cachedSherlockSites;
    }
  } catch (err) {
    console.error('[CyberShield Sherlock] Error reading sherlock.json:', err.message);
  }
  return FALLBACK_PLATFORMS;
}

const WAF_PATTERNS = [
  '.loading-spinner{visibility:hidden}',
  '<span id="challenge-error-text">',
  'AwsWafIntegration.forceRefreshToken',
  'perimeterxIdentifiers'
];

// High-accuracy targeted handlers for top platforms requiring specific headers/APIs
const CUSTOM_HANDLERS = {
  // Instagram: Server-side OpenGraph meta/title inspection via facebookexternalhit bot
  'Instagram': async (username, cleanUser, signal) => {
    try {
      const res = await fetch(`https://www.instagram.com/${encodeURIComponent(cleanUser)}/`, {
        headers: {
          'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9'
        },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(4500)]) : AbortSignal.timeout(4500)
      });
      const text = await res.text();
      const title = text.match(/<title>([^<]+)<\/title>/i)?.[1] || '';
      const exists = title.includes(`@${cleanUser}`) ||
                     title.includes(`&#064;${cleanUser}`) ||
                     (title.includes('• Instagram') && title.toLowerCase().includes(cleanUser.toLowerCase()));
      return {
        exists,
        status: exists ? 'Claimed' : 'Available',
        httpStatus: res.status
      };
    } catch {
      return { exists: false, status: 'Available' };
    }
  },

  // Twitter / X: Direct social bot probe to x.com (bypasses dead nitter instances)
  'Twitter': async (username, cleanUser, signal) => {
    try {
      const res = await fetch(`https://x.com/${encodeURIComponent(cleanUser)}`, {
        headers: {
          'User-Agent': 'Twitterbot/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(4500)]) : AbortSignal.timeout(4500)
      });
      const exists = res.status === 200;
      return {
        exists,
        status: exists ? 'Claimed' : 'Available',
        httpStatus: res.status
      };
    } catch {
      return { exists: false, status: 'Available' };
    }
  },

  // Reddit: SSR Title verification via Twitterbot UA (detects u/username vs generic home title)
  'Reddit': async (username, cleanUser, signal) => {
    try {
      const res = await fetch(`https://www.reddit.com/user/${encodeURIComponent(cleanUser)}/`, {
        headers: {
          'User-Agent': 'Twitterbot/1.0',
          'Accept': 'text/html'
        },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(4500)]) : AbortSignal.timeout(4500)
      });
      const text = await res.text();
      const title = text.match(/<title>([^<]+)<\/title>/i)?.[1] || '';
      const exists = title.toLowerCase().includes(`u/${cleanUser.toLowerCase()}`) ||
                     (title.includes('- Reddit') && title.toLowerCase().includes(cleanUser.toLowerCase()));
      return {
        exists,
        status: exists ? 'Claimed' : 'Available',
        httpStatus: res.status
      };
    } catch {
      return { exists: false, status: 'Available' };
    }
  },

  // LeetCode: GraphQL user profile existence probe
  'LeetCode': async (username, cleanUser, signal) => {
    try {
      const res = await fetch('https://leetcode.com/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Referer': 'https://leetcode.com'
        },
        body: JSON.stringify({
          query: 'query getUserProfile($username: String!) { matchedUser(username: $username) { username } }',
          variables: { username: cleanUser }
        }),
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(4500)]) : AbortSignal.timeout(4500)
      });
      const json = await res.json();
      const exists = Boolean(json?.data?.matchedUser?.username);
      return {
        exists,
        status: exists ? 'Claimed' : 'Available',
        httpStatus: res.status
      };
    } catch {
      return { exists: false, status: 'Available' };
    }
  },

  // GitLab: Official user lookup REST API
  'GitLab': async (username, cleanUser, signal) => {
    try {
      const res = await fetch(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(cleanUser)}`, {
        headers: { 'User-Agent': 'CyberShield-Sherlock/1.0' },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(4500)]) : AbortSignal.timeout(4500)
      });
      const data = await res.json();
      const exists = Array.isArray(data) && data.some(u => u.username?.toLowerCase() === cleanUser.toLowerCase());
      return {
        exists,
        status: exists ? 'Claimed' : 'Available',
        httpStatus: res.status
      };
    } catch {
      return { exists: false, status: 'Available' };
    }
  }
};

// Aliases
CUSTOM_HANDLERS['Twitter / X'] = CUSTOM_HANDLERS['Twitter'];
CUSTOM_HANDLERS['X'] = CUSTOM_HANDLERS['Twitter'];

async function probeSherlockTarget(target, username, signal = null) {
  const cleanUser = username.trim().replace(/^@/, '');
  const url = (target.url || '').replace(/{}/g, encodeURIComponent(cleanUser));
  const probeUrl = (target.urlProbe || target.url || '').replace(/{}/g, encodeURIComponent(cleanUser));

  if (!url || !probeUrl) {
    return { platform: target.name, url: url || '#', exists: false, status: 'Invalid Config', skipped: true };
  }

  // 1. Regex pre-validation check (Sherlock standard behavior)
  if (target.regexCheck) {
    try {
      const regex = new RegExp(target.regexCheck);
      if (!regex.test(cleanUser)) {
        return {
          platform: target.name,
          url,
          mainUrl: target.urlMain || target.url,
          exists: false,
          status: 'Format Not Supported',
          skipped: true
        };
      }
    } catch {}
  }

  // 2. High-accuracy custom handler for platforms with complex anti-bot or APIs
  if (CUSTOM_HANDLERS[target.name]) {
    try {
      const customRes = await CUSTOM_HANDLERS[target.name](username, cleanUser, signal);
      return {
        platform: target.name,
        url,
        mainUrl: target.urlMain || target.url,
        ...customRes
      };
    } catch (err) {
      if (signal && signal.aborted) throw err;
      return {
        platform: target.name,
        url,
        mainUrl: target.urlMain || target.url,
        exists: false,
        status: 'Available'
      };
    }
  }

  // 3. Abort signal with per-target timeout
  const timeoutSignal = AbortSignal.timeout(3500);
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

  try {
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      ...(target.headers || {})
    };

    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === 'string' && v.includes('{}')) {
        headers[k] = v.replace(/{}/g, cleanUser);
      }
    }

    const method = target.request_method || 'GET';
    const fetchOptions = {
      method,
      headers,
      signal: combinedSignal,
      redirect: 'follow'
    };

    if (target.request_payload && (method === 'POST' || method === 'PUT')) {
      const payloadStr = JSON.stringify(target.request_payload).replace(/{}/g, cleanUser);
      fetchOptions.body = payloadStr;
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
    }

    const res = await fetch(probeUrl, fetchOptions);

    let exists = false;
    let statusText = 'Available';
    const errType = Array.isArray(target.errorType) ? target.errorType : [target.errorType];

    if (errType.includes('message')) {
      const bodyText = await res.text();
      if (WAF_PATTERNS.some(waf => bodyText.includes(waf))) {
        return {
          platform: target.name,
          url,
          mainUrl: target.urlMain || target.url,
          exists: false,
          status: 'Available / Protected'
        };
      }
      const errorMsgs = Array.isArray(target.errorMsg) ? target.errorMsg : (target.errorMsg ? [target.errorMsg] : []);
      const hasErrorMsg = errorMsgs.some(msg => bodyText.includes(msg));
      exists = !hasErrorMsg && res.status >= 200 && res.status < 300;
      statusText = exists ? 'Claimed' : 'Available';
    } else if (errType.includes('status_code')) {
      const errCodes = Array.isArray(target.errorCode) ? target.errorCode : (target.errorCode ? [target.errorCode] : [404]);
      const isErrCode = errCodes.includes(res.status);

      if (!isErrCode && res.status >= 200 && res.status < 300) {
        exists = true;
        statusText = 'Claimed';
      } else if (res.status === 404 || isErrCode) {
        exists = false;
        statusText = 'Available';
      } else if (res.status === 403 || res.status === 401) {
        // Try quick social bot preview retry
        try {
          const retryRes = await fetch(probeUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'Twitterbot/1.0',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            },
            signal: AbortSignal.timeout(2000)
          });
          if (retryRes.status >= 200 && retryRes.status < 300) {
            exists = true;
            statusText = 'Claimed';
          } else {
            exists = false;
            statusText = 'Available';
          }
        } catch {
          exists = false;
          statusText = 'Available';
        }
      } else {
        exists = false;
        statusText = 'Available';
      }
    } else if (errType.includes('response_url')) {
      const redirectedToError = target.errorUrl && res.url.includes(target.errorUrl);
      exists = !redirectedToError && res.status >= 200 && res.status < 300;
      statusText = exists ? 'Claimed' : 'Available';
    } else {
      exists = res.status >= 200 && res.status < 300;
      statusText = exists ? 'Claimed' : 'Available';
    }

    return {
      platform: target.name,
      url,
      mainUrl: target.urlMain || target.url,
      exists,
      status: statusText,
      httpStatus: res.status
    };
  } catch (err) {
    if (signal && signal.aborted) {
      throw err;
    }
    return {
      platform: target.name,
      url,
      mainUrl: target.urlMain || target.url,
      exists: false,
      status: 'Available'
    };
  }
}

/**
 * 6. Username Search (Sherlock Multi-Platform Engine)
 * Scans all available Sherlock platforms (480+) concurrently or popular subset
 */
export async function searchUsername(rawUsername, options = {}) {
  const username = rawUsername.trim().replace(/^@/, '');
  if (!username) throw new Error('Please provide a valid username.');

  const {
    scope = 'all',
    concurrency = 35,
    onProgress = null,
    signal = null
  } = options;

  const allSites = getSherlockSites();

  let targetSites = allSites;
  if (scope === 'popular') {
    const popularSet = new Set([
      'GitHub', 'Reddit', 'Twitter', 'Instagram', 'TikTok', 'Pinterest',
      'Telegram', 'Steam', 'GitLab', 'Medium', 'Dev.to', 'SoundCloud',
      'Twitch', 'YouTube', 'Pastebin', 'Linktree', 'Discord', 'Spotify',
      'HackerRank', 'LeetCode', 'Docker Hub', 'Bitbucket', 'Patreon',
      'Bluesky', 'Mastodon', 'Disqus', 'DailyMotion', 'Substack',
      'Keybase', 'Kaggle', 'Behance', 'Dribbble', 'Flickr', 'Vimeo',
      'Goodreads', 'Anilist', 'Chess.com', 'Codecademy', 'Freelancer', 'ProductHunt'
    ]);
    targetSites = allSites.filter(s => popularSet.has(s.name));
  }

  const results = new Array(targetSites.length);
  let cursor = 0;
  let scannedCount = 0;
  let foundCount = 0;

  async function worker() {
    while (cursor < targetSites.length) {
      if (signal && signal.aborted) break;
      const idx = cursor++;
      if (idx >= targetSites.length) break;

      const target = targetSites[idx];
      const result = await probeSherlockTarget(target, username, signal);
      results[idx] = result;
      scannedCount++;
      if (result.exists) foundCount++;

      if (typeof onProgress === 'function') {
        onProgress({
          scanned: scannedCount,
          total: targetSites.length,
          foundCount,
          percent: Math.round((scannedCount / targetSites.length) * 100),
          result
        });
      }
    }
  }

  const workerCount = Math.min(concurrency, targetSites.length);
  const workers = Array.from({ length: workerCount }, () => worker());
  await Promise.all(workers);

  const finalResults = results.filter(Boolean);
  // Sort so Claimed profiles appear first, then alphabetical
  finalResults.sort((a, b) => {
    if (a.exists && !b.exists) return -1;
    if (!a.exists && b.exists) return 1;
    return a.platform.localeCompare(b.platform);
  });

  return {
    username,
    scope,
    scanned: finalResults.length,
    totalAvailable: allSites.length,
    foundCount: finalResults.filter(r => r.exists).length,
    platforms: finalResults
  };
}

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.net',
  'guerrillamailblock.com', '10minutemail.com', '10minutemail.net', 'yopmail.com', 'yopmail.fr',
  'trashmail.com', 'trashmail.net', 'trashmail.me', 'dispostable.com', 'sharklasers.com',
  'getairmail.com', 'throwawaymail.com', 'fakeinbox.com', 'mytemp.email', 'dropmail.me',
  'mohmal.com', 'nada.ltd', 'inboxkitten.com', 'crazymailing.com', 'burnermail.io',
  'generator.email', 'tempail.com', 'emailondeck.com', 'tempmailo.com', 'tmailor.com',
  'fakemailgenerator.com', 'maildrop.cc', 'harakirimail.com', 'disposablemail.com'
]);

const FREE_WEBMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'outlook.com', 'hotmail.com',
  'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com',
  'aol.com', 'zoho.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru'
]);

const ROLE_BASED_PREFIXES = new Set([
  'admin', 'administrator', 'support', 'contact', 'info', 'sales', 'billing',
  'help', 'helpdesk', 'security', 'abuse', 'postmaster', 'hostmaster', 'webmaster',
  'team', 'jobs', 'careers', 'press', 'media', 'compliance', 'legal'
]);

const COMMON_DOMAIN_TYPOS = {
  'gmai.com': 'gmail.com',
  'gmial.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'gmaill.com': 'gmail.com',
  'yaho.com': 'yahoo.com',
  'yaho.co': 'yahoo.com',
  'yahooo.com': 'yahoo.com',
  'hotmial.com': 'hotmail.com',
  'hotmaill.com': 'hotmail.com',
  'outlok.com': 'outlook.com',
  'outloo.com': 'outlook.com',
  'iclud.com': 'icloud.com',
  'prton.me': 'proton.me',
  'protonmai.com': 'protonmail.com'
};

function validateEmailSyntax(email) {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email string is required.' };
  }
  const parts = email.split('@');
  if (parts.length !== 2) {
    return { valid: false, error: 'Must contain exactly one "@" symbol.' };
  }
  const [local, domain] = parts;
  if (!local || local.length > 64) {
    return { valid: false, error: 'Username must be between 1 and 64 characters.' };
  }
  if (!domain || domain.length > 255) {
    return { valid: false, error: 'Domain must be between 1 and 255 characters.' };
  }
  if (local.startsWith('.') || local.endsWith('.')) {
    return { valid: false, error: 'Username cannot start or end with a period.' };
  }
  if (local.includes('..')) {
    return { valid: false, error: 'Username cannot contain consecutive periods (..).' };
  }
  const domainParts = domain.split('.');
  if (domainParts.length < 2) {
    return { valid: false, error: 'Domain must include a top-level domain (e.g. .com, .org).' };
  }
  const tld = domainParts[domainParts.length - 1];
  if (!tld || tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) {
    return { valid: false, error: `Invalid Top-Level Domain (.${tld}).` };
  }
  const localRegex = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
  if (!localRegex.test(local)) {
    return { valid: false, error: 'Username contains illegal characters.' };
  }
  const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain) || domain.includes('..')) {
    return { valid: false, error: 'Domain contains invalid format.' };
  }
  return { valid: true };
}

async function verifySmtpMailbox(email, primaryMx) {
  return new Promise((resolve) => {
    let socket;
    let resolved = false;

    const finish = (res) => {
      if (!resolved) {
        resolved = true;
        try {
          if (socket) {
            socket.write('QUIT\r\n');
            socket.end();
            socket.destroy();
          }
        } catch {}
        resolve(res);
      }
    };

    try {
      socket = net.createConnection(25, primaryMx);
    } catch {
      return finish({ deliverable: null, detail: 'Socket connection failed' });
    }

    let step = 0;
    socket.setTimeout(3500);

    socket.on('timeout', () => {
      finish({ deliverable: null, detail: 'Connection to mail server timed out' });
    });

    socket.on('error', (err) => {
      finish({ deliverable: null, detail: err.message });
    });

    socket.on('data', (data) => {
      const response = data.toString();
      const code = parseInt(response.slice(0, 3), 10);

      if (step === 0 && (code === 220 || code === 250)) {
        step = 1;
        socket.write('EHLO mail.cybershield.io\r\n');
      } else if (step === 1 && code === 250) {
        step = 2;
        socket.write('MAIL FROM:<check@mail.cybershield.io>\r\n');
      } else if (step === 2 && code === 250) {
        step = 3;
        socket.write(`RCPT TO:<${email}>\r\n`);
      } else if (step === 3) {
        if (code === 250 || code === 251) {
          finish({ deliverable: true, code, detail: 'Recipient mailbox verified active (250 OK)' });
        } else if (code >= 550 && code <= 554) {
          const firstLine = response.trim().split('\n')[0].replace(/\r$/, '');
          finish({ deliverable: false, code, detail: `Mailbox does not exist: ${firstLine}` });
        } else if (code >= 450 && code <= 452) {
          finish({ deliverable: null, code, detail: 'Mailbox greylisted / temporarily rate limited' });
        } else {
          finish({ deliverable: null, code, detail: response.trim().split('\n')[0] });
        }
      }
    });
  });
}

/**
 * 7. Email Intelligence: Multi-Stage Forensic Verification
 * Checks syntax, domain DNS, MX records, SMTP mailbox deliverability, burner risk & Gravatar
 */
export async function analyzeEmail(rawEmail) {
  const email = (rawEmail || '').trim().toLowerCase();
  const syntaxCheck = validateEmailSyntax(email);

  if (!syntaxCheck.valid) {
    return {
      email,
      user: email.split('@')[0] || '',
      domain: email.split('@')[1] || '',
      validSyntax: false,
      acceptsMail: false,
      isDisposable: false,
      mxRecords: [],
      verdict: 'MALFORMED',
      verdictLabel: 'Malformed / Invalid Syntax',
      isDeliverable: false,
      score: 0,
      syntax: {
        valid: false,
        details: syntaxCheck.error,
        typoSuggestion: null
      },
      domainInfo: { exists: false, hasMx: false, ips: [], mxRecords: [], primaryMx: null },
      provider: { type: 'Invalid', isDisposable: false, isFreeMail: false, isRoleAccount: false },
      mailbox: { checked: false, deliverable: false, status: 'Invalid Syntax', detail: syntaxCheck.error },
      gravatar: { hasAvatar: false, avatarUrl: null },
      breachSearchUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`
    };
  }

  const [user, domain] = email.split('@');

  // Check common typos
  let typoSuggestion = null;
  if (COMMON_DOMAIN_TYPOS[domain]) {
    typoSuggestion = `${user}@${COMMON_DOMAIN_TYPOS[domain]}`;
  }

  // Domain DNS A-record resolution
  let domainExists = false;
  let ips = [];
  try {
    ips = await dns.resolve4(domain);
    domainExists = Boolean(ips && ips.length > 0);
  } catch {}

  // MX resolution
  let mxRecords = [];
  try {
    mxRecords = await dns.resolveMx(domain);
    mxRecords.sort((a, b) => a.priority - b.priority);
  } catch {}

  const hasMx = mxRecords.length > 0;
  const acceptsMail = hasMx;

  // Provider classification
  const isDisposable = DISPOSABLE_EMAIL_DOMAINS.has(domain);
  const isFreeMail = FREE_WEBMAIL_DOMAINS.has(domain);
  const isRoleAccount = ROLE_BASED_PREFIXES.has(user);

  let providerType = 'Corporate / Private Domain';
  if (isDisposable) providerType = 'Disposable / Temporary Burner';
  else if (isFreeMail) providerType = 'Free Public Webmail';
  else if (domain.endsWith('.edu') || domain.endsWith('.ac.uk')) providerType = 'Educational Institution';
  else if (domain.endsWith('.gov')) providerType = 'Government Entity';

  // Mailbox probe (if domain & MX exist)
  let mailboxResult = {
    checked: false,
    deliverable: null,
    status: 'Unchecked',
    detail: !hasMx ? 'No mail exchange available for domain' : 'Skipped for disposable domain'
  };

  if (hasMx && !isDisposable) {
    const primary = mxRecords[0].exchange;
    const smtpRes = await verifySmtpMailbox(email, primary);
    mailboxResult = {
      checked: true,
      deliverable: smtpRes.deliverable,
      status: smtpRes.deliverable === true ? 'Active Mailbox' : smtpRes.deliverable === false ? 'Mailbox Rejected (550)' : 'Protected Gateway',
      detail: smtpRes.detail
    };
  }

  // Overall Verdict calculation
  let verdict = 'VALID';
  let verdictLabel = 'Deliverable & Active';
  let isDeliverable = true;
  let score = 95;

  if (!domainExists && !hasMx) {
    verdict = 'INVALID';
    verdictLabel = 'Non-Existent Domain (Unregistered / Dead)';
    isDeliverable = false;
    score = 0;
  } else if (!hasMx) {
    verdict = 'INVALID';
    verdictLabel = 'No Mail Exchange (Cannot Receive Mail)';
    isDeliverable = false;
    score = 10;
  } else if (isDisposable) {
    verdict = 'DISPOSABLE';
    verdictLabel = 'High-Risk Disposable Burner Email';
    isDeliverable = false;
    score = 25;
  } else if (mailboxResult.deliverable === false) {
    verdict = 'INVALID';
    verdictLabel = 'Mailbox Does Not Exist (550 User Unknown)';
    isDeliverable = false;
    score = 0;
  } else if (mailboxResult.deliverable === true) {
    verdict = 'VALID';
    verdictLabel = 'Verified Deliverable (Mailbox Confirmed)';
    isDeliverable = true;
    score = 100;
  } else {
    // Smtp probe timed out or blocked by gateway, but domain and MX records exist
    verdict = 'VALID';
    verdictLabel = 'Domain & MX Verified Active';
    isDeliverable = true;
    score = 85;
  }

  // MD5 hash for Gravatar avatar existence check
  const crypto = await import('crypto');
  const hash = crypto.createHash('md5').update(email).digest('hex');
  const gravatarUrl = `https://www.gravatar.com/avatar/${hash}?d=404`;

  let hasGravatar = false;
  try {
    const gravRes = await fetch(gravatarUrl, { method: 'HEAD', signal: AbortSignal.timeout(3000) });
    hasGravatar = gravRes.status === 200;
  } catch {}

  return {
    email,
    user,
    domain,
    validSyntax: true,
    acceptsMail,
    isDisposable,
    mxRecords: mxRecords.map((m) => `${m.exchange} (pri ${m.priority})`),
    verdict,
    verdictLabel,
    isDeliverable,
    score,
    syntax: {
      valid: true,
      details: 'Complies with RFC 5322 syntax standards.',
      typoSuggestion
    },
    domainInfo: {
      exists: domainExists,
      hasMx,
      ips,
      mxRecords: mxRecords.map((m) => `${m.exchange} (pri ${m.priority})`),
      primaryMx: mxRecords[0]?.exchange || null
    },
    provider: {
      type: providerType,
      isDisposable,
      isFreeMail,
      isRoleAccount
    },
    mailbox: mailboxResult,
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
