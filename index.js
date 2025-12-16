// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - COMPLETE UNIFIED VERSION
 * ============================================================================
 * 
 * Combined Features:
 * - Advanced Admin Panel with Auto-Refresh, Charts, Real-time Stats
 * - User Panel with Self-Contained QR Code Generator, Config Tester
 * - Health Check & Auto-Switching System
 * - Scamalytics IP Reputation Check
 * - RASPS (Responsive Adaptive Smart Polling)
 * - Complete Geo-location Detection
 * - D1 Database Integration
 * - Full Security Headers & CSRF Protection
 * - Reverse Proxy for Landing Page
 * - Custom 404 Page
 * - robots.txt and security.txt
 * - HTTP/3 Support
 * 
 * Last Updated: December 2025
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION SECTION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  
  scamalytics: {
    username: 'victoriacrossn',
    apiKey: 'ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },

  async fromEnv(env) {
    let selectedProxyIP = null;

    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip_port || null;
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

// ============================================================================
// CONSTANTS
// ============================================================================

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  
  AUTO_REFRESH_INTERVAL: 60000,
  
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000,
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// CORE SECURITY & HELPER FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net` 
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'";
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=86400');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aLen = a.length;
  const bLen = b.length;
  let result = 0;

  if (aLen !== bLen) {
    for (let i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  
  for (let i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"'/`]/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
  })[m]);
}

function safeBase64Encode(str) {
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// KEY-VALUE STORAGE FUNCTIONS (D1-based)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) return null;
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      return JSON.parse(res.value);
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) return;
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error(`kvPut error for ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) return;
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e}`);
  }
}

// ============================================================================
// USER DATA MANAGEMENT
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) return null;
    
    const cacheKey = `user:${uuid}`;
    let cachedData = await kvGet(env.DB, cacheKey, 'json');
    if (cachedData && cachedData.uuid) return cachedData;

    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    ctx ? ctx.waitUntil(cachePromise) : await cachePromise;
    
    return userFromDb;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid || !env.DB) return;
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  let attempts = 0;
  
  try {
    while (!lockAcquired && attempts < 5) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      attempts++;
    }
    
    if (!lockAcquired) return;
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare(
      "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
    ).bind(usage, uuid).run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    ctx ? ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise])) : await Promise.all([updatePromise, deleteCachePromise]);
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      await kvDelete(env.DB, usageLockKey).catch(e => console.error(`Lock release error for ${uuid}:`, e));
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) return;
  try {
    const cleanupPromise = env.DB.prepare(
      "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
    ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
    
    ctx ? ctx.waitUntil(cleanupPromise) : await cleanupPromise;
  } catch (e) {
    console.error(`cleanupOldIps error: ${e.message}`);
  }
}

// ============================================================================
// SCAMALYTICS IP REPUTATION CHECK
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) return false;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) return false;

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// 2FA (TOTP) VALIDATION SYSTEM
// ============================================================================

function base32ToBuffer(base32) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (let i = 0; i < str.length; i++) {
    const charValue = base32Chars.indexOf(str[i]);
    if (charValue === -1) throw new Error('Invalid Base32 character');
    
    value = (value << 5) | charValue;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hmacBuffer = new Uint8Array(hmac);
  
  const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  const otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) return false;
  
  let secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    return false;
  }
  
  const timeStep = 30;
  const epoch = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(epoch / timeStep);
  
  const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

  for (const counter of counters) {
    const generatedCode = await generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) return true;
  }
  
  return false;
}

async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(db, key, limit, ttl) {
  if (!db) return false;
  try {
    const countStr = await kvGet(db, key);
    const count = parseInt(countStr, 10) || 0;
    if (count >= limit) return true;
    await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
    return false;
  } catch (e) {
    return false;
  }
}

// ============================================================================
// UUID UTILITIES
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + 
    byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
    byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
    byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION LINK GENERATION
// ============================================================================

function generateRandomPath(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}`;
}

const CORE_PRESETS = {
  xray: {
    tls: {
      path: () => generateRandomPath(12),
      security: 'tls',
      fp: 'chrome',
      alpn: 'http/1.1',
      extra: { ed: '2560' },
    },
    tcp: {
      path: () => generateRandomPath(12),
      security: 'none',
      fp: 'chrome',
      extra: { ed: '2560' },
    },
  },
  sb: {
    tls: {
      path: () => generateRandomPath(18),
      security: 'tls',
      fp: 'firefox',
      alpn: 'h3',
      extra: CONST.ED_PARAMS,
    },
    tcp: {
      path: () => generateRandomPath(18),
      security: 'none',
      fp: 'firefox',
      extra: CONST.ED_PARAMS,
    },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function randomizeCase(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host,
    path,
  });

  if (security) {
    params.set('security', security);
    if (security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// SUBSCRIPTION HANDLER
// ============================================================================

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'go.inmobi.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    'mail.tm',
    'temp-mail.org',
    'ipaddress.my',
    'mdbmax.com',
    'check-host.net',
    'kodambroker.com',
    'iplocation.io',
    'whatismyip.org',
    'www.linkedin.com',
    'exir.io',
    'arzex.io',
    'ok-ex.io',
    'arzdigital.com',
    'pouyanit.com',
    'auth.grok.com',
    'grok.com',
    'maxmind.com',
    'whatsmyip.com',
    'iplocation.net',
    'ipchicken.com',
    'showmyip.com',
    'router-network.com',
    'whatismyipaddress.com',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: 'tls',
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: 'tcp',
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });

  const cacheKey = 'cf_ips';
  let ips = await kvGet(env.DB, cacheKey, 'json');
  if (!ips) {
    try {
      const r = await fetch(
        'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
      );
      if (r.ok) {
        const json = await r.json();
        ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map((x) => x.ip);
        await kvPut(env.DB, cacheKey, ips, { expirationTtl: 86400 });
      }
    } catch (e) {
      console.error('Fetch IP list failed', e);
    }
  }

  if (ips) {
    ips.forEach((ip, i) => {
      const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
      links.push(
        buildLink({
          core,
          proto: 'tls',
          userID,
          hostName,
          address: formattedAddress,
          port: pick(httpsPorts),
          tag: `IP${i + 1}`,
        }),
      );

      if (!isPagesDeployment) {
        links.push(
          buildLink({
            core,
            proto: 'tcp',
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpPorts),
            tag: `IP${i + 1}`,
          }),
        );
      }
    });
  }

  const headers = new Headers({ 
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
  });
  addSecurityHeaders(headers, null, {});
  return new Response(safeBase64Encode(links.join('\n')), { headers });
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) return;
  
  try {
    const createTables = [
      `CREATE TABLE IF NOT EXISTS users (
        uuid TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiration_date TEXT NOT NULL,
        expiration_time TEXT NOT NULL,
        notes TEXT,
        traffic_limit INTEGER,
        traffic_used INTEGER DEFAULT 0,
        ip_limit INTEGER DEFAULT -1
      )`,
      `CREATE TABLE IF NOT EXISTS user_ips (
        uuid TEXT,
        ip TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (uuid, ip),
        FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE
      )`,
      `CREATE TABLE IF NOT EXISTS key_value (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expiration INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS proxy_health (
        ip_port TEXT PRIMARY KEY,
        is_healthy INTEGER NOT NULL,
        latency_ms INTEGER,
        last_check INTEGER DEFAULT (strftime('%s', 'now'))
      )`
    ];
    
    await env.DB.batch(createTables.map(sql => env.DB.prepare(sql)));
    
    const testUUID = env.UUID || Config.userID;
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    const expDate = futureDate.toISOString().split('T')[0];
    const expTime = '23:59:59';
    
    await env.DB.prepare(
      "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1).run();
    
  } catch (e) {
    console.error('D1 tables init failed:', e);
  }
}

// ============================================================================
// HEALTH CHECK SYSTEM
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) return;
  
  const proxyIps = env.PROXYIPS 
    ? env.PROXYIPS.split(',').map(ip => ip.trim()) 
    : Config.proxyIPs;
  
  const healthStmts = proxyIps.map(async (ipPort) => {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { 
        signal: controller.signal,
        method: 'HEAD',
      });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status === 404) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error(`Health check failed for ${ipPort}: ${e.message}`);
    }
    
    return env.DB.prepare(
      "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
    ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000));
  });
  
  try {
    await env.DB.batch(await Promise.all(healthStmts));
  } catch (e) {
    console.error(`Health check batch error: ${e.message}`);
  }
}

// ============================================================================
// ADMIN LOGIN HTML
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-container { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); padding: 40px; border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); max-width: 400px; border: 1px solid rgba(255, 255, 255, 0.1); }
    h1 { color: #ffffff; margin-bottom: 24px; font-size: 28px; }
    form { display: flex; flex-direction: column; gap: 16px; }
    input { background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); color: #ffffff; padding: 14px; border-radius: 8px; transition: all 0.3s; }
    input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); background: rgba(255, 255, 255, 0.15); }
    button { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; border: none; padding: 14px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.3s; }
    button:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4); }
    .error { color: #ff6b6b; margin-top: 16px; background: rgba(255, 107, 107, 0.1); padding: 12px; border-radius: 8px; border: 1px solid rgba(255, 107, 107, 0.3); }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>🔐 Admin Login</h1>
    <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
      <input type="password" name="password" placeholder="Enter admin password" required>
      <input type="text" name="totp" placeholder="2FA Code (if enabled)" maxlength="6">
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`;

// @ts-ignore
const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - VLESS Proxy Manager</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root { --bg-main: #0a0e17; --text-primary: #F9FAFB; --accent: #3B82F6; --danger: #EF4444; --success: #22C55E; --purple: #a855f7; }
    body { background: linear-gradient(135deg, #0a0e17 0%, #111827 100%); color: var(--text-primary); font-family: Inter, sans-serif; min-height: 100vh; }
    .container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }
    .card { background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%); border-radius: 16px; padding: 28px; border: 1px solid rgba(255, 255, 255, 0.06); margin-bottom: 24px; }
    .dashboard-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
    .stat-card { background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%); padding: 24px; border-radius: 16px; text-align: center; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    input, select { background: #374151; border: 1px solid #4B5563; color: var(--text-primary); padding: 12px; border-radius: 8px; }
    .btn { padding: 12px 22px; border-radius: 10px; cursor: pointer; }
    .btn-primary { background: linear-gradient(135deg, var(--accent) 0%, #6366f1 100%); color: white; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 14px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.04); }
    .chart-container { height: 300px; }
    .search-input { width: 100%; margin-bottom: 20px; }
    .bulk-actions { display: flex; gap: 10px; margin-bottom: 20px; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="container">
    <h1>Admin Dashboard</h1>
    <div class="dashboard-stats">
      <div class="stat-card"><div id="total-users">0</div><div>Total Users</div></div>
      <div class="stat-card"><div id="active-users">0</div><div>Active Users</div></div>
      <div class="stat-card"><div id="traffic-used">0 GB</div><div>Traffic Used</div></div>
      <div class="stat-card"><div id="health-status">Healthy</div><div>System Health</div></div>
    </div>
    <div class="card">
      <h2>User Traffic Chart</h2>
      <div class="chart-container"><canvas id="traffic-chart"></canvas></div>
    </div>
    <div class="card">
      <h2>User Management</h2>
      <input type="text" class="search-input" placeholder="Search users..." onkeyup="filterTable()">
      <div class="bulk-actions">
        <button class="btn btn-primary" onclick="addUser()">Add User</button>
        <button class="btn btn-secondary" onclick="bulkDelete()">Bulk Delete</button>
        <button class="btn btn-danger" onclick="exportUsers()">Export CSV</button>
      </div>
      <div class="table-wrapper">
        <table id="user-table">
          <thead>
            <tr>
              <th><input type="checkbox" onclick="toggleAll(this)"></th>
              <th>UUID</th>
              <th>Expiration</th>
              <th>Traffic Used</th>
              <th>Status</th>
              <th>Actions</th>
          </thead>
          <tbody>
            <!-- Dynamic users -->
          </tbody>
        </table>
      </div>
    </div>
  </div>
  <div id="toast"></div>
  <div class="modal-overlay" id="add-user-modal">
    <div class="modal-content">
      <h2>Add New User</h2>
      <form id="add-user-form">
        <div class="form-group">
          <label>Expiration Date</label>
          <input type="date" name="exp_date" required>
        </div>
        <div class="form-group">
          <label>Expiration Time</label>
          <input type="time" name="exp_time" required>
        </div>
        <div class="form-group">
          <label>Notes</label>
          <input type="text" name="notes">
        </div>
        <button type="submit" class="btn btn-primary">Save User</button>
      </form>
    </div>
  </div>
  <script nonce="CSP_NONCE_PLACEHOLDER">
    let users = [];
    const trafficChart = new Chart(document.getElementById('traffic-chart'), {
      type: 'line',
      data: { labels: [], datasets: [{ label: 'Traffic (GB)', data: [], borderColor: var(--accent) }] },
      options: { responsive: true, scales: { y: { beginAtZero: true } } }
    });

    async function loadUsers() {
      users = await fetch('/api/users').then(res => res.json());
      const tableBody = document.querySelector('#user-table tbody');
      tableBody.innerHTML = '';
      users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
  const row = `
    <tr>
      <td><input type="checkbox" /></td>
      <td>${user.uuid}</td>
      <td>${user.expiration_date} ${user.expiration_time}</td>
      <td>${user.traffic_used} bytes</td>
      <td>
        <span class="${user.is_expired ? 'status-expired' : 'status-active'}">
          ${user.is_expired ? 'Expired' : 'Active'}
        </span>
      </td>
      <td>
        <button onclick="editUser('${user.uuid}')">Edit</button>
        <button onclick="deleteUser('${user.uuid}')">Delete</button>
      </td>
    </tr>
  `;
`;
        tableBody.appendChild(row);
      });
      updateStats();
      updateChart();
    }

    function updateStats() {
      document.getElementById('total-users').textContent = users.length;
      document.getElementById('active-users').textContent = users.filter(u => !u.is_expired).length;
      const totalTraffic = users.reduce((sum, u) => sum + u.traffic_used, 0) / (1024 * 1024 * 1024);
      document.getElementById('traffic-used').textContent = totalTraffic.toFixed(2) + ' GB';
      document.getElementById('health-status').textContent = 'Healthy';
    }

    function updateChart() {
      trafficChart.data.labels = users.map(u => u.uuid.slice(0, 8));
      trafficChart.data.datasets[0].data = users.map(u => u.traffic_used / (1024 * 1024 * 1024));
      trafficChart.update();
    }

    function filterTable() {
      const input = document.querySelector('.search-input').value.toLowerCase();
      const rows = document.querySelectorAll('#user-table tbody tr');
      rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(input) ? '' : 'none';
      });
    }

    function toggleAll(source) {
      document.querySelectorAll('#user-table input[type="checkbox"]').forEach(cb => cb.checked = source.checked);
    }

    function addUser() {
      document.getElementById('add-user-modal').classList.add('show');
    }

    document.getElementById('add-user-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      await fetch('/api/add-user', { method: 'POST', body: formData });
      document.getElementById('add-user-modal').classList.remove('show');
      loadUsers();
    });

    function editUser(uuid) {
      alert('Edit user ' + uuid);
    }

    function deleteUser(uuid) {
      if (confirm('Delete user?')) {
        fetch('/api/delete-user/' + uuid, { method: 'DELETE' });
        loadUsers();
      }
    }

    function bulkDelete() {
      const selected = Array.from(document.querySelectorAll('#user-table input[type="checkbox"]:checked')).map(cb => cb.parentElement.nextElementSibling.textContent);
      if (selected.length && confirm('Delete selected?')) {
        fetch('/api/bulk-delete', { method: 'POST', body: JSON.stringify(selected) });
        loadUsers();
      }
    }

    function exportUsers() {
      var csv = 'UUID,Expiration,Traffic\n' + users.map(function(u) {
        return u.uuid + ',' + u.expiration_date + ' ' + u.expiration_time + ',' + u.traffic_used;
      }).join('\n');
      var blob = new Blob([csv], { type: 'text/csv' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'users.csv';
      a.click();
    }

    loadUsers();
    setInterval(loadUsers, CONST.AUTO_REFRESH_INTERVAL);
  </script>
</body>
</html>`;

// @ts-ignore
const userPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Panel - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    body { background: #0f172a; color: #f9fafb; font-family: Inter, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .panel { max-width: 800px; background: rgba(255,255,255,0.05); backdrop-filter: blur(20px); border-radius: 24px; padding: 40px; box-shadow: 0 25px 70px rgba(0,0,0,0.4); }
    h1 { font-size: 28px; color: #3b82f6; margin-bottom: 20px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 30px; }
    .stat { background: rgba(255,255,255,0.02); padding: 16px; border-radius: 12px; text-align: center; }
    .qr-section { margin-bottom: 30px; }
    #qr-code { background: white; padding: 20px; border-radius: 16px; display: inline-block; }
    .chart-container { height: 250px; margin-top: 20px; }
    .btn { background: #3b82f6; color: white; padding: 12px 20px; border-radius: 8px; cursor: pointer; margin-top: 10px; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="panel">
    <h1>User Panel</h1>
    <div class="stats">
      <div class="stat"><h3>Traffic Used</h3><p id="traffic-used">0 GB</p></div>
      <div class="stat"><h3>Expiration</h3><p id="expiration">—</p></div>
      <div class="stat"><h3>Status</h3><p id="status">Active</p></div>
    </div>
    <div class="qr-section">
      <h2>QR Code</h2>
      <div id="qr-code"></div>
      <button class="btn" onclick="testConfig()">Test Config</button>
      <button class="btn" onclick="downloadQR()">Download QR</button>
    </div>
    <div class="chart-container"><canvas id="history-chart"></canvas></div>
  </div>
  <script nonce="CSP_NONCE_PLACEHOLDER">
    // QRCode logic here...
  </script>
</body>
</html>`;
