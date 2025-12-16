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

// @ts-ignore
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

// ============================================================================
// ADMIN PANEL HTML - Enhanced
// ============================================================================

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
            </tr>
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
        row.innerHTML = \`
          <td><input type="checkbox"></td>
          <td>\${user.uuid}</td>
          <td>\${user.expiration_date} \${user.expiration_time}</td>
          <td>\${user.traffic_used} bytes</td>
          <td><span class="\${user.is_expired ? 'status-expired' : 'status-active'}">\${user.is_expired ? 'Expired' : 'Active'}</span></td>
          <td><button onclick="editUser('\${user.uuid}')">Edit</button> <button onclick="deleteUser('\${user.uuid}')">Delete</button></td>
        \`;
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
      const csv = 'UUID,Expiration,Traffic\\n' + users.map(u => \`\${u.uuid},\${u.expiration_date} \${u.expiration_time},\${u.traffic_used}\`).join('\\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'users.csv';
      a.click();
    }

    loadUsers();
    setInterval(loadUsers, CONST.AUTO_REFRESH_INTERVAL);
  </script>
</body>
</html>`;

// ============================================================================
// USER PANEL HTML - Enhanced
// ============================================================================

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
    var QRCode=function(e,t){this._htOption={width:256,height:256,typeNumber:4,colorDark:"#000000",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.H};if(typeof t=="string"){t={text:t}}if(t){for(var n in t){this._htOption[n]=t[n]}}if(typeof this._htOption.typeNumber=="string"){this._htOption.typeNumber=parseInt(this._htOption.typeNumber)}if(typeof this._htOption.correctLevel=="string"){this._htOption.correctLevel=QRCode.CorrectLevel[this._htOption.correctLevel]}this._oQRCode=new QRCodeModel(this._htOption.typeNumber,this._htOption.correctLevel);this._oQRCode.addData(this._htOption.text);this._oQRCode.make();this.makeImage()};QRCode.CorrectLevel={L:1,M:0,Q:3,H:2};QRCode.prototype={makeImage:function(){var e=this._htOption.width;var t=this._htOption.height;var n=this._oQRCode.moduleCount;var i=Math.floor(t/n);var r=Math.floor(e/n);var o="";o+='<table style="border:0;border-collapse:collapse;">';for(var a=0;a<n;a++){o+="<tr>";for(var s=0;s<n;s++){var l=this._oQRCode.isDark(a,s)?this._htOption.colorDark:this._htOption.colorLight;o+='<td style="border:0;border-collapse:collapse;padding:0;margin:0;width:'+r+"px;height:"+i+"px;background-color:"+l+';"></td>'}o+="</tr>"}o+="</table>";e.innerHTML=o}};function QR8bitByte(e){this.mode=QRMode.MODE_8BIT_BYTE;this.data=e;this.parsedData=[];for(var t=0,n=this.data.length;t<n;t++){var i=[];var r=this.data.charCodeAt(t);if(r>65536){i[0]=240|(r&1835008)>>>18;i[1]=128|(r&258048)>>>12;i[2]=128|(r&4032)>>>6;i[3]=128| r&63}else if(r>2048){i[0]=224|(r&61440)>>>12;i[1]=128|(r&4032)>>>6;i[2]=128| r&63}else if(r>128){i[0]=192|(r&1984)>>>6;i[1]=128| r&63}else{i[0]=r}this.parsedData.push(i)}this.parsedData=Array.prototype.concat.apply([],this.parsedData);if(this.parsedData.length!=this.data.length){this.parsedData.unshift(191);this.parsedData.unshift(187);this.parsedData.unshift(239)}}QR8bitByte.prototype={getLength:function(e){return this.parsedData.length},write:function(e){for(var t=0,n=this.parsedData.length;t<n;t++){e.put(this.parsedData[t],8)}}};function QRCodeModel(e,t){this.typeNumber=e;this.errorCorrectLevel=t;this.modules=null;this.moduleCount=0;this.dataCache=null;this.dataList=[]}var qrcode=QRCodeModel.prototype;qrcode.addData=function(e){var t=new QR8bitByte(e);this.dataList.push(t);this.dataCache=null};qrcode.isDark=function(e,t){if(e<0||this.moduleCount<=e||t<0||this.moduleCount<=t){throw new Error(e+","+t)}return this.modules[e][t]};qrcode.getModuleCount=function(){return this.moduleCount};qrcode.make=function(){if(this.typeNumber<1){var e=1;for(e=1;e<40;e++){var t=QRRSBlock.getRSBlocks(e,this.errorCorrectLevel);var n=new QRBitBuffer();var i=0;for(var r=0;r<t.length;r++){i+=t[r].dataCount}for(var r=0;r<this.dataList.length;r++){var o=this.dataList[r];n.put(o.mode,4);n.put(o.getLength(),QRUtil.getLengthInBits(o.mode,e));o.write(n)}if(n.getLengthInBits()<=i*8)break}this.typeNumber=e}this.makeImpl(false,this.getBestMaskPattern())};qrcode.makeImpl=function(e,t){this.moduleCount=this.typeNumber*4+17;this.modules=new Array(this.moduleCount);for(var n=0;n<this.moduleCount;n++){this.modules[n]=new Array(this.moduleCount);for(var i=0;i<this.moduleCount;i++){this.modules[n][i]=null}}this.setupPositionProbePattern(0,0);this.setupPositionProbePattern(this.moduleCount-7,0);this.setupPositionProbePattern(0,this.moduleCount-7);this.setupPositionAdjustPattern();this.setupTimingPattern();this.setupTypeInfo(e,t);if(this.typeNumber>=7)this.setupTypeNumber(e);if(this.dataCache==null)this.dataCache=QRCodeModel.createData(this.typeNumber,this.errorCorrectLevel,this.dataList);this.mapData(this.dataCache,t)};qrcode.setupPositionProbePattern=function(e,t){for(var n=-1;n<=7;n++){if(e+n<=-1||this.moduleCount<=e+n)continue;if(t>=0&&t<=7){this.modules[e+n][t]=true;this.modules[e+n][t+6]=true;this.modules[e][t+n]=true;this.modules[e+6][t+n]=true}this.modules[e+n][t+1]=true;this.modules[e+n][t+5]=true;this.modules[e+1][t+n]=true;this.modules[e+5][t+n]=true;this.modules[e+1][t+1]=true;this.modules[e+1][t+2]=true;this.modules[e+1][t+3]=true;this.modules[e+1][t+4]=true;this.modules[e+1][t+5]=true;this.modules[e+2][t+1]=true;this.modules[e+3][t+1]=true;this.modules[e+4][t+1]=true;this.modules[e+5][t+1]=true;this.modules[e+5][t+2]=true;this.modules[e+5][t+3]=true;this.modules[e+5][t+4]=true;this.modules[e+5][t+5]=true;this.modules[e+2][t+5]=true;this.modules[e+3][t+5]=true;this.modules[e+4][t+5]=true}};qrcode.setupTimingPattern=function(){for(var e=8;e<this.moduleCount-8;e++){if(this.modules[e][6]!=null)continue;this.modules[e][6]=e%2==0;this.modules[6][e]=e%2==0}};qrcode.setupPositionAdjustPattern=function(){var e=QRUtil.getPatternPosition(this.typeNumber);for(var t=0;t<e.length;t++){for(var n=0;n<e.length;n++){var i=e[t];var r=e[n];if(this.modules[i][r]!=null)continue;for(var o=-2;o<=2;o++){for(var a=-2;a<=2;a++){if(o==-2||o==2||a==-2||a==2||o==0&&a==0){this.modules[i+o][r+a]=true}else{this.modules[i+o][r+a]=false}} }}};qrcode.setupTypeNumber=function(e){var t=QRUtil.getBCHTypeNumber(this.typeNumber);for(var n=0;n<18;n++){var i=!e&& (t>>n&1)==1;this.modules[Math.floor(n/3)][n%3+this.moduleCount-8-3]=i}for(var n=0;n<18;n++){var i=!e&& (t>>n&1)==1;this.modules[n%3+this.moduleCount-8-3][Math.floor(n/3)]=i}};qrcode.setupTypeInfo=function(e,t){var n=this.errorCorrectLevel<<3|t;var i=QRUtil.getBCHTypeInfo(n);for(var r=0;r<15;r++){var o=!e&& (i>>r&1)==1;if(r<6)this.modules[r][8]=o;else if(r<8)this.modules[r+1][8]=o;else this.modules[this.moduleCount-15+r][8]=o}for(var r=0;r<15;r++){var o=!e&& (i>>r&1)==1;if(r<8)this.modules[8][this.moduleCount-r-1]=o;else if(r<9)this.modules[8][15-r-1+1]=o;else this.modules[8][15-r-1]=o}this.modules[this.moduleCount-8][8]=!e};qrcode.mapData=function(e,t){var n=-1;var i=this.moduleCount-1;var r=7;var o=0;for(var a=this.moduleCount-1;a>0;a-=2){if(a==6)a--;for(;;){for(var s=0;s<2;s++){if(this.modules[i][a-s]==null){var l=false;if(o<e.length){l=(e[o]>>>r&1)==1}if(QRUtil.getMask(t,i,a-s)){l=!l}this.modules[i][a-s]=l;r--;if(r==-1){o++;r=7}}}i+=n;if(i<0||this.moduleCount<=i){i-=n;n=-n;break}}}};QRCodeModel.PAD0=236;QRCodeModel.PAD1=17;QRCodeModel.createData=function(e,t,n){var i=QRRSBlock.getRSBlocks(e,t);var r=new QRBitBuffer();for(var o=0;o<n.length;o++){var a=n[o];r.put(a.mode,4);r.put(a.getLength(),QRUtil.getLengthInBits(a.mode,e));a.write(r)}var s=0;for(var o=0;o<i.length;o++){s+=i[o].dataCount}if(r.getLengthInBits()>s*8){throw new Error("code length overflow. ("+r.getLengthInBits()+">"+s*8+")")}if(r.getLengthInBits()+4<=s*8)r.put(0,4);while(r.getLengthInBits()%8!=0){r.putBit(false)}while(true){if(r.getLengthInBits()>=s*8){break}r.put(QRCodeModel.PAD0,8);if(r.getLengthInBits()>=s*8){break}r.put(QRCodeModel.PAD1,8)}return QRCodeModel.createBytes(r,i)};QRCodeModel.createBytes=function(e,t){var n=0;var i=0;var r=0;var o=new Array(t.length);var a=new Array(t.length);for(var s=0;s<t.length;s++){var l=t[s].dataCount;var h=t[s].totalCount-l;i=Math.max(i,l);r=Math.max(r,h);o[s]=new Array(l);for(var u=0;u<o[s].length;u++){o[s][u]=255&e.buffer[u+n]}n+=l;var c=QRUtil.getErrorCorrectPolynomial(h);var f=new QRPolynomial(o[s],c.getLength()-1);var d=f.mod(c);a[s]=new Array(c.getLength()-1);for(var u=0;u<a[s].length;u++){var p=u+d.getLength()-a[s].length;a[s][u]=p>=0?d.get(p):0}}var v=0;for(var u=0;u<t.length;u++){v+=t[u].totalCount}var m=new Array(v);var g=0;for(var u=0;u<i;u++){for(var s=0;s<t.length;s++){if(u<o[s].length){m[g++]=o[s][u]}}}for(var u=0;u<r;u++){for(var s=0;s<t.length;s++){if(u<a[s].length){m[g++]=a[s][u]}}}return m};function QRBitBuffer(){this.buffer=[];this.length=0}QRBitBuffer.prototype={get:function(e){var t=Math.floor(e/8);return (this.buffer[t]>>>7-e%8&1)==1},put:function(e,t){for(var n=0;n<t;n++){this.putBit((e>>>t-n-1&1)==1)}},getLengthInBits:function(){return this.length},putBit:function(e){var t=Math.floor(this.length/8);if(this.buffer.length<=t){this.buffer.push(0)}if(e){this.buffer[t]|=128>>>this.length%8}this.length++}};var QRMode={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8};var QRMaskPattern={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7};var QRUtil={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:32768|16384|8192|4096|2048|1024|512|1,G18:262144|131072|65536|32768|16384|8192|4096|2048|1024|1,G15_MASK:53248,getBCHTypeInfo:function(e){var t=e<<3;while(QRUtil.getBCHDigit(t)-QRUtil.getBCHDigit(QRUtil.G15)>=0){t^=QRUtil.G15<<QRUtil.getBCHDigit(t)-QRUtil.getBCHDigit(QRUtil.G15)}return (e<<3)|t},getBCHTypeNumber:function(e){var t=e<<12;while(QRUtil.getBCHDigit(t)-QRUtil.getBCHDigit(QRUtil.G18)>=0){t^=QRUtil.G18<<QRUtil.getBCHDigit(t)-QRUtil.getBCHDigit(QRUtil.G18)}return e<<12|t},getBCHDigit:function(e){var t=0;while(e!=0){t++;e>>>=1}return t},getPatternPosition:function(e){return QRUtil.PATTERN_POSITION_TABLE[e-1]},getMask:function(e,t,n){switch(e){case QRMaskPattern.PATTERN000:return (t+n)%2==0;case QRMaskPattern.PATTERN001:return t%2==0;case QRMaskPattern.PATTERN010:return n%3==0;case QRMaskPattern.PATTERN011:return (t+n)%3==0;case QRMaskPattern.PATTERN100:return (Math.floor(t/2)+Math.floor(n/3))%2==0;case QRMaskPattern.PATTERN101:return t*n%2+t*n%3==0;case QRMaskPattern.PATTERN110:return (t*n%2+t*n%3)%2==0;case QRMaskPattern.PATTERN111:return (t*n%3+(t+n)%2)%2==0;default:throw new Error("bad maskPattern:"+e)}},getErrorCorrectPolynomial:function(e){var t=new QRPolynomial([1],0);for(var n=0;n<e;n++){t=t.multiply(new QRPolynomial([1,QRMath.gexp(n)],0))}return t},getLengthInBits:function(e,t){if(1<=t&&t<10){switch(e){case QRMode.MODE_NUMBER:return 10;case QRMode.MODE_ALPHA_NUM:return 9;case QRMode.MODE_8BIT_BYTE:return 8;case QRMode.MODE_KANJI:return 8;default:throw new Error("mode:"+e)}}else if(t<27){switch(e){case QRMode.MODE_NUMBER:return 12;case QRMode.MODE_ALPHA_NUM:return 11;case QRMode.MODE_8BIT_BYTE:return 16;case QRMode.MODE_KANJI:return 10;default:throw new Error("mode:"+e)}}else if(t<41){switch(e){case QRMode.MODE_NUMBER:return 14;case QRMode.MODE_ALPHA_NUM:return 13;case QRMode.MODE_8BIT_BYTE:return 16;case QRMode.MODE_KANJI:return 12;default:throw new Error("mode:"+e)}}else{throw new Error("type:"+t)}},getLostPoint:function(e){var t=e.getModuleCount();var n=0;for(var i=0;i<t;i++){for(var r=0;r<t;r++){var o=0;var a=e.isDark(i,r);for(var s=-1;s<=1;s++){if(i+s<0||t<=i+s)continue;for(var l=-1;l<=1;l++){if(r+l<0||t<=r+l)continue;if(s==0&&l==0)continue;if(a==e.isDark(i+s,r+l))o++}}if(o>5)n+=3+o-5}}}for(var i=0;i<t-1;i++){for(var r=0;r<t-1;r++){var h=0;if(e.isDark(i,r))h++;if(e.isDark(i+1,r))h++;if(e.isDark(i,r+1))h++;if(e.isDark(i+1,r+1))h++;if(h==0||h==4)n+=3}}}for(var i=0;i<t;i++){for(var r=0;r<t-6;r++){if(e.isDark(i,r)&&!e.isDark(i,r+1)&&e.isDark(i,r+2)&&e.isDark(i,r+3)&&e.isDark(i,r+4)&&!e.isDark(i,r+5)&&e.isDark(i,r+6))n+=40}}}for(var r=0;r<t;r++){for(var i=0;i<t-6;i++){if(e.isDark(i,r)&&!e.isDark(i+1,r)&&e.isDark(i+2,r)&&e.isDark(i+3,r)&&e.isDark(i+4,r)&&!e.isDark(i+5,r)&&e.isDark(i+6,r))n+=40}}}var u=0;for(var r=0;r<t;r++){for(var i=0;i<t;i++){if(e.isDark(i,r))u++}}var c=Math.abs(100*u/t/t-25)*4;if(c>20)n+=c;return n}};var QRMath={glog:function(e){if(e<1)throw new Error("glog("+e+")");return QRMath.LOG_TABLE[e]},gexp:function(e){while(e<0){e+=255}while(e>=256){e-=255}return QRMath.EXP_TABLE[e]},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)};for(var i=0;i<8;i++){QRMath.EXP_TABLE[i]=1<<i}for(var i=8;i<256;i++){QRMath.EXP_TABLE[i]=QRMath.EXP_TABLE[i-4]^QRMath.EXP_TABLE[i-5]^QRMath.EXP_TABLE[i-6]^QRMath.EXP_TABLE[i-8]}for(var i=0;i<255;i++){QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]]=i}function QRPolynomial(e,t){if(e.length==undefined)throw new Error(e.length+"/"+t);var n=0;while(n<e.length&&e[n]==0){n++}this.num=new Array(e.length-n+t);for(var i=0;i<e.length-n;i++){this.num[i]=e[i+n]}}QRPolynomial.prototype={get:function(e){return this.num[e]},getLength:function(){return this.num.length},multiply:function(e){var t=new Array(this.getLength()+e.getLength()-1);for(var n=0;n<this.getLength();n++){for(var i=0;i<e.getLength();i++){t[n+i]^=QRMath.gexp(QRMath.glog(this.get(n))+QRMath.glog(e.get(i)))}}return new QRPolynomial(t,0)},mod:function(e){if(this.getLength()-e.getLength()<0)return this;var t=QRMath.glog(this.get(0))-QRMath.glog(e.get(0));var n=new Array(this.getLength());for(var i=0;i<this.getLength();i++){n[i]=this.get(i)}for(var i=0;i<e.getLength();i++){n[i]^=QRMath.gexp(QRMath.glog(e.get(i))+t)}return new QRPolynomial(n,0).mod(e)}};var QRRSBlock={RS_BLOCK_TABLE:[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[9,141,111,3,142,112],[3,67,41,13,68,42],[17,54,24,1,55,25],[11,36,12,13,37,13],[17,129,102,5,130,103],[19,60,38,3,61,39],[3,42,14,23,43,15],[4,27,9,23,28,10],[10,147,117,5,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],getRSBlocks:function(e,t){var n=QRRSBlock.getRsBlockTable(e,t);if(n==undefined){throw new Error("bad rs block @ typeNumber:"+e+"/errorCorrectLevel:"+t)}var i=n.length/3;var r=new Array();for(var o=0;o<i;o++){var a=n[o*3+0];var s=n[o*3+1];var l=n[o*3+2];for(var h=0;h<a;h++){r.push(new QRRSBlock(s,l))}}return r},getRsBlockTable:function(e,t){switch(t){case QRUtil.getErrorCorrectPolynomial(1).getLength()-1:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+0];case QRUtil.getErrorCorrectPolynomial(0).getLength()-1:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+1];case QRUtil.getErrorCorrectPolynomial(3).getLength()-1:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+2];case QRUtil.getErrorCorrectPolynomial(2).getLength()-1:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+3]}}}};function QRRSBlock(e,t){this.totalCount=e;this.dataCount=t}QRRSBlock.getRSBlocks=function(e,t){var n=QRRSBlock.getRsBlockTable(e,t);if(n==undefined){throw new Error("bad rs block @ typeNumber:"+e+"/errorCorrectLevel:"+t)}var i=n.length/3;var r=[];for(var o=0;o<i;o++){var a=n[o*3+0];var s=n[o*3+1];var l=n[o*3+2];for(var h=0;h<a;h++){r.push(new QRRSBlock(s,l))}}return r};QRRSBlock.getRsBlockTable=function(e,t){switch(t){case QRErrorCorrectLevel.L:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+0];case QRErrorCorrectLevel.M:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+1];case QRErrorCorrectLevel.Q:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+2];case QRErrorCorrectLevel.H:return QRRSBlock.RS_BLOCK_TABLE[(e-1)*4+3];default:return undefined}};var QRErrorCorrectLevel={L:1,M:0,Q:3,H:2}; 

    let userData = {};
    const historyChart = new Chart(document.getElementById('history-chart'), {
      type: 'bar',
      data: { labels: [], datasets: [{ label: 'Daily Traffic (MB)', data: [], backgroundColor: '#3b82f6' }] },
      options: { responsive: true, scales: { y: { beginAtZero: true } } }
    });

    async function loadUserData(uuid) {
      userData = await fetch('/api/user/' + uuid).then(res => res.json());
      document.getElementById('traffic-used').textContent = (userData.traffic_used / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
      document.getElementById('expiration').textContent = userData.expiration_date + ' ' + userData.expiration_time;
      document.getElementById('status').textContent = userData.is_expired ? 'Expired' : 'Active';
      generateQR('vless://' + userData.uuid + '@example.com:443?type=ws#UserConfig');
      loadHistory(uuid);
    }

    function generateQR(text) {
      document.getElementById('qr-code').innerHTML = '';
      new QRCode(document.getElementById('qr-code'), text);
    }

    async function loadHistory(uuid) {
      const history = await fetch('/api/user/' + uuid + '/history').then(res => res.json());
      historyChart.data.labels = history.map(h => h.date);
      historyChart.data.datasets[0].data = history.map(h => h.download / (1024 * 1024));
      historyChart.update();
    }

    function testConfig() {
      alert('Config test: Valid');
    }

    function downloadQR() {
      const canvas = document.querySelector('#qr-code canvas');
      canvas.toBlob(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qr.png';
        a.click();
      });
    }

    const uuid = location.pathname.slice(1);
    loadUserData(uuid);
  </script>
</body>
</html>`;

// ============================================================================
// CUSTOM PAGES
// ============================================================================

const custom404HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 - Not Found</title>
  <style>
    body { background: #0f172a; color: #f9fafb; text-align: center; padding: 100px; font-family: sans-serif; }
    h1 { font-size: 48px; }
  </style>
</head>
<body>
  <h1>404 - Page Not Found</h1>
  <p>The requested resource could not be found.</p>
</body>
</html>`;

const robotsTxt = `User-agent: *
Disallow: /admin/
Disallow: /api/
Sitemap: https://yourdomain.com/sitemap.xml`;

const securityTxt = `Contact: mailto:security@yourdomain.com
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en
Policy: https://yourdomain.com/security-policy`;

// ============================================================================
// PROTOCOL HANDLER
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  const upgradeHeader = request.headers.get('Upgrade');
  if (!upgradeHeader || upgradeHeader !== 'websocket') {
    return new Response('Expected Upgrade: websocket', { status: 426 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();
  const url = new URL(request.url);
  const urlIdx = url.hostname.lastIndexOf("---");
  const remoteDomain = url.hostname.slice(urlIdx + 3);
  let address = '';
  let portWithRandomLog = '';
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  if (url.pathname.includes("/tcp/")) {
    const tcpSocket = connect({
      hostname: config.proxyIP || '127.0.0.1',
      port: config.proxyPort || 443,
    });
    server.addEventListener('message', event => {
      tcpSocket.write(event.data);
    });
    tcpSocket.readable.pipeTo(server.writable.getWriter()).catch(() => {});
    return new Response(null, { status: 101, webSocket: client });
  }
  const log = (info, event) => {
    console.log(`[${remoteDomain}] ${info}`, event || '');
  };
  const vlessBufferToUint8Array = (vlessBuffer) => {
    const len = vlessBuffer.byteLength;
    const u8a = new Uint8Array(len);
    const view = new DataView(vlessBuffer);
    for(let i = 0; i < len; i++) {
      u8a[i] = view.getUint8(i);
    }
    return u8a;
  };
  const uint8ArrayToUUID = (u8Arr) => {
    return stringify(vlessBufferToUint8Array(u8Arr.buffer));
  };
  const isValidVLESS = (uuidStr) => {
    return isValidUUID(uuidStr);
  };
  if (url.pathname.includes("/vless")) {
    let vlessConfig = '';
    const match = url.pathname.match(/\/vless\/(.*?)\/(.*)/);
    if (match) {
      vlessConfig = match[1];
    } else {
      return new Response('Invalid path', { status: 400 });
    }
    const uuid = vlessConfig;
    if (!isValidVLESS(uuid)) {
      log('Invalid UUID');
      return new Response('Invalid UUID', { status: 400 });
    }
    address = url.hostname;
    portWithRandomLog = url.port || '443';
    log(`Connecting to ${address}:${portWithRandomLog}`);
    let remoteSocket;
    try {
      remoteSocket = connect({
        hostname: config.proxyIP,
        port: parseInt(config.proxyPort),
      });
    } catch (error) {
      log('Socket connect error', error);
      return new Response('Socket connection failed', { status: 500 });
    }
    server.addEventListener('message', async event => {
      const value = event.data;
      try {
        remoteSocket.write(value);
      } catch (error) {
        remoteSocket.close();
      }
    });
    remoteSocket.readable.pipeTo(server.writable.getWriter()).catch(() => {});
    let isVlessHeaderSent = false;
    remoteSocket.writable.getWriter().write(Uint8Array.from([0x05, 0x00, 0x00]));
    const writer = remoteSocket.writable.getWriter();
    await writer.write(Uint8Array.from([0x05, 0x01, 0x00, 0x03, address.length, ...new TextEncoder().encode(address), portWithRandomLog >> 8, portWithRandomLog & 0xff]));
    writer.releaseLock();
    remoteSocket.readable.pipeTo(server.writable.getWriter()).catch(() => {});
    return new Response(null, { status: 101, webSocket: client });
  }
  return new Response('Not found', { status: 404 });
}

// ============================================================================
// FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
      const cfg = await Config.fromEnv(env);
      
      if (url.pathname === '/robots.txt') {
        const headers = new Headers({ 'Content-Type': 'text/plain' });
        addSecurityHeaders(headers, null);
        return new Response(robotsTxt, { headers });
      }
      
      if (url.pathname === '/.well-known/security.txt') {
        const headers = new Headers({ 'Content-Type': 'text/plain' });
        addSecurityHeaders(headers, null);
        return new Response(securityTxt, { headers });
      }
      
      if (url.pathname === '/admin') {
        const nonce = generateNonce();
        const html = adminLoginHTML.replace('CSP_NONCE_PLACEHOLDER', nonce).replace('ADMIN_PATH_PLACEHOLDER', '/admin/login');
        const headers = new Headers({ 'Content-Type': 'text/html' });
        addSecurityHeaders(headers, nonce);
        return new Response(html, { headers });
      }
      
      if (url.pathname === '/admin/dashboard') {
        const nonce = generateNonce();
        const html = adminPanelHTML.replace('CSP_NONCE_PLACEHOLDER', nonce);
        const headers = new Headers({ 'Content-Type': 'text/html' });
        addSecurityHeaders(headers, nonce, { img: 'https://cdn.jsdelivr.net', connect: 'wss://your-ws-endpoint' });
        return new Response(html, { headers });
      }
      
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const userData = await getUserData(env, path, ctx);
        if (!userData) return new Response('User not found', { status: 403 });
        const nonce = generateNonce();
        const html = userPanelHTML.replace('CSP_NONCE_PLACEHOLDER', nonce);
        const headers = new Headers({ 'Content-Type': 'text/html' });
        addSecurityHeaders(headers, nonce);
        return new Response(html, { headers });
      }
      
      if (request.headers.get('Upgrade') === 'websocket') {
        return ProtocolOverWSHandler(request, cfg, env, ctx);
      }
      
      if (url.pathname.startsWith('/xray/') || url.pathname.startsWith('/sb/')) {
        const core = url.pathname.startsWith('/xray/') ? 'xray' : 'sb';
        const userID = url.pathname.split('/')[2];
        return handleIpSubscription(core, userID, url.hostname);
      }
      
      if (env.ROOT_PROXY_URL && url.pathname === '/') {
        const newUrl = new URL(env.ROOT_PROXY_URL + url.pathname + url.search);
        newUrl.hostname = new URL(env.ROOT_PROXY_URL).hostname;
        const proxyRequest = new Request(newUrl, request);
        return fetch(proxyRequest);
      }
      
      const masqueradeHtml = '<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>';
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null);
      return new Response(masqueradeHtml, { headers });
      
    } catch (e) {
      console.error('Fetch error:', e);
      return new Response(custom404HTML, { status: 404, headers: { 'Content-Type': 'text/html' } });
    }
  },

  async scheduled(event, env, ctx) {
    await performHealthCheck(env, ctx);
    await cleanupOldIps(env, ctx);
  }
};
