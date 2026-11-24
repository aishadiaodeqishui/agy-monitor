/**
 * Multi-account vault, safe switching, OAuth capture, import/export,
 * and post-restart At-Most-Once task resume coordinator.
 *
 * Security & Stability Guarantees:
 * - Zero plaintext tokens on disk: credentials are sealed with Windows DPAPI
 *   (CurrentUser scope) via native AgyAccountTool.exe.
 * - Zero CLI argument exposure: secrets move exclusively over stdin/stdout pipes
 *   or DPAPI-encrypted temporary files.
 * - Detached offline switch daemon: gracefully closes Antigravity & language_server
 *   via WM_CLOSE before updating Windows Credential Manager + app_storage.json +
 *   credential-user-scope, with automatic DPAPI rollback on any error.
 * - At-Most-Once auto-resume: consumes pending_resume.json before dispatching
 *   `agentapi send-message` only after the new account's quota RPC confirms readiness.
 */

import { execFile, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { DatabaseSync } from 'node:sqlite';
import { atomicWriteBuffer, atomicWriteJson, atomicWriteText } from './paths.mjs';
import { findAntigravityExePath } from './cdp_theme_bridge.mjs';
import { restoreHostOpacityFallback } from './backdrop_manager.mjs';
import { normalizeQuotaSummary } from './quota.mjs';
import { detectWindowsHostEnv } from './wsl_bridge.mjs';

export const ACCOUNT_EXPORT_SCHEMA = 'agy-monitor.account.v1';
export const DEFAULT_RESUME_PROMPT =
  '已切换账号并重启完成，请检查刚才中断前的上下文与本地文件改动状态，直接继续完成剩余任务。';
export const PENDING_RESUME_TTL_MS = 5 * 60 * 1000;
export const PENDING_OAUTH_TTL_MS = 10 * 60 * 1000;
export const AUTO_SWITCH_COOLDOWN_MS = 2 * 60 * 1000;
export const AUTO_SWITCH_CROSS_ACCOUNT_SETTLE_MS = 15 * 1000;
export const QUOTA_ERROR_FRESHNESS_MS = 90 * 1000;
const MAX_HANDLED_QUOTA_ERRORS = 40;
const MAX_BACKUPS_RETAINED = 10;
const MAX_IMPORT_CHARS = 1024 * 1024;
const MAX_IMPORT_BATCH = 50;
const MAX_REMARK_CHARS = 120;

const VALID_AUTO_SWITCH_TARGETS = new Set(['gemini', 'gpt_claude', 'argon']);
const VALID_SORT_BY = new Set(['email', 'gemini', 'gpt_claude', 'argon', 'lastUsed']);
const VALID_SORT_ORDER = new Set(['asc', 'desc']);

export const DEFAULT_ACCOUNT_SETTINGS = Object.freeze({
  quotaRefreshIntervalMin: 5,
  autoSwitchTarget: 'gemini',
  autoSwitchEnabled: false,
  sortBy: 'lastUsed',
  sortOrder: 'desc',
});

export const ANTIGRAVITY_OAUTH_SCOPES = Object.freeze([
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs',
]);

let cachedLocalOAuthClient = null;

function extractPersonalClientIdFromText(text) {
  const s = String(text || '');
  const m = s.match(
    /Personal accounts[\s\S]{0,260}?clientId:\s*['"]([0-9]{10,16}-[A-Za-z0-9_-]{16,48}\.apps\.googleusercontent\.com)['"]/,
  );
  return m ? m[1].trim() : '';
}

function uniqueStrings(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

function readRawFileSyncWithoutAsar(filePath, maxBytes) {
  const hadNoAsar = Object.prototype.hasOwnProperty.call(process, 'noAsar');
  const prevNoAsar = process.noAsar;
  try {
    // Electron's patched node:fs treats `.asar` archives as virtual directories
    // (`statSync(asar).isFile() === false`), which breaks raw scanning inside
    // Antigravity's sidecar runtime unless `process.noAsar` is temporarily enabled.
    process.noAsar = true;
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > maxBytes) return null;
    return fs.readFileSync(filePath);
  } catch {
    return null;
  } finally {
    if (hadNoAsar) process.noAsar = prevNoAsar;
    else delete process.noAsar;
  }
}

/**
 * Discover Antigravity's desktop OAuth client dynamically from environment variables
 * or the locally installed Antigravity binaries (zero hardcoded client secrets in repo).
 */
export async function discoverLocalOAuthClient({
  env = process.env,
  exePath = '',
  forceRefresh = false,
} = {}) {
  const envId = typeof env?.ANTIGRAVITY_OAUTH_CLIENT_ID === 'string' ? env.ANTIGRAVITY_OAUTH_CLIENT_ID.trim() : '';
  const envSecret =
    typeof env?.ANTIGRAVITY_OAUTH_CLIENT_SECRET === 'string' ? env.ANTIGRAVITY_OAUTH_CLIENT_SECRET.trim() : '';
  if (envId && envSecret) {
    return {
      clientId: envId,
      clientSecret: envSecret,
      candidateClientIds: [envId],
      candidateSecrets: [envSecret],
      source: 'env',
    };
  }

  if (!forceRefresh && cachedLocalOAuthClient) {
    return cachedLocalOAuthClient;
  }

  let resolvedExe = exePath || '';
  if (!resolvedExe) {
    try {
      resolvedExe = (await Promise.resolve(findAntigravityExePath())) || '';
    } catch {
      resolvedExe = '';
    }
  }
  const roots = [];
  if (resolvedExe) {
    const exeDir = path.dirname(resolvedExe);
    roots.push(exeDir, path.join(exeDir, 'resources'), path.join(exeDir, '..', 'Resources'));
  }
  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    roots.push(
      path.join(localAppData, 'Programs', 'antigravity', 'resources'),
      path.join(localAppData, 'Programs', 'Antigravity', 'resources'),
    );
  } else if (process.platform === 'darwin') {
    roots.push(
      '/Applications/Antigravity.app/Contents/Resources',
      path.join(os.homedir(), 'Applications', 'Antigravity.app', 'Contents', 'Resources'),
    );
  } else {
    roots.push('/opt/Antigravity/resources', '/usr/share/antigravity/resources');
  }

  const uniqueRoots = uniqueStrings(roots.map((r) => path.resolve(r)));
  let personalId = '';
  for (const root of uniqueRoots) {
    for (const rel of ['app.asar', path.join('app', 'out', 'main.js')]) {
      const p = path.join(root, rel);
      const buf = readRawFileSyncWithoutAsar(p, 160 * 1024 * 1024);
      if (!buf) continue;
      const hit = extractPersonalClientIdFromText(buf.toString('latin1'));
      if (hit) {
        personalId = hit;
        break;
      }
    }
    if (personalId) break;
  }

  const lsCandidates = [
    path.join('bin', 'language_server.exe'),
    path.join('bin', 'language_server_windows_x64.exe'),
    path.join('bin', 'language_server_macos_arm'),
    path.join('bin', 'language_server_macos_x64'),
    path.join('bin', 'language_server_macos'),
    path.join('bin', 'language_server_linux_x64'),
    path.join('bin', 'language_server'),
    path.join('app', 'extensions', 'antigravity', 'bin', 'language_server_windows_x64.exe'),
    path.join('app', 'extensions', 'antigravity', 'bin', 'language_server_macos_arm'),
    path.join('app', 'extensions', 'antigravity', 'bin', 'language_server_macos_x64'),
  ];

  const idRe = /[0-9]{10,16}-[A-Za-z0-9_-]{16,48}\.apps\.googleusercontent\.com/g;
  const secRe = /GOCSPX-[A-Za-z0-9_-]{28}/g;

  for (const root of uniqueRoots) {
    for (const rel of lsCandidates) {
      const p = path.join(root, rel);
      const buf = readRawFileSyncWithoutAsar(p, 260 * 1024 * 1024);
      if (!buf) continue;
      const txt = buf.toString('latin1');
      const ids = uniqueStrings(txt.match(idRe) || []);
      const secrets = uniqueStrings(txt.match(secRe) || []);
      if (ids.length === 0 || secrets.length === 0) continue;

      const chosenId = (personalId && ids.includes(personalId) ? personalId : '') || personalId || ids[0];
      const candidateClientIds = uniqueStrings([chosenId, ...ids]);
      const idx = ids.indexOf(chosenId);
      const primarySecret = (idx >= 0 && secrets[idx]) || secrets[0];
      const candidateSecrets = uniqueStrings([primarySecret, ...secrets]);

      cachedLocalOAuthClient = {
        clientId: chosenId,
        clientSecret: primarySecret,
        candidateClientIds,
        candidateSecrets,
        source: 'local_binary',
      };
      return cachedLocalOAuthClient;
    }
  }

  return null;
}

export function clearDiscoveredOAuthClientCache() {
  cachedLocalOAuthClient = null;
}

export function generatePkce() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function buildAuthorizationUrl({ clientId, redirectUri, state, codeChallenge }) {
  const cid = String(clientId || '').trim();
  if (!cid) throw new TypeError('clientId is required');
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.searchParams.set('client_id', cid);
  u.searchParams.set('redirect_uri', String(redirectUri || '').trim());
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', ANTIGRAVITY_OAUTH_SCOPES.join(' '));
  u.searchParams.set('access_type', 'offline');
  u.searchParams.set('prompt', 'select_account consent');
  u.searchParams.set('state', String(state || '').trim());
  u.searchParams.set('code_challenge', String(codeChallenge || '').trim());
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

export function parseWindowsProxyServer(rawProxyServer, targetProtocol = 'https:') {
  const raw = String(rawProxyServer || '').trim();
  if (!raw) return null;

  const isHttps = String(targetProtocol || 'https:').toLowerCase() === 'https:';
  let chosen = '';
  let forceSocks5 = false;

  if (raw.includes('=')) {
    const map = new Map();
    for (const part of raw.split(';')) {
      const idx = part.indexOf('=');
      if (idx <= 0) continue;
      const k = part.slice(0, idx).trim().toLowerCase();
      const v = part.slice(idx + 1).trim();
      if (k && v) map.set(k, v);
    }
    const order = isHttps
      ? ['https', 'http', 'socks5', 'socks', 'socks4']
      : ['http', 'https', 'socks5', 'socks', 'socks4'];
    for (const key of order) {
      if (map.has(key)) {
        chosen = map.get(key);
        if (key.startsWith('socks')) forceSocks5 = true;
        break;
      }
    }
  } else {
    chosen = raw;
  }

  if (!chosen) return null;
  let candidate = chosen;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    candidate = `${forceSocks5 ? 'socks5' : 'http'}://${candidate}`;
  }
  try {
    const parsed = new URL(candidate);
    if (!parsed.hostname) return null;
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

export function shouldBypassProxy(hostname, rawList = '') {
  const host = String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  if (!host) return true;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.startsWith('127.')) {
    return true;
  }
  const entries = String(rawList || '')
    .split(/[,;]/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  for (const rawEntry of entries) {
    if (rawEntry === '*') return true;
    if (rawEntry === '<local>') {
      if (!host.includes('.')) return true;
      continue;
    }
    const pattern = rawEntry.replace(/:\d+$/, '');
    if (!pattern) continue;
    if (pattern.includes('*')) {
      const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      if (new RegExp(`^${escaped}$`, 'i').test(host)) return true;
      continue;
    }
    if (pattern.startsWith('.')) {
      if (host === pattern.slice(1) || host.endsWith(pattern)) return true;
    } else if (host === pattern || host.endsWith(`.${pattern}`)) {
      return true;
    }
  }
  return false;
}

export function readWindowsSystemProxy() {
  if (process.platform !== 'win32') return Promise.resolve(null);
  return new Promise((resolve) => {
    execFile(
      'reg.exe',
      ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'],
      { windowsHide: true, timeout: 2500 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve(null);
          return;
        }
        const text = String(stdout);
        const enableMatch = text.match(/^\s*ProxyEnable\s+REG_DWORD\s+(0x[0-9a-f]+|\d+)/im);
        const serverMatch = text.match(/^\s*ProxyServer\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$/im);
        const overrideMatch = text.match(/^\s*ProxyOverride\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$/im);
        const enabled = enableMatch ? Number(enableMatch[1]) === 1 : false;
        resolve({
          enabled,
          proxyServer: serverMatch ? serverMatch[1].trim() : '',
          proxyOverride: overrideMatch ? overrideMatch[1].trim() : '',
        });
      },
    );
  });
}

export async function resolveSystemProxyUrl(
  targetUrl,
  { env = process.env, platform = process.platform, readWindowsProxy = readWindowsSystemProxy } = {},
) {
  let target;
  try {
    target = new URL(targetUrl);
  } catch {
    return null;
  }

  const noProxy = env.NO_PROXY || env.no_proxy || '';
  if (shouldBypassProxy(target.hostname, noProxy)) {
    return null;
  }

  const isHttps = target.protocol === 'https:';
  const envKeys = isHttps
    ? ['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy']
    : ['HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy'];

  for (const key of envKeys) {
    const val = String(env[key] || '').trim();
    if (!val) continue;
    const normalized = parseWindowsProxyServer(val, target.protocol);
    if (normalized) return normalized;
  }

  if (platform === 'win32' && typeof readWindowsProxy === 'function') {
    const winProxy = await readWindowsProxy().catch(() => null);
    if (winProxy?.enabled && winProxy.proxyServer) {
      if (shouldBypassProxy(target.hostname, winProxy.proxyOverride || '')) {
        return null;
      }
      return parseWindowsProxyServer(winProxy.proxyServer, target.protocol);
    }
  }

  return null;
}

function openHttpConnectTunnel(proxyUrlStr, targetHost, targetPort, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const proxy = new URL(proxyUrlStr);
    const isHttpsProxy = proxy.protocol === 'https:';
    const mod = isHttpsProxy ? https : http;
    const headers = { Host: `${targetHost}:${targetPort}` };
    if (proxy.username || proxy.password) {
      const auth = Buffer.from(
        `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`,
      ).toString('base64');
      headers['Proxy-Authorization'] = `Basic ${auth}`;
    }

    let settled = false;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(val);
    };

    const req = mod.request({
      host: proxy.hostname,
      port: Number(proxy.port) || (isHttpsProxy ? 443 : 80),
      method: 'CONNECT',
      path: `${targetHost}:${targetPort}`,
      headers,
    });

    const timer = setTimeout(() => {
      req.destroy();
      const err = new Error(`代理连接超时 (${timeoutMs}ms)`);
      err.code = 'ETIMEDOUT';
      done(err);
    }, timeoutMs);

    req.on('connect', (res, socket, head) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        const err = new Error(`代理 CONNECT 隧道失败 (HTTP ${res.statusCode})`);
        err.code = 'EPROXYCONNECT';
        done(err);
        return;
      }
      if (head && head.length > 0) {
        socket.unshift(head);
      }
      done(null, socket);
    });

    req.on('error', (err) => done(err));
    req.end();
  });
}

function openSocks5Tunnel(proxyUrlStr, targetHost, targetPort, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const proxy = new URL(proxyUrlStr);
    const socket = net.createConnection({
      host: proxy.hostname,
      port: Number(proxy.port) || 1080,
    });

    let settled = false;
    let buf = Buffer.alloc(0);
    let waiter = null;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };

    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(err);
    };

    const onData = (chunk) => {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      if (waiter && buf.length >= waiter.n) {
        const w = waiter;
        waiter = null;
        const out = buf.subarray(0, w.n);
        buf = buf.subarray(w.n);
        w.resolve(out);
      }
    };

    const onError = (err) => fail(err);
    const onClose = () => fail(new Error('SOCKS5 代理连接意外中断'));

    const readExact = (n) => {
      if (buf.length >= n) {
        const out = buf.subarray(0, n);
        buf = buf.subarray(n);
        return Promise.resolve(out);
      }
      return new Promise((res) => {
        waiter = { n, resolve: res };
      });
    };

    const timer = setTimeout(() => {
      const err = new Error(`SOCKS5 代理连接超时 (${timeoutMs}ms)`);
      err.code = 'ETIMEDOUT';
      fail(err);
    }, timeoutMs);

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);

    socket.once('connect', async () => {
      try {
        const hasAuth = Boolean(proxy.username || proxy.password);
        socket.write(
          hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]),
        );
        const greet = await readExact(2);
        if (greet[0] !== 0x05) throw new Error('无效的 SOCKS5 协议响应');
        if (greet[1] === 0x02 && hasAuth) {
          const uBuf = Buffer.from(decodeURIComponent(proxy.username), 'utf8');
          const pBuf = Buffer.from(decodeURIComponent(proxy.password), 'utf8');
          socket.write(Buffer.concat([Buffer.from([0x01, uBuf.length]), uBuf, Buffer.from([pBuf.length]), pBuf]));
          const authRep = await readExact(2);
          if (authRep[1] !== 0x00) throw new Error('SOCKS5 代理账号密码认证失败');
        } else if (greet[1] !== 0x00) {
          throw new Error(`SOCKS5 代理要求不支持的认证方式 (${greet[1]})`);
        }

        const hostBuf = Buffer.from(targetHost, 'utf8');
        if (hostBuf.length > 255) throw new Error('目标主机名过长');
        const reqPacket = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
        ]);
        socket.write(reqPacket);

        const repHead = await readExact(4);
        if (repHead[0] !== 0x05 || repHead[1] !== 0x00) {
          throw new Error(`SOCKS5 CONNECT 失败 (code ${repHead[1]})`);
        }
        const atyp = repHead[3];
        if (atyp === 0x01) {
          await readExact(6);
        } else if (atyp === 0x03) {
          const lenBuf = await readExact(1);
          await readExact(lenBuf[0] + 2);
        } else if (atyp === 0x04) {
          await readExact(18);
        } else {
          throw new Error(`未知 SOCKS5 地址类型 (${atyp})`);
        }

        if (settled) return;
        settled = true;
        cleanup();
        if (buf.length > 0) {
          socket.unshift(buf);
        }
        resolve(socket);
      } catch (err) {
        fail(err);
      }
    });
  });
}

class SingleSocketHttpsAgent extends https.Agent {
  constructor(tunnelSocket, tlsOptions = {}) {
    super({ keepAlive: false });
    this._tunnelSocket = tunnelSocket;
    this._tlsOptions = tlsOptions;
  }

  createConnection(options, cb) {
    const tlsSocket = tls.connect({
      ...options,
      socket: this._tunnelSocket,
      servername: options.servername || options.host,
      ...this._tlsOptions,
    });
    if (typeof cb === 'function') cb(null, tlsSocket);
    return tlsSocket;
  }
}

class SingleSocketHttpAgent extends http.Agent {
  constructor(tunnelSocket) {
    super({ keepAlive: false });
    this._tunnelSocket = tunnelSocket;
  }

  createConnection(_options, cb) {
    if (typeof cb === 'function') cb(null, this._tunnelSocket);
    return this._tunnelSocket;
  }
}

export async function requestOverProxy(targetUrl, options = {}, proxyUrlStr, timeoutMs = 15000) {
  const target = new URL(targetUrl);
  const proxy = new URL(proxyUrlStr);
  const method = String(options.method || 'GET').toUpperCase();
  const headers = { 'accept-encoding': 'identity', connection: 'close' };
  if (options.headers && typeof options.headers === 'object') {
    for (const [k, v] of Object.entries(options.headers)) {
      if (v !== undefined && v !== null) headers[k.toLowerCase()] = String(v);
    }
  }
  const bodyBuf =
    options.body === undefined || options.body === null
      ? null
      : Buffer.isBuffer(options.body)
        ? options.body
        : Buffer.from(String(options.body), 'utf8');
  if (bodyBuf && !headers['content-length']) {
    headers['content-length'] = String(bodyBuf.length);
  }

  const isHttpsTarget = target.protocol === 'https:';
  const targetPort = Number(target.port) || (isHttpsTarget ? 443 : 80);
  const isSocksProxy = proxy.protocol.startsWith('socks');

  let tunnelSocket = null;
  if (isHttpsTarget || isSocksProxy) {
    tunnelSocket = isSocksProxy
      ? await openSocks5Tunnel(proxyUrlStr, target.hostname, targetPort, timeoutMs)
      : await openHttpConnectTunnel(proxyUrlStr, target.hostname, targetPort, timeoutMs);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let activeReq = null;
    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        try {
          activeReq?.destroy();
        } catch {}
        try {
          tunnelSocket?.destroy();
        } catch {}
        reject(err);
      } else {
        resolve(val);
      }
    };

    const timer = setTimeout(() => {
      const err = new Error(`通过代理请求超时 (${timeoutMs}ms)`);
      err.code = 'ETIMEDOUT';
      finish(err);
    }, timeoutMs);

    const onResponse = (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        const status = Number(res.statusCode || 0);
        finish(null, {
          ok: status >= 200 && status < 300,
          status,
          statusText: res.statusMessage || '',
          headers: res.headers || {},
          text: async () => text,
          json: async () => JSON.parse(text),
        });
      });
      res.on('error', (err) => finish(err));
    };

    try {
      if (isHttpsTarget) {
        const agent = new SingleSocketHttpsAgent(tunnelSocket, options.tlsOptions || {});
        activeReq = https.request(
          {
            host: target.hostname,
            port: targetPort,
            path: `${target.pathname}${target.search}`,
            method,
            headers,
            agent,
          },
          onResponse,
        );
      } else if (isSocksProxy) {
        const agent = new SingleSocketHttpAgent(tunnelSocket);
        activeReq = http.request(
          {
            host: target.hostname,
            port: targetPort,
            path: `${target.pathname}${target.search}`,
            method,
            headers,
            agent,
          },
          onResponse,
        );
      } else {
        const proxyHeaders = { ...headers, host: target.host };
        if (proxy.username || proxy.password) {
          const auth = Buffer.from(
            `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`,
          ).toString('base64');
          proxyHeaders['proxy-authorization'] = `Basic ${auth}`;
        }
        activeReq = http.request(
          {
            host: proxy.hostname,
            port: Number(proxy.port) || 80,
            path: target.toString(),
            method,
            headers: proxyHeaders,
            agent: false,
          },
          onResponse,
        );
      }

      activeReq.on('error', (err) => finish(err));
      if (bodyBuf) activeReq.write(bodyBuf);
      activeReq.end();
    } catch (err) {
      finish(err);
    }
  });
}

function formatSafeProxyLabel(proxyUrlStr) {
  try {
    const u = new URL(proxyUrlStr);
    return `${u.protocol}//${u.host}`;
  } catch {
    return String(proxyUrlStr || '');
  }
}

export async function proxyAwareFetch(targetUrl, options = {}, deps = {}) {
  const timeoutMs = Math.max(2000, Number(options.timeoutMs) || 15000);
  const directFetch = deps.fetch || fetch;
  const proxyUrl = await resolveSystemProxyUrl(targetUrl, deps);

  if (proxyUrl) {
    try {
      return await requestOverProxy(targetUrl, options, proxyUrl, timeoutMs);
    } catch (proxyErr) {
      const code = proxyErr?.code || '';
      const isProxyDown = code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH';
      if (isProxyDown) {
        try {
          return await directFetch(targetUrl, {
            ...options,
            signal: options.signal || AbortSignal.timeout(timeoutMs),
          });
        } catch {
          // Fall through to report the proxy error clearly
        }
      }
      const proxyLabel = formatSafeProxyLabel(proxyUrl);
      const detail = proxyErr?.cause?.message || proxyErr?.message || String(proxyErr);
      throw new Error(`通过系统代理 (${proxyLabel}) 访问 Google 服务失败：${detail}`);
    }
  }

  try {
    return await directFetch(targetUrl, {
      ...options,
      signal: options.signal || AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const detail = err?.cause?.message || err?.cause?.code || err?.message || '网络连接失败';
    throw new Error(`连接 Google 服务失败（未检测到系统代理，请检查代理软件是否开启）：${detail}`);
  }
}

export async function exchangeOAuthCode(
  { code, codeVerifier, redirectUri, clientId, clientSecret, candidateSecrets = [] },
  fetchImpl = proxyAwareFetch,
) {
  let cid = String(clientId || '').trim();
  let secretsToTry = uniqueStrings([String(clientSecret || '').trim(), ...candidateSecrets]);
  if (!cid || secretsToTry.length === 0) {
    const discovered = await discoverLocalOAuthClient();
    if (!discovered) {
      throw new Error(
        '未能从本机 Antigravity 客户端读取 OAuth 配置，请确认已安装 Antigravity 或配置 ANTIGRAVITY_OAUTH_CLIENT_ID / ANTIGRAVITY_OAUTH_CLIENT_SECRET',
      );
    }
    cid = cid || discovered.clientId;
    if (secretsToTry.length === 0) secretsToTry = discovered.candidateSecrets;
  }

  let lastErr = null;
  for (const secret of secretsToTry) {
    const res = await fetchImpl('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: cid,
        client_secret: secret,
        code: String(code || '').trim(),
        code_verifier: String(codeVerifier || '').trim(),
        grant_type: 'authorization_code',
        redirect_uri: String(redirectUri || '').trim(),
      }).toString(),
    });
    if (res.ok) {
      if (cachedLocalOAuthClient && cachedLocalOAuthClient.clientId === cid) {
        cachedLocalOAuthClient = { ...cachedLocalOAuthClient, clientSecret: secret };
      }
      return await res.json();
    }
    const errText = await res.text().catch(() => '');
    lastErr = new Error(`Google OAuth Token 换取失败 (HTTP ${res.status}): ${errText}`);
    if (res.status === 401 && /invalid_client|unauthorized_client/i.test(errText)) {
      continue;
    }
    throw lastErr;
  }
  throw lastErr || new Error('Google OAuth Token 换取失败');
}

export async function fetchGoogleProfile(accessToken, fetchImpl = proxyAwareFetch) {
  try {
    const res = await fetchImpl('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { authorization: `Bearer ${String(accessToken || '').trim()}` },
    });
    if (!res.ok) return null;
    return await res.json().catch(() => null);
  } catch {
    return null;
  }
}

const CLOUD_CODE_DAILY_BASE_URL = 'https://daily-cloudcode-pa.googleapis.com';
const CLOUD_CODE_PROD_BASE_URL = 'https://cloudcode-pa.googleapis.com';
const CLOUD_CODE_IDE_VERSION = '2.25.0';
const CLOUD_CODE_LOAD_UA = `antigravity/${CLOUD_CODE_IDE_VERSION} windows/amd64 google-api-nodejs-client/10.3.0`;
const CLOUD_CODE_QUOTA_UA = `antigravity/${CLOUD_CODE_IDE_VERSION} (aidev_client; os_type=windows; arch=amd64; cl=1003475615)`;
const CLOUD_CODE_X_GOOG_API_CLIENT = 'gl-node/22.21.1';
const OAUTH_REFRESH_SAFETY_MS = 60_000;

function validCloudCodeProjectId(raw) {
  const s = typeof raw === 'string' ? raw.trim() : '';
  return s && s !== 'aicode-consumers' ? s : '';
}

function extractCloudCodeProjectId(val) {
  if (!val) return '';
  if (typeof val === 'string') return validCloudCodeProjectId(val);
  if (typeof val === 'object') {
    for (const key of ['cloudaicompanionProject', 'projectId', 'project', 'id', 'value']) {
      if (val[key] !== undefined && val[key] !== null) {
        const hit = extractCloudCodeProjectId(val[key]);
        if (hit) return hit;
      }
    }
  }
  return '';
}

function parseGoogleCloudCodeError(status, rawText = '') {
  let message = String(rawText || '').trim() || `HTTP ${status}`;
  let reason = '';
  let validationUrl = '';
  try {
    const parsed = JSON.parse(rawText);
    const errObj = parsed?.error && typeof parsed.error === 'object' ? parsed.error : null;
    if (errObj?.message) message = String(errObj.message);
    const details = Array.isArray(errObj?.details) ? errObj.details : [];
    for (const d of details) {
      if (!reason && typeof d?.reason === 'string') reason = d.reason;
      if (!validationUrl && typeof d?.metadata?.validation_url === 'string') {
        validationUrl = d.metadata.validation_url;
      }
    }
  } catch {
    // non-JSON body
  }
  if (!reason) {
    if (/verify\s+(?:your\s+)?account/i.test(message)) reason = 'VALIDATION_REQUIRED';
    else if (/subscription\s+required/i.test(message)) reason = 'SUBSCRIPTION_REQUIRED';
  }
  const err = new Error(
    reason === 'VALIDATION_REQUIRED' || validationUrl
      ? 'Google 要求验证该账号，请切换登录完成验证后再刷新'
      : reason === 'SUBSCRIPTION_REQUIRED'
        ? '该账号暂无有效 Antigravity 订阅权限'
        : status === 401
          ? '该账号 OAuth 凭据已失效，请重新授权'
          : `Google 配额接口错误 (HTTP ${status}): ${message.slice(0, 180)}`,
  );
  err.status = status;
  err.reason = reason;
  err.validationUrl = validationUrl;
  return err;
}

export async function refreshAccessTokenForCredential(
  credObj,
  { fetchImpl = proxyAwareFetch, nowMs = Date.now(), forceRefresh = false, oauthClient = null } = {},
) {
  if (!credObj || typeof credObj !== 'object') {
    const err = new Error('该账号缺少有效凭据，无法刷新额度');
    err.status = 422;
    throw err;
  }
  const existingToken = credObj.token && typeof credObj.token === 'object' ? credObj.token : {};
  const existingAccess =
    (typeof existingToken.access_token === 'string' && existingToken.access_token.trim()) ||
    (typeof credObj.access_token === 'string' && credObj.access_token.trim()) ||
    '';
  const refreshToken = extractRefreshToken(credObj);
  const expiryRaw = existingToken.expiry || credObj.expiry || '';
  const expiryMs = expiryRaw ? Date.parse(expiryRaw) : Number.NaN;

  if (!forceRefresh && existingAccess && Number.isFinite(expiryMs) && expiryMs - nowMs > OAUTH_REFRESH_SAFETY_MS) {
    return { accessToken: existingAccess, credObj, renewed: false };
  }

  if (!refreshToken) {
    const err = new Error('该账号缺少 refresh_token，请重新通过 OAuth 授权');
    err.status = 401;
    throw err;
  }

  const client = oauthClient || (await discoverLocalOAuthClient());
  if (!client?.clientId || !client?.clientSecret) {
    const err = new Error(
      '未能从本机 Antigravity 客户端读取 OAuth 配置，请确认已安装 Antigravity 或配置 ANTIGRAVITY_OAUTH_CLIENT_ID / ANTIGRAVITY_OAUTH_CLIENT_SECRET',
    );
    err.status = 500;
    throw err;
  }
  const clientIdsToTry = uniqueStrings([client.clientId, ...(client.candidateClientIds || [])]);
  const secretsToTry = uniqueStrings([client.clientSecret, ...(client.candidateSecrets || [])]);

  let payload = null;
  let lastErr = null;
  for (const cid of clientIdsToTry) {
    for (const secret of secretsToTry) {
      const res = await fetchImpl('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: cid,
          client_secret: secret,
          refresh_token: refreshToken,
          grant_type: 'refresh_token',
        }).toString(),
      });

      if (res.ok) {
        if (cachedLocalOAuthClient && cachedLocalOAuthClient.source === 'local_binary') {
          cachedLocalOAuthClient = {
            ...cachedLocalOAuthClient,
            clientId: cid,
            clientSecret: secret,
            candidateClientIds: uniqueStrings([cid, ...(cachedLocalOAuthClient.candidateClientIds || [])]),
            candidateSecrets: uniqueStrings([secret, ...(cachedLocalOAuthClient.candidateSecrets || [])]),
          };
        }
        payload = await res.json();
        break;
      }

      const errText = await res.text().catch(() => '');
      if (res.status === 401 && /invalid_client|unauthorized_client/i.test(errText)) {
        lastErr = new Error(`Google OAuth 客户端校验失败 (HTTP 401): ${errText.slice(0, 120)}`);
        lastErr.status = 401;
        continue;
      }
      const err = new Error(
        res.status === 400 || res.status === 401
          ? '该账号 OAuth 凭据已失效或被撤销，请重新通过 OAuth 授权'
          : `刷新 Google OAuth 令牌失败 (HTTP ${res.status}): ${errText.slice(0, 160)}`,
      );
      err.status = res.status === 400 || res.status === 401 ? 401 : res.status || 502;
      throw err;
    }
    if (payload) break;
  }

  if (!payload) {
    throw lastErr || new Error('刷新 Google OAuth 令牌失败');
  }
  const accessToken = typeof payload?.access_token === 'string' ? payload.access_token.trim() : '';
  if (!accessToken) {
    const err = new Error('Google OAuth 刷新未返回有效的 access_token');
    err.status = 401;
    throw err;
  }

  const expiresIn = Math.max(60, Number(payload.expires_in) || 3600);
  const nextExpiry = new Date(nowMs + expiresIn * 1000).toISOString();
  const nextToken = {
    ...existingToken,
    access_token: accessToken,
    token_type:
      (typeof payload.token_type === 'string' && payload.token_type.trim()) ||
      existingToken.token_type ||
      'Bearer',
    refresh_token:
      (typeof payload.refresh_token === 'string' && payload.refresh_token.trim()) || refreshToken,
    expiry: nextExpiry,
    expires_in: expiresIn,
    ...(typeof payload.id_token === 'string' && payload.id_token.trim()
      ? { id_token: payload.id_token.trim() }
      : {}),
  };

  const updatedCredObj = {
    ...credObj,
    token: nextToken,
    auth_method:
      (typeof credObj.auth_method === 'string' && credObj.auth_method.trim()) || 'consumer',
  };

  return { accessToken, credObj: updatedCredObj, renewed: true };
}

export function buildQuotaFromAvailableModels(modelsResponse, nowMs = Date.now()) {
  const models = modelsResponse?.models && typeof modelsResponse.models === 'object'
    ? modelsResponse.models
    : {};
  const groupBuckets = new Map();
  const groupMeta = {
    gemini: { key: 'gemini', label: 'Gemini', displayName: 'Gemini Models', order: 0 },
    gpt_claude: { key: 'gpt_claude', label: 'GPT&Claude', displayName: 'GPT & Claude', order: 1 },
    argon: { key: 'argon', label: 'Argon', displayName: 'Argon', order: 2 },
  };

  for (const [modelId, info] of Object.entries(models)) {
    const qi = info?.quotaInfo;
    if (!qi || typeof qi !== 'object') continue;
    const rawFrac = qi.remainingFraction;
    if (rawFrac === null || rawFrac === undefined || rawFrac === '') continue;
    const fracNum = Number(rawFrac);
    if (!Number.isFinite(fracNum)) continue;
    const frac = Math.max(0, Math.min(1, fracNum));
    const groupKey = mapModelToQuotaGroup(modelId);
    if (!groupKey || !groupMeta[groupKey]) continue;

    const resetTime = typeof qi.resetTime === 'string' ? qi.resetTime.trim() : '';
    const parsedReset = resetTime ? Date.parse(resetTime) : Number.NaN;
    const resetTimeMs = Number.isFinite(parsedReset) ? parsedReset : null;

    const cur = groupBuckets.get(groupKey);
    if (!cur || frac < cur.remainingFraction) {
      groupBuckets.set(groupKey, {
        remainingFraction: frac,
        resetTime,
        resetTimeMs,
      });
    } else if (cur && frac === cur.remainingFraction && resetTimeMs && (!cur.resetTimeMs || resetTimeMs < cur.resetTimeMs)) {
      cur.resetTime = resetTime;
      cur.resetTimeMs = resetTimeMs;
    }
  }

  if (groupBuckets.size === 0) return null;

  const groups = ['gemini', 'gpt_claude', 'argon']
    .filter((k) => groupBuckets.has(k))
    .map((k) => {
      const m = groupMeta[k];
      const b = groupBuckets.get(k);
      const remainingPct = Math.round(b.remainingFraction * 100);
      const remainingPctExact = Math.round(b.remainingFraction * 1000) / 10;
      const isFull = b.remainingFraction >= 0.99999;
      return {
        key: m.key,
        label: m.label,
        displayName: m.displayName,
        fiveHour: {
          bucketId: `${m.key}-5h`,
          window: '5h',
          remainingFraction: b.remainingFraction,
          remainingPct,
          remainingPctExact,
          resetTime: b.resetTime,
          resetTimeMs: b.resetTimeMs,
          isFull,
          disabled: false,
        },
        weekly: null,
      };
    });

  return {
    ok: true,
    available: true,
    fetchedAtMs: nowMs,
    groups,
  };
}

function hasUsableQuotaGroups(summary) {
  if (!summary || !Array.isArray(summary.groups) || summary.groups.length === 0) return false;
  return summary.groups.some((g) => {
    const f5 = g?.fiveHour?.remainingFraction;
    const fw = g?.weekly?.remainingFraction;
    return (f5 !== null && f5 !== undefined) || (fw !== null && fw !== undefined);
  });
}

async function resolveCloudCodeProject(accessToken, cachedProjectId, fetchImpl) {
  const validCached = validCloudCodeProjectId(cachedProjectId);
  const metadata = {
    ideName: 'antigravity',
    ideType: 'ANTIGRAVITY',
    ideVersion: CLOUD_CODE_IDE_VERSION,
    platform: 'WINDOWS_AMD64',
    updateChannel: 'stable',
    pluginType: 'GEMINI',
    ...(validCached ? { duetProject: validCached } : {}),
  };
  const body = {
    metadata,
    mode: 'FULL_ELIGIBILITY_CHECK',
    ...(validCached ? { cloudaicompanionProject: validCached } : {}),
  };

  let projectId = validCached;
  let subscriptionTier = '';
  let allowedTiers = [];

  const res = await fetchImpl(`${CLOUD_CODE_DAILY_BASE_URL}/v1internal:loadCodeAssist`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      'user-agent': CLOUD_CODE_LOAD_UA,
      'x-goog-api-client': CLOUD_CODE_X_GOOG_API_CLIENT,
      accept: '*/*',
    },
    body: JSON.stringify(body),
  });

  if (res.status === 401) {
    const err = new Error('loadCodeAssist 401 Unauthorized');
    err.status = 401;
    throw err;
  }

  if (res.ok) {
    const data = await res.json().catch(() => null);
    if (data && typeof data === 'object') {
      const fromResp = extractCloudCodeProjectId(data.cloudaicompanionProject);
      if (fromResp) projectId = fromResp;
      subscriptionTier =
        (typeof data?.paidTier?.id === 'string' && data.paidTier.id.trim()) ||
        (typeof data?.currentTier?.id === 'string' && data.currentTier.id.trim()) ||
        '';
      if (Array.isArray(data.allowedTiers)) allowedTiers = data.allowedTiers;
    }
  }

  if (!projectId && allowedTiers.length > 0) {
    const tierId =
      allowedTiers.find((t) => t?.isDefault === true && t?.id)?.id ||
      allowedTiers.find((t) => t?.id)?.id ||
      subscriptionTier ||
      'free-tier';
    try {
      const obRes = await fetchImpl(`${CLOUD_CODE_DAILY_BASE_URL}/v1internal:onboardUser`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessToken}`,
          'content-type': 'application/json',
          'user-agent': CLOUD_CODE_LOAD_UA,
          'x-goog-api-client': CLOUD_CODE_X_GOOG_API_CLIENT,
          accept: '*/*',
        },
        body: JSON.stringify({
          tierId,
          metadata,
        }),
      });
      if (obRes.ok) {
        const obData = await obRes.json().catch(() => null);
        const obProj = extractCloudCodeProjectId(obData?.response?.cloudaicompanionProject || obData);
        if (obProj) projectId = obProj;
      }
    } catch {
      // Non-fatal; quota endpoint can still work without onboarded project
    }
  }

  return { projectId, subscriptionTier };
}

/**
 * Fetch real-time 3-category (Gemini / GPT&Claude / Argon) 5h + weekly quota
 * for ANY stored account directly via Google's official CloudCode endpoints
 * (aligned with Cockpit Tools `quota.rs` and Antigravity Hub).
 */
export async function fetchCloudCodeQuotaForCredential(
  credObj,
  { cachedProjectId = '', fetchImpl = proxyAwareFetch, nowMs = Date.now(), oauthClient = null } = {},
) {
  let tokenState = await refreshAccessTokenForCredential(credObj, {
    fetchImpl,
    nowMs,
    forceRefresh: false,
    oauthClient,
  });

  const runWithToken = async (accessToken) => {
    const { projectId, subscriptionTier } = await resolveCloudCodeProject(
      accessToken,
      cachedProjectId,
      fetchImpl,
    );
    const reqBody = JSON.stringify(projectId ? { project: projectId } : {});
    const reqHeaders = {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      'user-agent': CLOUD_CODE_QUOTA_UA,
      accept: '*/*',
    };

    let lastDenialError = null;
    let lastHttpError = null;

    // 1. Primary: v1internal:retrieveUserQuotaSummary (provides exact 5h + weekly buckets)
    for (const baseUrl of [CLOUD_CODE_DAILY_BASE_URL, CLOUD_CODE_PROD_BASE_URL]) {
      try {
        const res = await fetchImpl(`${baseUrl}/v1internal:retrieveUserQuotaSummary`, {
          method: 'POST',
          headers: reqHeaders,
          body: reqBody,
        });
        if (res.status === 401) {
          const err = new Error('retrieveUserQuotaSummary 401');
          err.status = 401;
          throw err;
        }
        if (res.ok) {
          const raw = await res.json().catch(() => null);
          if (raw && typeof raw === 'object') {
            const normalized = normalizeQuotaSummary(raw, nowMs);
            if (hasUsableQuotaGroups(normalized)) {
              return {
                quota: normalizeStoredQuota(normalized, nowMs),
                projectId,
                subscriptionTier,
                source: 'retrieveUserQuotaSummary',
              };
            }
          }
        } else {
          const errText = await res.text().catch(() => '');
          const parsedErr = parseGoogleCloudCodeError(res.status, errText);
          if (parsedErr.reason === 'VALIDATION_REQUIRED' || parsedErr.validationUrl) {
            lastDenialError = parsedErr;
            break;
          }
          lastHttpError = parsedErr;
        }
      } catch (err) {
        if (err?.status === 401) throw err;
        lastHttpError = err;
      }
    }

    if (lastDenialError) throw lastDenialError;

    // 2. Fallback: v1internal:fetchAvailableModels (per-model quotaInfo collapsed into 3 groups)
    for (const baseUrl of [CLOUD_CODE_DAILY_BASE_URL, CLOUD_CODE_PROD_BASE_URL]) {
      try {
        const res = await fetchImpl(`${baseUrl}/v1internal:fetchAvailableModels`, {
          method: 'POST',
          headers: reqHeaders,
          body: reqBody,
        });
        if (res.status === 401) {
          const err = new Error('fetchAvailableModels 401');
          err.status = 401;
          throw err;
        }
        if (res.ok) {
          const raw = await res.json().catch(() => null);
          const built = buildQuotaFromAvailableModels(raw, nowMs);
          if (built && hasUsableQuotaGroups(built)) {
            return {
              quota: normalizeStoredQuota(built, nowMs),
              projectId,
              subscriptionTier,
              source: 'fetchAvailableModels',
            };
          }
        } else {
          const errText = await res.text().catch(() => '');
          const parsedErr = parseGoogleCloudCodeError(res.status, errText);
          if (
            parsedErr.reason === 'VALIDATION_REQUIRED' ||
            parsedErr.reason === 'SUBSCRIPTION_REQUIRED' ||
            parsedErr.validationUrl
          ) {
            throw parsedErr;
          }
          lastHttpError = parsedErr;
        }
      } catch (err) {
        if (err?.status === 401 || err?.reason) throw err;
        lastHttpError = err;
      }
    }

    throw lastHttpError || new Error('Google 配额接口未返回有效的模型额度数据');
  };

  try {
    const fetched = await runWithToken(tokenState.accessToken);
    return {
      ok: true,
      ...fetched,
      updatedCredObj: tokenState.credObj,
      renewed: tokenState.renewed,
    };
  } catch (err) {
    if (err?.status === 401 && !tokenState.renewed) {
      tokenState = await refreshAccessTokenForCredential(credObj, {
        fetchImpl,
        nowMs,
        forceRefresh: true,
        oauthClient,
      });
      const fetched = await runWithToken(tokenState.accessToken);
      return {
        ok: true,
        ...fetched,
        updatedCredObj: tokenState.credObj,
        renewed: true,
      };
    }
    throw err;
  }
}

export function openExternalUrl(rawUrl) {
  const url = String(rawUrl || '').trim();
  if (!url || (!url.startsWith('https://') && !url.startsWith('http://'))) {
    return false;
  }
  try {
    if (process.platform === 'win32') {
      const child = spawn(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', 'Start-Process $env:TARGET_URL'],
        {
          env: { ...process.env, TARGET_URL: url },
          stdio: 'ignore',
          windowsHide: true,
        },
      );
      child.unref();
      return true;
    }
    const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
    const child = spawn(cmd, [url], { stdio: 'ignore' });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

function escapeHtmlText(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderOauthSuccessHtml(email = '') {
  const safeEmail = escapeHtmlText(email);
  const accountLine = safeEmail
    ? `<p class="email">${safeEmail}</p>`
    : '';
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Antigravity 账号授权成功</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0d1117;
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 36px 32px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 12px 32px rgba(0,0,0,0.5);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 14px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
      background: rgba(46, 160, 67, 0.18);
      color: #3fb950;
      border: 1px solid rgba(63, 185, 80, 0.4);
      margin-bottom: 18px;
    }
    h2 {
      margin: 0 0 10px;
      font-size: 20px;
      color: #58a6ff;
    }
    .email {
      margin: 0 0 14px;
      font-size: 14px;
      font-weight: 600;
      color: #e6edf3;
    }
    p {
      margin: 0 0 20px;
      font-size: 14px;
      line-height: 1.6;
      color: #8b949e;
    }
    .tip {
      font-size: 12px;
      color: #7d8590;
      background: #21262d;
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px dashed #30363d;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✓ 官方授权并入库成功</div>
    <h2>Google 账号已加密收录</h2>
    ${accountLine}
    <p>凭据已通过官方接口换取并由 Windows DPAPI 硬件级加密写入 Antigravity 保险库。<br>当前正在运行的会话不受任何影响。</p>
    <div class="tip">您现在可以安全关闭此浏览器标签页，直接返回 Antigravity 控制台。</div>
  </div>
</body>
</html>`;
}

export function renderOauthErrorHtml(errorMessage = '') {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Antigravity 账号授权失败</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0d1117;
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .card {
      background: #161b22;
      border: 1px solid #da3633;
      border-radius: 12px;
      padding: 36px 32px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 12px 32px rgba(0,0,0,0.5);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 14px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
      background: rgba(248, 81, 73, 0.18);
      color: #f85149;
      border: 1px solid rgba(248, 81, 73, 0.4);
      margin-bottom: 18px;
    }
    h2 {
      margin: 0 0 12px;
      font-size: 20px;
      color: #f85149;
    }
    p {
      margin: 0 0 20px;
      font-size: 14px;
      line-height: 1.6;
      color: #8b949e;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✕ 授权未完成</div>
    <h2>Google 账号授权失败</h2>
    <p>${escapeHtmlText(errorMessage || '未完成授权流程，请返回控制台重新尝试。')}</p>
  </div>
</body>
</html>`;
}

export function normalizeAccountSettings(raw = {}) {
  const src = raw && typeof raw === 'object' ? raw : {};

  let refreshMin = DEFAULT_ACCOUNT_SETTINGS.quotaRefreshIntervalMin;
  if (src.quotaRefreshIntervalMin !== undefined && src.quotaRefreshIntervalMin !== null && src.quotaRefreshIntervalMin !== '') {
    const n = Math.round(Number(src.quotaRefreshIntervalMin));
    if (Number.isFinite(n)) {
      refreshMin = Math.max(0, Math.min(1440, n));
    }
  }

  let rawTarget = String(src.autoSwitchTarget || DEFAULT_ACCOUNT_SETTINGS.autoSwitchTarget).trim().toLowerCase();
  if (rawTarget === 'claude' || rawTarget === 'gpt' || rawTarget === 'gptclaude') {
    rawTarget = 'gpt_claude';
  }
  const autoSwitchTarget = VALID_AUTO_SWITCH_TARGETS.has(rawTarget)
    ? rawTarget
    : DEFAULT_ACCOUNT_SETTINGS.autoSwitchTarget;

  const autoSwitchEnabled = Boolean(src.autoSwitchEnabled);

  const rawSortBy = String(src.sortBy || DEFAULT_ACCOUNT_SETTINGS.sortBy).trim();
  const sortBy = VALID_SORT_BY.has(rawSortBy) ? rawSortBy : DEFAULT_ACCOUNT_SETTINGS.sortBy;

  const rawSortOrder = String(src.sortOrder || DEFAULT_ACCOUNT_SETTINGS.sortOrder).trim().toLowerCase();
  const sortOrder = VALID_SORT_ORDER.has(rawSortOrder)
    ? rawSortOrder
    : DEFAULT_ACCOUNT_SETTINGS.sortOrder;

  return {
    quotaRefreshIntervalMin: refreshMin,
    autoSwitchTarget,
    autoSwitchEnabled,
    sortBy,
    sortOrder,
  };
}

function getEffectiveBucketPct(bucket, nowMs) {
  if (!bucket || bucket.disabled) return null;
  if (!bucket.isFull && bucket.resetTimeMs && bucket.resetTimeMs <= nowMs) {
    return 100;
  }
  if (bucket.remainingPct !== null && bucket.remainingPct !== undefined && Number.isFinite(Number(bucket.remainingPct))) {
    return Math.max(0, Math.min(100, Number(bucket.remainingPct)));
  }
  if (bucket.remainingFraction !== null && bucket.remainingFraction !== undefined && Number.isFinite(Number(bucket.remainingFraction))) {
    return Math.max(0, Math.min(100, Math.round(Number(bucket.remainingFraction) * 100)));
  }
  return null;
}

/**
 * Determine whether the specified quota group's 5-hour OR weekly quota is definitively exhausted (<= 0%).
 * Returns `{ exhausted, reason: 'five_hour' | 'weekly' | null }`.
 * Never treats missing/null/disabled data or already-reset windows as exhausted.
 */
export function inspectQuotaExhaustion(quota, targetGroupKey = 'gemini', nowMs = Date.now()) {
  if (!quota || !Array.isArray(quota.groups)) {
    return { exhausted: false, reason: null };
  }
  const group = quota.groups.find((g) => g && g.key === targetGroupKey);
  if (!group) {
    return { exhausted: false, reason: null };
  }

  const eff5h = getEffectiveBucketPct(group.fiveHour, nowMs);
  if (eff5h !== null && eff5h <= 0) {
    return { exhausted: true, reason: 'five_hour' };
  }
  const effWeekly = getEffectiveBucketPct(group.weekly, nowMs);
  if (effWeekly !== null && effWeekly <= 0) {
    return { exhausted: true, reason: 'weekly' };
  }
  return { exhausted: false, reason: null };
}

/**
 * Determine whether the specified quota group's 5-hour or weekly quota is definitively exhausted (<= 0%).
 * Kept under the existing export name for backward compatibility.
 */
export function isFiveHourQuotaExhausted(quota, targetGroupKey = 'gemini', nowMs = Date.now()) {
  return inspectQuotaExhaustion(quota, targetGroupKey, nowMs).exhausted;
}

export function mapModelToQuotaGroup(modelId) {
  const s = String(modelId || '').trim().toLowerCase();
  if (!s) return null;
  if (s.includes('argon')) return 'argon';
  if (
    s.includes('claude') ||
    s.includes('opus') ||
    s.includes('sonnet') ||
    s.includes('haiku') ||
    s.includes('gpt') ||
    s.includes('codex') ||
    /(?:^|[-_/])o[134](?:$|[-_/])/.test(s)
  ) {
    return 'gpt_claude';
  }
  if (
    s.includes('gemini') ||
    s.includes('flash') ||
    s.includes('hydrogen') ||
    s.includes('neon') ||
    s.includes('carbon')
  ) {
    return 'gemini';
  }
  return null;
}

function readLocalProtoVarint(buf, offset) {
  let val = 0n;
  let shift = 0n;
  let i = offset;
  const maxEnd = Math.min(buf.length, offset + 10);
  while (i < maxEnd) {
    const b = buf[i++];
    val |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value: val, next: i, ok: true };
    shift += 7n;
  }
  return { value: 0n, next: buf.length, ok: false };
}

function iterLocalProtoFields(buf, onField) {
  let i = 0;
  while (i < buf.length) {
    const tag = readLocalProtoVarint(buf, i);
    if (!tag.ok) break;
    i = tag.next;
    const field = Number(tag.value >> 3n);
    const wire = Number(tag.value & 7n);
    if (field <= 0) break;
    if (wire === 0) {
      const v = readLocalProtoVarint(buf, i);
      if (!v.ok) break;
      i = v.next;
      onField(field, wire, v.value);
    } else if (wire === 1) {
      if (i + 8 > buf.length) break;
      i += 8;
    } else if (wire === 2) {
      const lenRes = readLocalProtoVarint(buf, i);
      if (!lenRes.ok) break;
      const len = Number(lenRes.value);
      i = lenRes.next;
      if (!Number.isSafeInteger(len) || len < 0 || i + len > buf.length) break;
      onField(field, wire, buf.subarray(i, i + len));
      i += len;
    } else if (wire === 5) {
      if (i + 4 > buf.length) break;
      i += 4;
    } else {
      break;
    }
  }
}

function decodeLocalProtoTimestampMs(buf) {
  if (!buf || buf.length === 0) return 0;
  let sec = 0n;
  let nanos = 0n;
  iterLocalProtoFields(buf, (f, w, v) => {
    if (w !== 0) return;
    if (f === 1) sec = v;
    else if (f === 2) nanos = v;
  });
  if (sec <= 0n || sec > 4_102_444_800n) return 0;
  const nanoMs = nanos >= 0n && nanos < 1_000_000_000n ? Math.trunc(Number(nanos) / 1e6) : 0;
  return Number(sec) * 1000 + nanoMs;
}

const QUOTA_EXHAUSTED_TEXT_RE =
  /\bQUOTA_EXHAUSTED\b|\bMODEL_QUOTA_EXHAUSTED\b|individual\s+quota\s+reached|baseline\s+quota\s+will\s+refresh|quota\s+(?:is\s+)?(?:reached|exhausted|depleted|empty)|out\s+of\s+quota|enable\s+AI\s+Credit\s+overages/i;

/**
 * Parse an Antigravity `steps` row with `step_type = 17` (`ERROR_MESSAGE`) from
 * `conversations/<convId>.db` and detect genuine quota-exhausted errors
 * (e.g. `QUOTA_EXHAUSTED` / `Individual quota reached` / HTTP 429 `RESOURCE_EXHAUSTED`).
 * Transient capacity/network errors (503 UNAVAILABLE, TLS/EOF, stream interrupted) return null.
 */
export function parseQuotaExhaustedStepError(metadataBuf, payloadBuf, { convId = '', stepIndex = 0 } = {}) {
  const meta = Buffer.isBuffer(metadataBuf)
    ? metadataBuf
    : metadataBuf instanceof Uint8Array
      ? Buffer.from(metadataBuf.buffer, metadataBuf.byteOffset, metadataBuf.byteLength)
      : null;
  const payload = Buffer.isBuffer(payloadBuf)
    ? payloadBuf
    : payloadBuf instanceof Uint8Array
      ? Buffer.from(payloadBuf.buffer, payloadBuf.byteOffset, payloadBuf.byteLength)
      : null;
  if (!payload || payload.length === 0) return null;

  let createdAtMs = 0;
  if (meta && meta.length > 0) {
    iterLocalProtoFields(meta, (f, w, v) => {
      if (f === 1 && w === 2 && createdAtMs === 0) {
        createdAtMs = decodeLocalProtoTimestampMs(v);
      }
    });
  }

  let shortMessage = '';
  let detailMessage = '';
  let rawErrorJson = '';
  let errorId = '';
  let httpCode = 0;
  let altDetailMessage = '';
  const rpcDetails = [];

  try {
    iterLocalProtoFields(payload, (f, w, v) => {
      if (f === 5 && w === 2 && createdAtMs === 0) {
        iterLocalProtoFields(v, (mf, mw, mv) => {
          if (mf === 1 && mw === 2 && createdAtMs === 0) {
            createdAtMs = decodeLocalProtoTimestampMs(mv);
          }
        });
      } else if (f === 24 && w === 2) {
        iterLocalProtoFields(v, (ef, ew, ev) => {
          if (ef !== 3 || ew !== 2) return;
          iterLocalProtoFields(ev, (df, dw, dv) => {
            if (df === 1 && dw === 2 && !shortMessage) shortMessage = dv.toString('utf8').trim();
            else if (df === 2 && dw === 2 && !detailMessage) detailMessage = dv.toString('utf8').trim();
            else if (df === 5 && dw === 2 && !rawErrorJson) rawErrorJson = dv.toString('utf8').trim();
            else if (df === 6 && dw === 2 && !errorId) errorId = dv.toString('utf8').trim();
            else if (df === 7 && dw === 0 && !httpCode) httpCode = Number(dv);
            else if (df === 9 && dw === 2 && !altDetailMessage) altDetailMessage = dv.toString('utf8').trim();
            else if (df === 10 && dw === 2) rpcDetails.push(dv.toString('utf8').trim());
          });
        });
      }
    });
  } catch {
    return null;
  }

  let isQuotaExhausted = false;
  let model = '';
  const inspectRpcObj = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    const reason = String(obj.reason || '').trim().toUpperCase();
    if (reason === 'QUOTA_EXHAUSTED' || reason === 'MODEL_QUOTA_EXHAUSTED') {
      isQuotaExhausted = true;
    }
    if (!model && typeof obj.metadata?.model === 'string' && obj.metadata.model.trim()) {
      model = obj.metadata.model.trim();
    }
    if (obj.error && typeof obj.error === 'object') {
      const status = String(obj.error.status || '').trim().toUpperCase();
      const msg = String(obj.error.message || '');
      if (status === 'RESOURCE_EXHAUSTED' && /quota/i.test(msg)) {
        isQuotaExhausted = true;
      }
      if (Array.isArray(obj.error.details)) {
        for (const d of obj.error.details) inspectRpcObj(d);
      }
    }
  };

  for (const jsonStr of rpcDetails) {
    if (!jsonStr || !jsonStr.startsWith('{')) continue;
    try {
      inspectRpcObj(JSON.parse(jsonStr));
    } catch {
      // ignore malformed JSON
    }
  }
  if (rawErrorJson && rawErrorJson.startsWith('{')) {
    try {
      inspectRpcObj(JSON.parse(rawErrorJson));
    } catch {
      // ignore malformed JSON
    }
  }

  const combinedText = [shortMessage, detailMessage, altDetailMessage].filter(Boolean).join(' | ');
  if (!isQuotaExhausted && combinedText) {
    if (QUOTA_EXHAUSTED_TEXT_RE.test(combinedText)) {
      isQuotaExhausted = true;
    } else if (
      httpCode === 429 &&
      /RESOURCE_EXHAUSTED/i.test(combinedText) &&
      /quota/i.test(combinedText)
    ) {
      isQuotaExhausted = true;
    }
  }
  if (!isQuotaExhausted) return null;

  if (!model && combinedText) {
    const m = combinedText.match(/\bfor\s+model\s+([a-zA-Z0-9._-]+)/i);
    if (m && m[1]) model = m[1];
  }

  const cleanConvId = String(convId || '').trim();
  const cleanIdx = Number.isInteger(Number(stepIndex)) ? Number(stepIndex) : 0;
  const errorKey = errorId || `${cleanConvId}:${cleanIdx}:${createdAtMs}`;

  return {
    convId: cleanConvId,
    stepIndex: cleanIdx,
    createdAtMs,
    errorId: errorId || errorKey,
    errorKey,
    model,
    quotaGroup: mapModelToQuotaGroup(model),
    message: (shortMessage || detailMessage || 'Individual quota reached').slice(0, 240),
  };
}

/**
 * Scan recently modified `conversations/<convId>.db` files (strictly read-only)
 * to detect a fresh halted `step_type = 17` quota-exhausted error.
 * Uses an optional file-stamp cache (`mtime:size` across `.db` + `.db-wal`) so idle ticks do zero SQLite opens.
 */
export async function detectRecentQuotaExhaustedError(
  conversationsDir,
  {
    nowMs = Date.now(),
    freshnessMs = QUOTA_ERROR_FRESHNESS_MS,
    minCreatedAtMs = 0,
    handledErrorKeys = null,
    fileStampCache = null,
    summariesDbPath = '',
  } = {},
) {
  if (!conversationsDir || !fs.existsSync(conversationsDir)) return null;
  let entries;
  try {
    entries = await fsp.readdir(conversationsDir, { withFileTypes: true });
  } catch {
    return null;
  }

  const cutoffMs = Math.max(nowMs - freshnessMs, Number(minCreatedAtMs) || 0);
  const recentFiles = [];
  for (const ent of entries) {
    if (!ent.isFile() || !ent.name.endsWith('.db')) continue;
    const convId = ent.name.slice(0, -3);
    if (!convId || convId.startsWith('.')) continue;
    const dbPath = path.join(conversationsDir, ent.name);
    let mainStat;
    try {
      mainStat = await fsp.stat(dbPath);
    } catch {
      continue;
    }
    let walMtime = 0;
    let walSize = 0;
    try {
      const walStat = await fsp.stat(`${dbPath}-wal`);
      walMtime = Math.trunc(walStat.mtimeMs);
      walSize = walStat.size;
    } catch {
      // No active WAL file
    }
    const effectiveMtime = Math.max(Math.trunc(mainStat.mtimeMs), walMtime);
    if (effectiveMtime < cutoffMs - 5000) continue;
    const stamp = `${Math.trunc(mainStat.mtimeMs)}:${mainStat.size}|${walMtime}:${walSize}`;
    recentFiles.push({ convId, dbPath, effectiveMtime, stamp });
  }

  if (recentFiles.length === 0) return null;
  recentFiles.sort((a, b) => b.effectiveMtime - a.effectiveMtime);
  const topCandidates = recentFiles.slice(0, 10);

  let newestError = null;
  for (const item of topCandidates) {
    if (fileStampCache && fileStampCache.get(item.convId) === item.stamp) {
      continue;
    }
    let db = null;
    try {
      db = new DatabaseSync(item.dbPath, { readOnly: true, timeout: 500 });
      const hasSteps = db
        .prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'steps'`)
        .get();
      if (!hasSteps) {
        fileStampCache?.set(item.convId, item.stamp);
        continue;
      }
      // Latest major step (14=USER_INPUT, 15=PLANNER_RESPONSE, 17=ERROR_MESSAGE):
      // only treat as an active halt if step_type=17 is NOT superseded by a newer turn.
      const row = db
        .prepare(
          `SELECT idx, step_type, metadata, step_payload
           FROM steps
           WHERE step_type IN (14, 15, 17)
           ORDER BY idx DESC
           LIMIT 1`,
        )
        .get();
      fileStampCache?.set(item.convId, item.stamp);
      if (!row || Number(row.step_type) !== 17) continue;

      const parsed = parseQuotaExhaustedStepError(row.metadata, row.step_payload, {
        convId: item.convId,
        stepIndex: Number(row.idx),
      });
      if (!parsed) continue;

      const ts = parsed.createdAtMs || item.effectiveMtime;
      parsed.createdAtMs = ts;
      if (ts < nowMs - freshnessMs) continue;
      if (minCreatedAtMs > 0 && ts <= minCreatedAtMs) continue;
      if (handledErrorKeys && handledErrorKeys.has(parsed.errorKey)) continue;

      if (!newestError || parsed.createdAtMs > newestError.createdAtMs) {
        newestError = parsed;
      }
    } catch {
      // Transient SQLite lock or legacy schema: skip cleanly
    } finally {
      if (db) {
        try {
          db.close();
        } catch {
          // ignore
        }
      }
    }
  }

  if (!newestError) return null;

  // If the errored conversation is a subagent, resolve its top-level parent for safe auto-resume
  let resumeConvId = newestError.convId;
  let resumeTitle = '';
  if (summariesDbPath && fs.existsSync(summariesDbPath)) {
    let sumDb = null;
    try {
      sumDb = new DatabaseSync(summariesDbPath, { readOnly: true, timeout: 500 });
      const cols = new Set(
        sumDb
          .prepare(`PRAGMA table_info(conversation_summaries)`)
          .all()
          .map((c) => String(c.name || '').toLowerCase()),
      );
      if (cols.has('conversation_id')) {
        const parentSel = cols.has('parent_conversation_id')
          ? 'parent_conversation_id'
          : "'' AS parent_conversation_id";
        const titleSel = cols.has('title') ? 'title' : "'' AS title";
        const metaRow = sumDb
          .prepare(
            `SELECT ${titleSel}, ${parentSel} FROM conversation_summaries WHERE conversation_id = ?`,
          )
          .get(newestError.convId);
        if (metaRow) {
          const parentId = String(metaRow.parent_conversation_id || '').trim();
          if (parentId && parentId !== newestError.convId) {
            resumeConvId = parentId;
          } else {
            resumeTitle = String(metaRow.title || '').trim();
          }
        }
      }
    } catch {
      // Non-fatal
    } finally {
      if (sumDb) {
        try {
          sumDb.close();
        } catch {
          // ignore
        }
      }
    }
  }

  return {
    ...newestError,
    resumeConvId,
    resumeTitle,
  };
}

/**
 * Pick the highest-remaining-quota enabled backup account for `targetGroupKey`.
 * Strictly excludes:
 * - currently active account
 * - disabled accounts
 * - accounts whose target group's 5h quota is 0% (and not yet reset)
 * - accounts whose target group's weekly quota is 0% (and not yet reset)
 */
export function selectBestAutoSwitchCandidate(
  accounts = [],
  { currentEmail = '', targetGroupKey = 'gemini', nowMs = Date.now() } = {},
) {
  const curEmailNorm = sanitizeEmail(currentEmail);
  const candidates = [];

  for (const acc of Array.isArray(accounts) ? accounts : []) {
    if (!acc || !acc.id) continue;
    if (acc.enabled === false) continue;
    if (curEmailNorm && sanitizeEmail(acc.email) === curEmailNorm) continue;

    const group = Array.isArray(acc.quota?.groups)
      ? acc.quota.groups.find((g) => g && g.key === targetGroupKey) || null
      : null;

    const eff5h = getEffectiveBucketPct(group?.fiveHour || null, nowMs);
    const effWeekly = getEffectiveBucketPct(group?.weekly || null, nowMs);

    // Exclude any candidate whose 5h quota is 0 OR whose weekly quota is 0
    if (eff5h !== null && eff5h <= 0) continue;
    if (effWeekly !== null && effWeekly <= 0) continue;

    const primaryScore =
      eff5h !== null ? eff5h : effWeekly !== null ? effWeekly : -1;
    const secondaryScore = effWeekly !== null ? effWeekly : -1;

    candidates.push({
      acc,
      primaryScore,
      secondaryScore,
      lastUsedAtMs: Number(acc.lastUsedAtMs || 0),
    });
  }

  if (candidates.length === 0) return null;

  candidates.sort((a, b) => {
    if (b.primaryScore !== a.primaryScore) return b.primaryScore - a.primaryScore;
    if (b.secondaryScore !== a.secondaryScore) return b.secondaryScore - a.secondaryScore;
    return a.lastUsedAtMs - b.lastUsedAtMs;
  });

  return candidates[0].acc;
}

const DEFAULT_QUOTA_GROUPS = Object.freeze([
  { key: 'gemini', label: 'Gemini', displayName: 'Gemini Models' },
  { key: 'gpt_claude', label: 'GPT&Claude', displayName: 'Claude and GPT models' },
  { key: 'argon', label: 'Argon', displayName: 'Gemini 4 Argon' },
]);

let compilePromise = null;

function execFileWithStdin(file, args, { stdinText = '', timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      file,
      args,
      { windowsHide: true, timeout, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout;
          err.stderr = stderr;
          reject(err);
          return;
        }
        resolve({ stdout, stderr });
      },
    );
    if (child.stdin) {
      child.stdin.on('error', () => {});
      if (stdinText) {
        child.stdin.write(stdinText, 'utf8');
      }
      child.stdin.end();
    }
  });
}

function writeUtf16LeBom(filePath, content) {
  const buf = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from(String(content ?? ''), 'utf16le'),
  ]);
  return atomicWriteBuffer(filePath, buf);
}

function escapeVbsString(str) {
  return String(str || '').replace(/"/g, '""');
}

function sanitizeEmail(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s || s.length > 180) return '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return '';
  return s;
}

function sanitizeRemark(raw) {
  return String(raw || '')
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, MAX_REMARK_CHARS);
}

function decodeJwtEmail(idToken) {
  if (typeof idToken !== 'string') return '';
  const parts = idToken.split('.');
  if (parts.length < 2) return '';
  try {
    const padLen = (4 - (parts[1].length % 4)) % 4;
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLen);
    const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    return sanitizeEmail(payload?.email || '');
  } catch {
    return '';
  }
}

function extractRefreshToken(credObj) {
  if (!credObj || typeof credObj !== 'object') return '';
  if (typeof credObj.token?.refresh_token === 'string' && credObj.token.refresh_token.trim()) {
    return credObj.token.refresh_token.trim();
  }
  if (typeof credObj.refresh_token === 'string' && credObj.refresh_token.trim()) {
    return credObj.refresh_token.trim();
  }
  if (typeof credObj.refreshToken === 'string' && credObj.refreshToken.trim()) {
    return credObj.refreshToken.trim();
  }
  return '';
}

function extractEmailFromCred(credObj) {
  if (!credObj || typeof credObj !== 'object') return '';
  const direct = sanitizeEmail(
    credObj.id_token_email ||
      credObj.email ||
      credObj.user_email ||
      credObj.account_email ||
      credObj.token?.email ||
      '',
  );
  if (direct) return direct;
  const idToken =
    credObj.id_token ||
    credObj.token?.id_token ||
    credObj.idToken ||
    '';
  return decodeJwtEmail(idToken);
}

/**
 * Normalize any supported OAuth credential shape into Antigravity 2.x's
 * canonical Windows Credential Manager UTF-8 JSON structure.
 */
export function normalizeCredentialObject(rawObj, fallbackEmail = '') {
  if (!rawObj || typeof rawObj !== 'object') return null;
  const refreshToken = extractRefreshToken(rawObj);
  if (!refreshToken) return null;

  const email = extractEmailFromCred(rawObj) || sanitizeEmail(fallbackEmail);
  const existingToken = rawObj.token && typeof rawObj.token === 'object' ? rawObj.token : {};

  const accessToken =
    (typeof existingToken.access_token === 'string' && existingToken.access_token.trim()) ||
    (typeof rawObj.access_token === 'string' && rawObj.access_token.trim()) ||
    (typeof rawObj.accessToken === 'string' && rawObj.accessToken.trim()) ||
    '';

  const tokenType =
    (typeof existingToken.token_type === 'string' && existingToken.token_type.trim()) ||
    (typeof rawObj.token_type === 'string' && rawObj.token_type.trim()) ||
    'Bearer';

  const expiry =
    (typeof existingToken.expiry === 'string' && existingToken.expiry.trim()) ||
    (typeof rawObj.expiry === 'string' && rawObj.expiry.trim()) ||
    '1970-01-01T00:00:00Z';

  const expiresInRaw = existingToken.expires_in ?? rawObj.expires_in ?? 0;
  const expiresIn = Number.isFinite(Number(expiresInRaw)) ? Number(expiresInRaw) : 0;

  const tokenPayload = {
    ...existingToken,
    access_token: accessToken,
    token_type: tokenType,
    refresh_token: refreshToken,
    expiry,
    expires_in: expiresIn,
  };
  if (typeof rawObj.id_token === 'string' && rawObj.id_token.trim() && !tokenPayload.id_token) {
    tokenPayload.id_token = rawObj.id_token.trim();
  }

  const normalized = {
    token: tokenPayload,
    auth_method:
      (typeof rawObj.auth_method === 'string' && rawObj.auth_method.trim()) || 'consumer',
    ...(email ? { id_token_email: email } : {}),
    ...(typeof rawObj.writer_id === 'string' && rawObj.writer_id.trim()
      ? { writer_id: rawObj.writer_id.trim() }
      : {}),
  };

  return {
    email,
    refreshToken,
    credObj: normalized,
    credJson: JSON.stringify(normalized),
  };
}

/**
 * Parse flexible Token / JSON import text into normalized account entries.
 * Supports:
 * 1. Exported agy-monitor JSON (single object, array, or `{ accounts: [...] }`)
 * 2. Raw Antigravity credential JSON (`{ token: { refresh_token, ... }, id_token_email }`)
 * 3. Flat OAuth JSON (`{ email, refresh_token, access_token, id_token }`)
 * 4. Plain refresh_token lines (optionally `email,refresh_token,remark` or bare `1//0...`)
 */
export function parseImportPayload(rawInput, { fallbackEmail = '', fallbackRemark = '' } = {}) {
  const text = String(rawInput ?? '').trim();
  if (!text) {
    return { ok: false, status: 400, error: '导入内容不能为空' };
  }
  if (text.length > MAX_IMPORT_CHARS) {
    return { ok: false, status: 413, error: '导入文本超出 1 MB 大小上限' };
  }

  const cleanFallbackEmail = sanitizeEmail(fallbackEmail);
  const cleanFallbackRemark = sanitizeRemark(fallbackRemark);
  const parsedEntries = [];

  const pushFromObject = (item, idx) => {
    if (!item || typeof item !== 'object') return;
    const nestedCred =
      item.credential && typeof item.credential === 'object'
        ? item.credential
        : typeof item.credJson === 'string'
          ? (() => {
              try {
                return JSON.parse(item.credJson);
              } catch {
                return null;
              }
            })()
          : item;
    const hintEmail =
      sanitizeEmail(item.email || item.id_token_email || '') ||
      (idx === 0 ? cleanFallbackEmail : '');
    const norm = normalizeCredentialObject(nestedCred, hintEmail);
    if (!norm) return;

    const finalEmail =
      norm.email ||
      hintEmail ||
      `imported-${crypto.createHash('sha1').update(norm.refreshToken).digest('hex').slice(0, 8)}@oauth.local`;

    parsedEntries.push({
      email: finalEmail,
      remark: sanitizeRemark(item.remark ?? item.note ?? (idx === 0 ? cleanFallbackRemark : '')),
      enabled: item.enabled !== false,
      credTarget: typeof item.credTarget === 'string' && item.credTarget.trim()
        ? item.credTarget.trim()
        : 'gemini:antigravity',
      credUserName: typeof item.credUserName === 'string' && item.credUserName.trim()
        ? item.credUserName.trim()
        : 'antigravity',
      credPersist: Number.isInteger(Number(item.credPersist)) && Number(item.credPersist) > 0
        ? Number(item.credPersist)
        : 2,
      credJson: norm.credJson,
      authMethod: norm.credObj.auth_method || 'oauth',
      credentialUserScope:
        typeof item.credentialUserScope === 'string' ? item.credentialUserScope.trim() : '',
      quota: item.quota && typeof item.quota === 'object' ? normalizeStoredQuota(item.quota) : null,
    });
  };

  let parsedJson = null;
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      parsedJson = JSON.parse(text);
    } catch {
      return { ok: false, status: 400, error: 'JSON 格式解析失败，请检查括号与引号是否完整' };
    }
  }

  if (parsedJson !== null) {
    if (Array.isArray(parsedJson)) {
      parsedJson.slice(0, MAX_IMPORT_BATCH).forEach((item, idx) => pushFromObject(item, idx));
    } else if (Array.isArray(parsedJson.accounts)) {
      parsedJson.accounts.slice(0, MAX_IMPORT_BATCH).forEach((item, idx) => pushFromObject(item, idx));
    } else {
      pushFromObject(parsedJson, 0);
    }
  } else {
    // Plain text token lines: support bare `1//...` or `email,refresh_token,remark` / tab-separated
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));

    for (let i = 0; i < lines.length && parsedEntries.length < MAX_IMPORT_BATCH; i += 1) {
      const line = lines[i];
      if (line.startsWith('{')) {
        try {
          pushFromObject(JSON.parse(line), i);
          continue;
        } catch {
          // fall through to line parser
        }
      }
      const parts = line.includes('\t')
        ? line.split('\t').map((p) => p.trim())
        : line.includes(',')
          ? line.split(',').map((p) => p.trim())
          : [line];

      let lineEmail = '';
      let lineToken = '';
      let lineRemark = '';
      if (parts.length === 1) {
        lineToken = parts[0];
        if (i === 0) {
          lineEmail = cleanFallbackEmail;
          lineRemark = cleanFallbackRemark;
        }
      } else {
        for (const p of parts) {
          if (!lineEmail && sanitizeEmail(p)) {
            lineEmail = sanitizeEmail(p);
          } else if (!lineToken && (p.startsWith('1//') || p.length >= 24)) {
            lineToken = p;
          } else if (!lineRemark && p) {
            lineRemark = sanitizeRemark(p);
          }
        }
      }

      if (lineToken && lineToken.length >= 16) {
        pushFromObject(
          {
            email: lineEmail || (i === 0 ? cleanFallbackEmail : ''),
            remark: lineRemark || (i === 0 ? cleanFallbackRemark : ''),
            refresh_token: lineToken,
          },
          i,
        );
      }
    }
  }

  if (parsedEntries.length === 0) {
    return {
      ok: false,
      status: 400,
      error: '未识别到有效的 refresh_token 或账号 JSON，请检查输入格式',
    };
  }

  return { ok: true, items: parsedEntries };
}

function normalizeQuotaBucket(bucket) {
  if (!bucket || typeof bucket !== 'object') return null;
  const remainingFraction =
    bucket.remainingFraction !== null && bucket.remainingFraction !== undefined && Number.isFinite(Number(bucket.remainingFraction))
      ? Math.max(0, Math.min(1, Number(bucket.remainingFraction)))
      : bucket.remainingPct !== null && bucket.remainingPct !== undefined && Number.isFinite(Number(bucket.remainingPct))
        ? Math.max(0, Math.min(1, Number(bucket.remainingPct) / 100))
        : null;
  const remainingPct =
    remainingFraction === null ? null : Math.round(remainingFraction * 100);
  const remainingPctExact =
    remainingFraction === null ? null : Math.round(remainingFraction * 1000) / 10;
  const resetTimeMs = Number.isFinite(Number(bucket.resetTimeMs)) && Number(bucket.resetTimeMs) > 0
    ? Number(bucket.resetTimeMs)
    : null;
  return {
    remainingFraction,
    remainingPct,
    remainingPctExact,
    resetTimeMs,
    isFull: Boolean(bucket.isFull),
    disabled: Boolean(bucket.disabled),
  };
}

/**
 * Normalize quota payload into the 3 fixed account quota categories:
 * Gemini / GPT&Claude / Argon.
 */
export function normalizeStoredQuota(rawQuota, nowMs = Date.now()) {
  if (!rawQuota || typeof rawQuota !== 'object') return null;
  const rawGroups = Array.isArray(rawQuota.groups) ? rawQuota.groups : [];
  const byKey = new Map();
  for (const g of rawGroups) {
    if (!g || typeof g !== 'object') continue;
    const key = String(g.key || '').trim();
    if (!key) continue;
    byKey.set(key, g);
  }

  const groups = DEFAULT_QUOTA_GROUPS.map((def) => {
    const src = byKey.get(def.key) || null;
    return {
      key: def.key,
      label: src?.label || def.label,
      displayName: src?.displayName || def.displayName,
      fiveHour: normalizeQuotaBucket(src?.fiveHour || null),
      weekly: normalizeQuotaBucket(src?.weekly || null),
    };
  });

  return {
    fetchedAtMs: Number(rawQuota.fetchedAtMs) > 0 ? Number(rawQuota.fetchedAtMs) : nowMs,
    source: rawQuota.source === 'estimated' ? 'estimated' : 'live',
    groups,
  };
}

function enrichQuotaWithResetStatus(quota, nowMs = Date.now()) {
  if (!quota || !Array.isArray(quota.groups)) return null;
  let resetPassedAny = false;
  const groups = quota.groups.map((g) => {
    const check = (b) => {
      if (!b) return null;
      const resetPassed = Boolean(
        !b.disabled && !b.isFull && b.resetTimeMs && b.resetTimeMs <= nowMs,
      );
      if (resetPassed) resetPassedAny = true;
      return { ...b, resetPassed };
    };
    return {
      ...g,
      fiveHour: check(g.fiveHour),
      weekly: check(g.weekly),
    };
  });
  return {
    ...quota,
    resetPassedAny,
    groups,
  };
}

function readJsonFileSafe(filePath, fallback = null) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

/**
 * Compile AgyAccountTool.cs -> agy_account_tool.exe incrementally using built-in csc.exe.
 */
export async function ensureAccountTool(paths) {
  const hostInfo = detectWindowsHostEnv();
  if (!hostInfo.isNativeWindows) {
    return {
      supported: false,
      compiled: false,
      exePath: '',
      reason: '原生凭据与 DPAPI 加密目前仅支持 Windows 宿主环境',
    };
  }
  const srcPath = paths?.accountToolSourceFile || '';
  if (!srcPath || !fs.existsSync(srcPath)) {
    return { supported: true, compiled: false, exePath: '', reason: 'AgyAccountTool.cs 源码缺失' };
  }
  if (!hostInfo.cscPath || !fs.existsSync(hostInfo.cscPath)) {
    return { supported: true, compiled: false, exePath: '', reason: '未检测到 .NET Framework csc.exe' };
  }

  const doWork = async () => {
    const exePath = paths.accountToolExeFile;
    const hashPath = paths.accountToolHashFile;
    const binDir = path.dirname(exePath);
    const sourceBuf = await fsp.readFile(srcPath);
    const sourceHash = crypto.createHash('sha1').update(sourceBuf).digest('hex');

    let prevHash = '';
    try {
      prevHash = (await fsp.readFile(hashPath, 'utf8')).trim();
    } catch {
      prevHash = '';
    }

    if (fs.existsSync(exePath) && prevHash === sourceHash) {
      return { supported: true, compiled: true, compiledNow: false, exePath };
    }

    await fsp.mkdir(binDir, { recursive: true });
    const tmpExe = `${exePath}.tmp.${process.pid}.exe`;
    try {
      await execFileWithStdin(
        hostInfo.cscPath,
        [
          '/nologo',
          '/target:exe',
          '/optimize+',
          `/out:${tmpExe}`,
          '/r:System.Security.dll',
          '/r:System.Web.Extensions.dll',
          srcPath,
        ],
        { timeout: 25000 },
      );
      try {
        await fsp.rename(tmpExe, exePath);
      } catch {
        await fsp.copyFile(tmpExe, exePath);
        await fsp.rm(tmpExe, { force: true }).catch(() => {});
      }
      await atomicWriteText(hashPath, `${sourceHash}\n`);
      return { supported: true, compiled: true, compiledNow: true, exePath };
    } catch (err) {
      await fsp.rm(tmpExe, { force: true }).catch(() => {});
      return {
        supported: true,
        compiled: false,
        exePath: '',
        reason: err?.stderr || err?.stdout || err?.message || '编译 AgyAccountTool 失败',
      };
    }
  };

  if (!compilePromise) {
    compilePromise = doWork().finally(() => {
      compilePromise = null;
    });
  }
  return compilePromise;
}

/**
 * Detect current running Antigravity.exe path and non-internal launch flags
 * (preserving `--remote-debugging-port=<port>` so CDP wallpaper & HUD stay intact).
 */
async function detectRunningAntigravityLaunch(storage) {
  const fallbackExe = findAntigravityExePath();
  let exePath = fallbackExe;
  let launchArgs = '';

  const hostInfo = detectWindowsHostEnv();
  if (hostInfo.isNativeWindows) {
    try {
      const ps =
        "Get-CimInstance Win32_Process -Filter \"Name='Antigravity.exe'\" | Select-Object ExecutablePath, CommandLine | ConvertTo-Json -Compress";
      const { stdout } = await execFileWithStdin('powershell.exe', ['-NoProfile', '-Command', ps], {
        timeout: 4000,
      });
      const parsed = JSON.parse(String(stdout || '[]').trim() || '[]');
      const procs = Array.isArray(parsed) ? parsed : [parsed];
      // Primary Electron main process does not have `--type=` or `sidecars/`
      const mainProc = procs.find(
        (p) =>
          p &&
          typeof p.CommandLine === 'string' &&
          !p.CommandLine.includes('--type=') &&
          !p.CommandLine.includes('sidecar_sdk') &&
          !p.CommandLine.includes('mcp_entry'),
      );
      if (mainProc) {
        if (mainProc.ExecutablePath && fs.existsSync(mainProc.ExecutablePath)) {
          exePath = mainProc.ExecutablePath;
        }
        const cmd = String(mainProc.CommandLine || '').trim();
        // Strip leading quoted or unquoted executable path
        const stripped = cmd.replace(/^(?:"[^"]+"|\S+)\s*/, '').trim();
        if (stripped) {
          launchArgs = stripped;
        }
      }
    } catch {
      // Fallback to exe discovery + theme CDP flag
    }
  }

  // If CDP wallpaper mode was enabled in themes, ensure `--remote-debugging-port` is preserved
  if (!launchArgs.includes('--remote-debugging-port') && storage?.getThemes) {
    try {
      const themes = await storage.getThemes();
      const cdpPort = Number(themes?.cdpPort || 9229);
      const wantCdp = Boolean(themes?.backdropEnabled && themes?.activeWallpaperId);
      if (wantCdp && Number.isInteger(cdpPort) && cdpPort >= 1024 && cdpPort <= 65535) {
        launchArgs = launchArgs
          ? `${launchArgs} --remote-debugging-port=${cdpPort}`
          : `--remote-debugging-port=${cdpPort}`;
      }
    } catch {
      // Non-fatal
    }
  }

  return {
    exePath,
    launchArgs,
    workDir: exePath ? path.dirname(exePath) : '',
  };
}

/**
 * Strip Electron/sidecar pollution (notably `ELECTRON_RUN_AS_NODE=1` injected by
 * `agy-node.cmd`) so the detached switch daemon relaunches Antigravity.exe as a
 * full desktop Electron app rather than a Node CLI process that exits immediately.
 */
export function buildCleanLaunchEnv(baseEnv = process.env) {
  const clean = {};
  const blockedExact = new Set([
    'ELECTRON_RUN_AS_NODE',
    'ELECTRON_NO_ATTACH_CONSOLE',
    'ELECTRON_NO_ASAR',
    'NODE_OPTIONS',
    'NODE_EXTRA_CA_CERTS',
  ]);
  for (const [k, v] of Object.entries(baseEnv || {})) {
    if (v === undefined) continue;
    const upper = String(k).toUpperCase();
    if (
      blockedExact.has(upper) ||
      upper.startsWith('ANTIGRAVITY_') ||
      upper.startsWith('AGY_') ||
      upper.startsWith('VSCODE_')
    ) {
      continue;
    }
    clean[k] = v;
  }
  return clean;
}

/**
 * Default native Windows driver backed by compiled AgyAccountTool.exe (DPAPI + CredRead/Write).
 */
export function createWindowsAccountDriver(paths, storage) {
  const roamingDir = path.join(
    process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'),
    'Antigravity',
  );

  async function requireToolExe() {
    const res = await ensureAccountTool(paths);
    if (!res.supported || !res.compiled || !res.exePath) {
      const err = new Error(res.reason || '本机凭据安全助手不可用');
      err.status = 501;
      throw err;
    }
    return res.exePath;
  }

  async function runToolJson(args, stdinText = '') {
    const exePath = await requireToolExe();
    const { stdout } = await execFileWithStdin(exePath, args, { stdinText, timeout: 15000 });
    const parsed = JSON.parse(String(stdout || '{}'));
    if (parsed && parsed.ok === false) {
      throw new Error(parsed.error || '凭据助手执行失败');
    }
    return parsed;
  }

  return {
    isSupported() {
      return detectWindowsHostEnv().isNativeWindows;
    },
    getRoamingDir() {
      return roamingDir;
    },
    async ensureReady() {
      return ensureAccountTool(paths);
    },
    async readLiveCredential() {
      const res = await runToolJson(['--cred-read', 'gemini:antigravity']);
      if (!res?.found || !res.blobBase64) {
        return { found: false, roamingDir };
      }
      const credJson = Buffer.from(res.blobBase64, 'base64').toString('utf8');
      let credentialUserScope = '';
      const scopePath = path.join(roamingDir, 'credential-user-scope');
      try {
        if (fs.existsSync(scopePath)) {
          credentialUserScope = (await fsp.readFile(scopePath, 'utf8')).trim();
        }
      } catch {
        // optional
      }
      return {
        found: true,
        credTarget: res.target || 'gemini:antigravity',
        credUserName: res.userName || 'antigravity',
        credPersist: Number(res.persist) || 2,
        credJson,
        lastWrittenUtc: res.lastWrittenUtc || '',
        credentialUserScope,
        roamingDir,
      };
    },
    async protectSecret(plainText) {
      const res = await runToolJson(['--dpapi-protect'], String(plainText || ''));
      if (!res?.cipherBase64) {
        throw new Error('DPAPI 加密失败');
      }
      return String(res.cipherBase64);
    },
    async unprotectSecret(cipherBase64) {
      const res = await runToolJson(['--dpapi-unprotect'], String(cipherBase64 || ''));
      if (typeof res?.plainText !== 'string') {
        throw new Error('DPAPI 解密失败');
      }
      return res.plainText;
    },
    async detectAntigravityLaunchConfig() {
      return detectRunningAntigravityLaunch(storage);
    },
    async launchSwitchDaemon(txPath) {
      const exePath = await requireToolExe();
      // Launch via wscript.exe with window style 0 for zero console flash and full process-tree detachment
      const vbsPath = path.join(paths.accountsDir, 'run_switch_daemon.vbs');
      const cmd = `"${escapeVbsString(exePath)}" --switch-daemon "${escapeVbsString(txPath)}"`;
      const vbsContent = [
        'Set sh = CreateObject("WScript.Shell")',
        `sh.Run "${escapeVbsString(cmd)}", 0, False`,
        '',
      ].join('\r\n');
      await writeUtf16LeBom(vbsPath, vbsContent);

      const child = spawn('wscript.exe', ['//Nologo', vbsPath], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        env: buildCleanLaunchEnv(process.env),
      });
      child.unref();
      return { ok: true, launched: true };
    },
  };
}

/**
 * Create the multi-account manager bound to paths, storage, quotaClient, and optional injected driver.
 */
export function createAccountManager({
  paths,
  storage,
  quotaClient,
  sidecarBridge,
  getRunningConversations,
  driver,
  remoteQuotaFetcher,
  now = () => Date.now(),
  onBeforeHostClose,
} = {}) {
  const activeDriver = driver || createWindowsAccountDriver(paths, storage);
  const activeRemoteQuotaFetcher =
    typeof remoteQuotaFetcher === 'function' ? remoteQuotaFetcher : fetchCloudCodeQuotaForCredential;
  const allowBackgroundRemoteRefresh = !driver || typeof remoteQuotaFetcher === 'function';
  let storeLock = Promise.resolve();
  let lastResumeResult = null;
  let lastOauthCaptureResult = null;
  let lastAutoSwitchResult = null;
  let lastAutoRefreshAtMs = 0;
  let lastAutoSwitchAtMs = 0;
  let lastAutoSwitchFromEmail = '';
  let autoSwitchInFlight = false;
  let watcherTimer = null;
  let watcherBusy = false;
  let activeDirectOauth = null;
  const quotaErrorFileStampCache = new Map();

  function withStoreLock(fn) {
    const next = storeLock.then(fn, fn);
    storeLock = next.catch(() => {});
    return next;
  }

  async function ensureDirs() {
    await fsp.mkdir(paths.accountsDir, { recursive: true });
    await fsp.mkdir(paths.accountsBackupsDir, { recursive: true });
  }

  function normalizeAutoSwitchState(rawState) {
    const s = rawState && typeof rawState === 'object' ? rawState : {};
    const handledErrorIds = Array.isArray(s.handledErrorIds)
      ? s.handledErrorIds.map((x) => String(x || '').trim()).filter(Boolean).slice(-MAX_HANDLED_QUOTA_ERRORS)
      : [];
    return {
      handledErrorIds,
      lastAutoSwitchAtMs: Number(s.lastAutoSwitchAtMs) > 0 ? Number(s.lastAutoSwitchAtMs) : 0,
      lastAutoSwitchFromEmail: sanitizeEmail(s.lastAutoSwitchFromEmail || ''),
    };
  }

  async function readIndex() {
    const raw = readJsonFileSafe(paths.accountsIndexFile, null);
    if (!raw || typeof raw !== 'object') {
      return {
        version: 1,
        activeAccountId: '',
        settings: normalizeAccountSettings(),
        autoSwitchState: normalizeAutoSwitchState(),
        accounts: [],
      };
    }
    return {
      version: 1,
      activeAccountId: typeof raw.activeAccountId === 'string' ? raw.activeAccountId : '',
      settings: normalizeAccountSettings(raw.settings),
      autoSwitchState: normalizeAutoSwitchState(raw.autoSwitchState),
      accounts: Array.isArray(raw.accounts) ? raw.accounts : [],
    };
  }

  async function recordAutoSwitchStatePatch({ handledErrorKey = '', switchedAtMs = 0, fromEmail = '' } = {}) {
    return withStoreLock(async () => {
      const index = await readIndex();
      const state = normalizeAutoSwitchState(index.autoSwitchState);
      if (handledErrorKey && !state.handledErrorIds.includes(handledErrorKey)) {
        state.handledErrorIds = [...state.handledErrorIds, handledErrorKey].slice(-MAX_HANDLED_QUOTA_ERRORS);
      }
      if (switchedAtMs > 0) {
        state.lastAutoSwitchAtMs = switchedAtMs;
        state.lastAutoSwitchFromEmail = sanitizeEmail(fromEmail);
      }
      index.autoSwitchState = state;
      await writeIndex(index);
      return state;
    });
  }

  async function writeIndex(index) {
    await ensureDirs();
    await atomicWriteJson(paths.accountsIndexFile, index);
  }

  async function readVault() {
    try {
      if (!fs.existsSync(paths.accountsVaultFile)) {
        return { version: 1, secrets: {} };
      }
      const cipher = (await fsp.readFile(paths.accountsVaultFile, 'utf8')).trim();
      if (!cipher) return { version: 1, secrets: {} };
      const plain = await activeDriver.unprotectSecret(cipher);
      const parsed = JSON.parse(plain);
      if (parsed && typeof parsed === 'object' && parsed.secrets && typeof parsed.secrets === 'object') {
        return { version: 1, secrets: parsed.secrets };
      }
      return { version: 1, secrets: {} };
    } catch (err) {
      const wrapped = new Error(`无法读取加密账号保险库: ${err?.message || err}`);
      wrapped.status = 500;
      throw wrapped;
    }
  }

  async function writeVault(vault) {
    await ensureDirs();
    const plain = JSON.stringify({
      version: 1,
      secrets: vault?.secrets && typeof vault.secrets === 'object' ? vault.secrets : {},
    });
    const cipher = await activeDriver.protectSecret(plain);
    await atomicWriteText(paths.accountsVaultFile, cipher);
  }

  async function listBackups() {
    try {
      const entries = await fsp.readdir(paths.accountsBackupsDir, { withFileTypes: true });
      const items = [];
      for (const ent of entries) {
        if (!ent.isFile() || !ent.name.endsWith('.bak.dat')) continue;
        const full = path.join(paths.accountsBackupsDir, ent.name);
        try {
          const st = await fsp.stat(full);
          items.push({ name: ent.name, path: full, mtimeMs: st.mtimeMs });
        } catch {
          // ignore
        }
      }
      items.sort((a, b) => b.mtimeMs - a.mtimeMs);
      return items;
    } catch {
      return [];
    }
  }

  async function pruneBackups() {
    const items = await listBackups();
    for (const stale of items.slice(MAX_BACKUPS_RETAINED)) {
      await fsp.rm(stale.path, { force: true }).catch(() => {});
    }
  }

  async function readLiveEmailSafe() {
    if (!activeDriver.isSupported()) {
      return { supported: false, email: '', found: false };
    }
    try {
      const live = await activeDriver.readLiveCredential();
      if (!live?.found || !live.credJson) {
        return { supported: true, email: '', found: false };
      }
      const parsed = JSON.parse(live.credJson);
      const email = extractEmailFromCred(parsed);
      return { supported: true, email, found: true, live, parsed };
    } catch {
      return { supported: true, email: '', found: false };
    }
  }

  async function fetchLiveQuotaNormalized() {
    if (!quotaClient || typeof quotaClient.getQuotaSummary !== 'function') return null;
    try {
      const raw = await quotaClient.getQuotaSummary({ force: true });
      if (raw && raw.ok && Array.isArray(raw.groups) && raw.groups.length > 0) {
        return normalizeStoredQuota(raw, now());
      }
      return null;
    } catch {
      return null;
    }
  }

  async function maybeTriggerAutoSwitch(liveEmail, liveQuota, { skipCheck = false, quotaError = null } = {}) {
    if (skipCheck || autoSwitchInFlight || !activeDriver.isSupported() || !liveEmail) {
      return { triggered: false };
    }
    if (!quotaError && !liveQuota) {
      return { triggered: false };
    }
    const nowMs = now();
    const cleanLiveEmail = sanitizeEmail(liveEmail);

    const index = await readIndex();
    const settings = normalizeAccountSettings(index.settings);
    if (!settings.autoSwitchEnabled) {
      return { triggered: false, reason: 'disabled' };
    }

    const persistedState = normalizeAutoSwitchState(index.autoSwitchState);
    const effectiveLastSwitchAtMs = Math.max(lastAutoSwitchAtMs, persistedState.lastAutoSwitchAtMs);
    const effectiveLastFromEmail = lastAutoSwitchFromEmail || persistedState.lastAutoSwitchFromEmail;
    if (effectiveLastSwitchAtMs > 0) {
      const elapsed = nowMs - effectiveLastSwitchAtMs;
      const sameAccount = Boolean(
        cleanLiveEmail && effectiveLastFromEmail && cleanLiveEmail === effectiveLastFromEmail,
      );
      const requiredCooldown = sameAccount
        ? AUTO_SWITCH_COOLDOWN_MS
        : AUTO_SWITCH_CROSS_ACCOUNT_SETTLE_MS;
      if (elapsed >= 0 && elapsed < requiredCooldown) {
        return { triggered: false, reason: 'cooldown' };
      }
    }

    let triggerReason = null;
    let targetGroupKey = settings.autoSwitchTarget;
    if (quotaError) {
      if (quotaError.errorKey && persistedState.handledErrorIds.includes(quotaError.errorKey)) {
        return { triggered: false, reason: 'already_handled' };
      }
      triggerReason = 'quota_error';
      targetGroupKey = quotaError.quotaGroup || settings.autoSwitchTarget;
    } else {
      const ex = inspectQuotaExhaustion(liveQuota, settings.autoSwitchTarget, nowMs);
      if (!ex.exhausted) {
        return { triggered: false, reason: 'not_exhausted' };
      }
      triggerReason = ex.reason; // 'five_hour' | 'weekly'
    }

    // Do not auto-switch while another switch transaction is actively in flight
    const tx = readJsonFileSafe(paths.accountSwitchTxFile, null);
    if (
      tx &&
      tx.stage &&
      !['done', 'failed', 'relaunch_failed'].includes(tx.stage) &&
      nowMs - Number(tx.updatedAtMs || tx.startedAtMs || 0) < 30_000
    ) {
      return { triggered: false, reason: 'tx_in_progress' };
    }

    // On a quota-exhausted error, best-effort sync current account's latest quota snapshot before leaving
    let latestAccounts = index.accounts;
    if (quotaError) {
      const freshNow = await fetchLiveQuotaNormalized().catch(() => null);
      if (freshNow) {
        await syncActiveAccountQuotaFromLive(
          { ok: true, ...freshNow },
          { skipAutoSwitch: true },
        ).catch(() => {});
        const refreshedIndex = await readIndex();
        latestAccounts = refreshedIndex.accounts;
      }
    }

    const best = selectBestAutoSwitchCandidate(latestAccounts, {
      currentEmail: liveEmail,
      targetGroupKey,
      nowMs,
    });
    if (!best) {
      if (quotaError?.errorKey) {
        await recordAutoSwitchStatePatch({ handledErrorKey: quotaError.errorKey }).catch(() => {});
      }
      const reasonLabel =
        triggerReason === 'quota_error'
          ? '检测到额度为空报错'
          : triggerReason === 'weekly'
            ? '当前账号周额度已耗尽'
            : '当前账号 5h 额度已耗尽';
      lastAutoSwitchResult = {
        ok: false,
        reason: 'no_eligible_candidate',
        triggerReason,
        targetGroup: targetGroupKey,
        fromEmail: liveEmail,
        message: `${reasonLabel}，但无符合条件的可用备用号（已跳过禁用号及 5h/周额度为 0 的账号）`,
        atMs: nowMs,
      };
      return { triggered: false, reason: 'no_eligible_candidate' };
    }

    autoSwitchInFlight = true;
    lastAutoSwitchAtMs = nowMs;
    lastAutoSwitchFromEmail = cleanLiveEmail;
    // Persist handled error key & cooldown BEFORE launching detached switch daemon to guarantee zero restart loops
    await recordAutoSwitchStatePatch({
      handledErrorKey: quotaError?.errorKey || '',
      switchedAtMs: nowMs,
      fromEmail: cleanLiveEmail,
    }).catch(() => {});

    const extraResumeConversations =
      quotaError && (quotaError.resumeConvId || quotaError.convId)
        ? [{ id: quotaError.resumeConvId || quotaError.convId, title: quotaError.resumeTitle || '' }]
        : [];

    try {
      const res = await switchAccount({
        accountId: best.id,
        autoResume: true,
        skipPreQuotaCheck: true,
        extraResumeConversations,
      });
      if (res?.ok) {
        lastAutoSwitchResult = {
          ok: true,
          triggerReason,
          targetGroup: targetGroupKey,
          fromEmail: liveEmail,
          toEmail: best.email,
          ...(quotaError?.errorId ? { errorId: quotaError.errorId } : {}),
          atMs: nowMs,
        };
        return {
          triggered: true,
          triggerReason,
          targetGroup: targetGroupKey,
          targetEmail: best.email,
          targetAccountId: best.id,
        };
      }
      lastAutoSwitchResult = {
        ok: false,
        triggerReason,
        targetGroup: targetGroupKey,
        fromEmail: liveEmail,
        toEmail: best.email,
        message: res?.error || '自动切号失败',
        atMs: nowMs,
      };
      return { triggered: false, reason: 'switch_failed', error: res?.error };
    } finally {
      autoSwitchInFlight = false;
    }
  }

  /**
   * Keep the currently active account's cached quota fresh whenever general quota cards refresh,
   * and trigger auto-switch when the configured target's 5h quota hits 0%.
   */
  async function syncActiveAccountQuotaFromLive(rawQuotaSummary, { skipAutoSwitch = false } = {}) {
    if (!rawQuotaSummary || !rawQuotaSummary.ok || !Array.isArray(rawQuotaSummary.groups)) {
      return false;
    }
    const normalized = normalizeStoredQuota(rawQuotaSummary, now());
    if (!normalized) return false;
    const liveInfo = await readLiveEmailSafe();
    if (!liveInfo.email) return false;

    const synced = await withStoreLock(async () => {
      const index = await readIndex();
      const target = index.accounts.find(
        (a) => sanitizeEmail(a.email) === liveInfo.email,
      );
      if (!target) return false;
      target.quota = normalized;
      target.updatedAtMs = now();
      index.activeAccountId = target.id;
      await writeIndex(index);
      return true;
    });

    if (!skipAutoSwitch) {
      void maybeTriggerAutoSwitch(liveInfo.email, normalized).catch(() => {});
    }
    return synced;
  }

  async function updateAccountSettings(patch = {}) {
    if (!patch || typeof patch !== 'object') {
      return { ok: false, status: 400, error: '设置参数格式无效' };
    }
    return withStoreLock(async () => {
      const index = await readIndex();
      const merged = normalizeAccountSettings({
        ...index.settings,
        ...patch,
      });
      index.settings = merged;
      await writeIndex(index);
      return { ok: true, settings: merged };
    });
  }

  function formatPublicAccount(acc, liveEmail, nowMs) {
    const isCurrent = Boolean(liveEmail && sanitizeEmail(acc.email) === liveEmail);
    return {
      id: acc.id,
      email: acc.email,
      remark: acc.remark || '',
      enabled: acc.enabled !== false,
      authMethod: acc.authMethod || 'oauth',
      source: acc.source || 'capture',
      isCurrent,
      createdAtMs: Number(acc.createdAtMs) || 0,
      updatedAtMs: Number(acc.updatedAtMs) || 0,
      lastUsedAtMs: Number(acc.lastUsedAtMs) || 0,
      quota: enrichQuotaWithResetStatus(acc.quota || null, nowMs),
    };
  }

  async function listAccounts() {
    const nowMs = now();
    const [index, liveInfo, backups] = await Promise.all([
      readIndex(),
      readLiveEmailSafe(),
      listBackups(),
    ]);

    const tx = readJsonFileSafe(paths.accountSwitchTxFile, null);
    const pendingResume = readJsonFileSafe(paths.accountPendingResumeFile, null);
    const pendingOauth = readJsonFileSafe(paths.accountPendingOauthFile, null);

    const activePendingResume =
      pendingResume &&
      !pendingResume.consumed &&
      nowMs - Number(pendingResume.createdAtMs || 0) <= Number(pendingResume.ttlMs || PENDING_RESUME_TTL_MS)
        ? {
            id: pendingResume.id,
            conversations: Array.isArray(pendingResume.conversations)
              ? pendingResume.conversations
              : pendingResume.conversationId
                ? [{ id: pendingResume.conversationId, title: pendingResume.conversationTitle || '' }]
                : [],
            targetEmail: pendingResume.targetEmail || '',
            createdAtMs: pendingResume.createdAtMs,
          }
        : null;

    const activePendingOauth =
      pendingOauth &&
      !pendingOauth.consumed &&
      nowMs - Number(pendingOauth.createdAtMs || 0) <= Number(pendingOauth.ttlMs || PENDING_OAUTH_TTL_MS)
        ? {
            id: pendingOauth.id,
            mode: pendingOauth.mode || 'watch',
            lastSeenEmail: pendingOauth.lastSeenEmail || pendingOauth.previousEmail || '',
            capturedEmails: Array.isArray(pendingOauth.capturedEmails) ? pendingOauth.capturedEmails : [],
            createdAtMs: pendingOauth.createdAtMs,
          }
        : null;

    const accounts = index.accounts.map((acc) => formatPublicAccount(acc, liveInfo.email, nowMs));

    return {
      ok: true,
      supported: activeDriver.isSupported(),
      dpapiProtected: activeDriver.isSupported(),
      currentEmail: liveInfo.email || '',
      hasLiveCredential: Boolean(liveInfo.found),
      accounts,
      settings: index.settings || {},
      backupCount: backups.length,
      lastTransaction: tx
        ? {
            id: tx.id || '',
            mode: tx.mode || 'switch',
            stage: tx.stage || '',
            targetEmail: tx.targetEmail || '',
            error: tx.error || '',
            updatedAtMs: tx.updatedAtMs || tx.startedAtMs || 0,
          }
        : null,
      pendingResume: activePendingResume,
      pendingOauth: activePendingOauth,
      lastResumeResult,
      lastOauthCaptureResult,
      lastAutoSwitchResult,
    };
  }

  /**
   * Capture the currently logged-in Antigravity account from Windows Credential Manager
   * + current live 3-category quota snapshot, sealed into DPAPI vault.
   */
  async function captureCurrentAccount({ remark = '', source = 'capture' } = {}) {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持原生凭据捕获（仅支持 Windows）' };
    }
    const live = await activeDriver.readLiveCredential();
    if (!live?.found || !live.credJson) {
      return {
        ok: false,
        status: 404,
        error: '未检测到当前已登录的 Antigravity 凭据，请先在 Antigravity 中登录账号',
      };
    }

    let parsedCred;
    try {
      parsedCred = JSON.parse(live.credJson);
    } catch {
      return { ok: false, status: 422, error: '当前系统凭据格式异常，无法解析 JSON' };
    }

    const norm = normalizeCredentialObject(parsedCred);
    if (!norm) {
      return { ok: false, status: 422, error: '当前系统凭据中缺少 refresh_token，无法保存' };
    }

    const email =
      norm.email ||
      `account-${crypto.createHash('sha1').update(norm.refreshToken).digest('hex').slice(0, 8)}@antigravity.local`;
    const liveQuota = await fetchLiveQuotaNormalized();
    const ts = now();

    return withStoreLock(async () => {
      const [index, vault] = await Promise.all([readIndex(), readVault()]);
      let existing = index.accounts.find((a) => sanitizeEmail(a.email) === email);
      const isNew = !existing;
      if (!existing) {
        existing = {
          id: `acc_${crypto.randomBytes(6).toString('hex')}`,
          email,
          remark: sanitizeRemark(remark),
          enabled: true,
          authMethod: norm.credObj.auth_method || 'oauth',
          source,
          createdAtMs: ts,
          updatedAtMs: ts,
          lastUsedAtMs: ts,
          quota: liveQuota,
        };
        index.accounts.unshift(existing);
      } else {
        existing.updatedAtMs = ts;
        existing.lastUsedAtMs = ts;
        existing.authMethod = norm.credObj.auth_method || existing.authMethod || 'oauth';
        if (remark && sanitizeRemark(remark)) {
          existing.remark = sanitizeRemark(remark);
        }
        if (liveQuota) {
          existing.quota = liveQuota;
        }
      }

      index.activeAccountId = existing.id;
      vault.secrets[existing.id] = {
        credTarget: live.credTarget || 'gemini:antigravity',
        credUserName: live.credUserName || 'antigravity',
        credPersist: Number(live.credPersist) || 2,
        credJson: live.credJson,
        credentialUserScope: live.credentialUserScope || '',
        capturedAtMs: ts,
      };

      await writeVault(vault);
      await writeIndex(index);

      return {
        ok: true,
        isNew,
        account: formatPublicAccount(existing, email, ts),
      };
    });
  }

  /**
   * Import one or many accounts from Token / JSON text, sealed into DPAPI vault.
   */
  async function importAccounts({ rawInput, email = '', remark = '' } = {}) {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持 DPAPI 安全入库（仅支持 Windows）' };
    }
    const parsed = parseImportPayload(rawInput, {
      fallbackEmail: email,
      fallbackRemark: remark,
    });
    if (!parsed.ok) return parsed;

    const liveInfo = await readLiveEmailSafe();
    const ts = now();

    return withStoreLock(async () => {
      const [index, vault] = await Promise.all([readIndex(), readVault()]);
      let addedCount = 0;
      let updatedCount = 0;
      const imported = [];

      for (const item of parsed.items) {
        let existing = index.accounts.find((a) => sanitizeEmail(a.email) === sanitizeEmail(item.email));
        if (!existing) {
          existing = {
            id: `acc_${crypto.randomBytes(6).toString('hex')}`,
            email: item.email,
            remark: item.remark || '',
            enabled: item.enabled !== false,
            authMethod: item.authMethod || 'oauth',
            source: 'import',
            createdAtMs: ts,
            updatedAtMs: ts,
            lastUsedAtMs: 0,
            quota: item.quota || null,
          };
          index.accounts.push(existing);
          addedCount += 1;
        } else {
          existing.updatedAtMs = ts;
          if (item.remark) existing.remark = item.remark;
          if (item.quota && !existing.quota) existing.quota = item.quota;
          updatedCount += 1;
        }

        vault.secrets[existing.id] = {
          credTarget: item.credTarget || 'gemini:antigravity',
          credUserName: item.credUserName || 'antigravity',
          credPersist: Number(item.credPersist) || 2,
          credJson: item.credJson,
          credentialUserScope: item.credentialUserScope || '',
          capturedAtMs: ts,
        };
        imported.push(formatPublicAccount(existing, liveInfo.email, ts));
      }

      await writeVault(vault);
      await writeIndex(index);

      return {
        ok: true,
        addedCount,
        updatedCount,
        totalImported: imported.length,
        accounts: imported,
      };
    });
  }

  async function toggleAccountEnabled(accountId, enabled) {
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    const liveInfo = await readLiveEmailSafe();
    const ts = now();

    return withStoreLock(async () => {
      const index = await readIndex();
      const acc = index.accounts.find((a) => a.id === id);
      if (!acc) return { ok: false, status: 404, error: '目标账号不存在' };
      acc.enabled = enabled === undefined ? !(acc.enabled !== false) : Boolean(enabled);
      acc.updatedAtMs = ts;
      await writeIndex(index);
      return { ok: true, account: formatPublicAccount(acc, liveInfo.email, ts) };
    });
  }

  async function updateAccountRemark(accountId, remark) {
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    const liveInfo = await readLiveEmailSafe();
    const ts = now();

    return withStoreLock(async () => {
      const index = await readIndex();
      const acc = index.accounts.find((a) => a.id === id);
      if (!acc) return { ok: false, status: 404, error: '目标账号不存在' };
      acc.remark = sanitizeRemark(remark);
      acc.updatedAtMs = ts;
      await writeIndex(index);
      return { ok: true, account: formatPublicAccount(acc, liveInfo.email, ts) };
    });
  }

  async function deleteAccount(accountId) {
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    return withStoreLock(async () => {
      const [index, vault] = await Promise.all([readIndex(), readVault()]);
      const before = index.accounts.length;
      index.accounts = index.accounts.filter((a) => a.id !== id);
      if (index.accounts.length === before) {
        return { ok: false, status: 404, error: '目标账号不存在' };
      }
      delete vault.secrets[id];
      if (index.activeAccountId === id) {
        index.activeAccountId = '';
      }
      await writeVault(vault);
      await writeIndex(index);
      return { ok: true, deletedId: id };
    });
  }

  async function exportAccountJson(accountId) {
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    const [index, vault] = await Promise.all([readIndex(), readVault()]);
    const acc = index.accounts.find((a) => a.id === id);
    if (!acc) return { ok: false, status: 404, error: '目标账号不存在' };

    const secret = vault.secrets[id];
    if (!secret || !secret.credJson) {
      return { ok: false, status: 404, error: '加密保险库中未找到该账号凭证' };
    }

    let credObj;
    try {
      credObj = JSON.parse(secret.credJson);
    } catch {
      return { ok: false, status: 500, error: '该账号凭证数据已损坏' };
    }

    const exported = {
      schema: ACCOUNT_EXPORT_SCHEMA,
      exportedAt: new Date(now()).toISOString(),
      email: acc.email,
      remark: acc.remark || '',
      enabled: acc.enabled !== false,
      credTarget: secret.credTarget || 'gemini:antigravity',
      credUserName: secret.credUserName || 'antigravity',
      credPersist: Number(secret.credPersist) || 2,
      credentialUserScope: secret.credentialUserScope || '',
      credential: credObj,
      ...(acc.quota ? { quota: acc.quota } : {}),
    };

    return {
      ok: true,
      filename: `agy-account-${acc.email.replace(/[^a-zA-Z0-9._-]+/g, '_')}.json`,
      jsonText: JSON.stringify(exported, null, 2),
      data: exported,
    };
  }

  async function refreshAccountQuota(accountId) {
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    const nowMs = now();
    const liveInfo = await readLiveEmailSafe();

    // Snapshot account & secret without holding storeLock across network I/O
    const snap = await withStoreLock(async () => {
      const [index, vault] = await Promise.all([readIndex(), readVault()]);
      const acc = index.accounts.find((a) => a.id === id);
      if (!acc) return { missing: true };
      const secret = vault?.secrets?.[acc.id] || null;
      return {
        missing: false,
        email: acc.email,
        projectId: typeof acc.projectId === 'string' ? acc.projectId : '',
        hasQuota: Boolean(acc.quota),
        secretCredJson: typeof secret?.credJson === 'string' ? secret.credJson : '',
      };
    });

    if (snap.missing) {
      return { ok: false, status: 404, error: '目标账号不存在' };
    }

    const isCurrent = Boolean(liveInfo.email && sanitizeEmail(snap.email) === liveInfo.email);
    if (isCurrent) {
      const freshQuota = await fetchLiveQuotaNormalized();
      if (freshQuota) {
        return withStoreLock(async () => {
          const index = await readIndex();
          const acc = index.accounts.find((a) => a.id === id);
          if (!acc) return { ok: false, status: 404, error: '目标账号不存在' };
          acc.quota = freshQuota;
          acc.updatedAtMs = nowMs;
          index.activeAccountId = acc.id;
          await writeIndex(index);
          return {
            ok: true,
            mode: 'live',
            message: `已实时同步 ${acc.email} 的官方三类额度`,
            account: formatPublicAccount(acc, liveInfo.email, nowMs),
          };
        });
      }
    }

    // Remote real-time OAuth + CloudCode quota fetch (Cockpit Tools compatible)
    let parsedCred = null;
    if (snap.secretCredJson) {
      try {
        parsedCred = JSON.parse(snap.secretCredJson);
      } catch {
        parsedCred = null;
      }
    }
    if (!parsedCred || !extractRefreshToken(parsedCred)) {
      return withStoreLock(async () => {
        const index = await readIndex();
        const acc = index.accounts.find((a) => a.id === id);
        return {
          ok: false,
          status: 422,
          error: '该账号缺少有效的 OAuth 凭据，请重新授权或导入后再刷新额度',
          account: acc ? formatPublicAccount(acc, liveInfo.email, nowMs) : null,
        };
      });
    }

    let remote;
    try {
      remote = await activeRemoteQuotaFetcher(parsedCred, {
        cachedProjectId: snap.projectId,
        nowMs,
      });
    } catch (err) {
      return withStoreLock(async () => {
        const index = await readIndex();
        const acc = index.accounts.find((a) => a.id === id);
        return {
          ok: false,
          status: Number(err?.status) || 502,
          error: err?.message || `同步 ${snap.email} 官方额度失败`,
          account: acc ? formatPublicAccount(acc, liveInfo.email, nowMs) : null,
        };
      });
    }

    if (!remote?.ok || !remote.quota) {
      return withStoreLock(async () => {
        const index = await readIndex();
        const acc = index.accounts.find((a) => a.id === id);
        return {
          ok: false,
          status: 502,
          error: `未能获取 ${snap.email} 的有效官方配额数据`,
          account: acc ? formatPublicAccount(acc, liveInfo.email, nowMs) : null,
        };
      });
    }

    return withStoreLock(async () => {
      const [index, vault] = await Promise.all([readIndex(), readVault()]);
      const acc = index.accounts.find((a) => a.id === id);
      if (!acc) return { ok: false, status: 404, error: '目标账号不存在' };

      acc.quota = normalizeStoredQuota(remote.quota, nowMs);
      if (remote.projectId) {
        acc.projectId = remote.projectId;
      }
      acc.updatedAtMs = nowMs;

      if (remote.renewed && remote.updatedCredObj && vault?.secrets?.[acc.id]) {
        vault.secrets[acc.id] = {
          ...vault.secrets[acc.id],
          credJson: JSON.stringify(remote.updatedCredObj),
        };
        await writeVault(vault);
      }
      await writeIndex(index);

      return {
        ok: true,
        mode: 'remote_oauth',
        source: remote.source || 'cloudcode',
        message: `已实时同步 ${acc.email} 的官方三类额度`,
        account: formatPublicAccount(acc, liveInfo.email, nowMs),
      };
    });
  }

  async function resolveRunningConversationsSnapshot() {
    if (typeof getRunningConversations !== 'function') return [];
    try {
      const rawList = await Promise.resolve(getRunningConversations());
      if (!Array.isArray(rawList)) return [];
      const dedup = new Map();
      for (const item of rawList) {
        if (!item || typeof item !== 'object') continue;
        // Strictly allow ONLY genuinely running conversations (never finished/idle/viewed ones)
        if (item.status && item.status !== 'running') continue;
        const cid = String(item.id || '').trim();
        if (!cid || dedup.has(cid)) continue;
        dedup.set(cid, {
          id: cid,
          title: String(item.title || '').trim().slice(0, 120),
        });
      }
      return Array.from(dedup.values());
    } catch {
      return [];
    }
  }

  /**
   * Trigger detached offline switch to a stored account, automatically resuming
   * ONLY conversations that were genuinely running at switch time.
   */
  async function switchAccount({
    accountId,
    autoResume = true,
    resumePrompt = DEFAULT_RESUME_PROMPT,
    skipPreQuotaCheck = false,
    extraResumeConversations = [],
  } = {}) {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持自动切号重启（仅支持 Windows）' };
    }
    const id = String(accountId || '').trim();
    if (!id) return { ok: false, status: 400, error: 'accountId 不能为空' };

    const ts = now();
    await ensureDirs();

    // Pre-switch: snapshot live quota of current account so we don't lose its latest remaining %
    if (!skipPreQuotaCheck) {
      const currentLiveQuota = await fetchLiveQuotaNormalized();
      if (currentLiveQuota) {
        await syncActiveAccountQuotaFromLive(
          { ok: true, ...currentLiveQuota },
          { skipAutoSwitch: true },
        ).catch(() => {});
      }
    }

    const [index, vault, liveInfo, activeRunningConversations] = await Promise.all([
      readIndex(),
      readVault(),
      readLiveEmailSafe(),
      autoResume ? resolveRunningConversationsSnapshot() : Promise.resolve([]),
    ]);

    const resumeDedup = new Map();
    for (const item of activeRunningConversations) {
      if (item && item.id) resumeDedup.set(item.id, item);
    }
    if (autoResume && Array.isArray(extraResumeConversations)) {
      for (const item of extraResumeConversations) {
        const cid = String(item?.id || '').trim();
        if (!cid || resumeDedup.has(cid)) continue;
        resumeDedup.set(cid, {
          id: cid,
          title: String(item?.title || '').trim().slice(0, 120),
        });
      }
    }
    const runningConversations = Array.from(resumeDedup.values());

    const target = index.accounts.find((a) => a.id === id);
    if (!target) {
      return { ok: false, status: 404, error: '目标账号不存在' };
    }
    if (target.enabled === false) {
      return { ok: false, status: 400, error: '该账号当前已禁用，请先启用后再切换' };
    }

    const secret = vault.secrets[id];
    if (!secret || !secret.credJson) {
      return { ok: false, status: 422, error: '目标账号凭证缺失，无法切换' };
    }

    let parsedTargetCred;
    try {
      parsedTargetCred = JSON.parse(secret.credJson);
    } catch {
      return { ok: false, status: 422, error: '目标账号凭证 JSON 损坏，已中止切换' };
    }
    if (!extractRefreshToken(parsedTargetCred)) {
      return { ok: false, status: 422, error: '目标账号缺少有效的 refresh_token，已中止切换' };
    }

    // Also ensure current account is safely backed up inside vault or backup dir before leaving
    const launchCfg = await activeDriver.detectAntigravityLaunchConfig();
    if (!launchCfg?.exePath) {
      return { ok: false, status: 500, error: '未定位到 Antigravity.exe 路径，无法自动重启' };
    }

    const txId = `tx_${ts}_${crypto.randomBytes(4).toString('hex')}`;
    const backupFile = path.join(paths.accountsBackupsDir, `pre_switch_${ts}_${txId.slice(-6)}.bak.dat`);
    const payloadFile = path.join(paths.accountsDir, `switch_payload_${txId}.dat`);

    // Seal one-time switch payload with DPAPI so plaintext token never touches disk
    const sealedPayload = await activeDriver.protectSecret(
      JSON.stringify({
        credTarget: secret.credTarget || 'gemini:antigravity',
        credUserName: secret.credUserName || 'antigravity',
        credPersist: Number(secret.credPersist) || 2,
        credJson: secret.credJson,
        credentialUserScope: secret.credentialUserScope || '',
      }),
    );
    await atomicWriteText(payloadFile, sealedPayload);

    // Record At-Most-Once pending resume ONLY when genuinely running conversations exist
    const cleanPrompt = String(resumePrompt || DEFAULT_RESUME_PROMPT).trim() || DEFAULT_RESUME_PROMPT;
    if (autoResume && runningConversations.length > 0) {
      await atomicWriteJson(paths.accountPendingResumeFile, {
        id: `resume_${txId}`,
        transactionId: txId,
        conversations: runningConversations,
        prompt: cleanPrompt.slice(0, 4000),
        targetAccountId: target.id,
        targetEmail: target.email,
        createdAtMs: ts,
        ttlMs: PENDING_RESUME_TTL_MS,
        consumed: false,
      });
    } else {
      await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});
    }

    // Update target lastUsedAtMs
    await withStoreLock(async () => {
      const freshIndex = await readIndex();
      const item = freshIndex.accounts.find((a) => a.id === id);
      if (item) {
        item.lastUsedAtMs = ts;
        item.updatedAtMs = ts;
        freshIndex.activeAccountId = id;
        await writeIndex(freshIndex);
      }
    });

    const txData = {
      id: txId,
      mode: 'switch',
      stage: 'queued',
      targetAccountId: target.id,
      targetEmail: target.email,
      previousEmail: liveInfo.email || '',
      roamingDir: activeDriver.getRoamingDir(),
      antigravityExe: launchCfg.exePath,
      launchArgs: launchCfg.launchArgs || '',
      workDir: launchCfg.workDir || '',
      payloadFile,
      backupFile,
      startedAtMs: ts,
      updatedAtMs: ts,
    };
    await atomicWriteJson(paths.accountSwitchTxFile, txData);
    void pruneBackups();

    // Restore host window opacity before closing so backdrop companion never leaves a translucent ghost
    if (typeof onBeforeHostClose === 'function') {
      await Promise.resolve(onBeforeHostClose()).catch(() => {});
    } else {
      await restoreHostOpacityFallback(paths).catch(() => {});
    }

    await activeDriver.launchSwitchDaemon(paths.accountSwitchTxFile);

    return {
      ok: true,
      switching: true,
      transactionId: txId,
      targetEmail: target.email,
      autoResumeScheduled: runningConversations.length > 0,
      autoResumeCount: runningConversations.length,
    };
  }

  /**
   * Non-destructive OAuth new-account watch mode (NEVER closes or kills Antigravity):
   * 1. Immediately captures & seals the currently signed-in account so it is never lost.
   * 2. Enables a 10-minute background credential watcher (`pending_oauth_capture.json`).
   * 3. Whenever the user signs into a new Google account via Antigravity's native OAuth flow,
   *    the watcher detects the credential change within ~1.5s and seals it automatically.
   */
  async function startOauthWatch() {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持原生 OAuth 凭据捕获（仅支持 Windows）' };
    }

    const ts = now();
    await ensureDirs();

    let capturedCurrent = null;
    const liveInfo = await readLiveEmailSafe();
    if (liveInfo.found) {
      const capRes = await captureCurrentAccount({ source: 'capture' }).catch(() => null);
      if (capRes?.ok) {
        capturedCurrent = capRes.account;
      }
    }

    const watchId = `watch_${ts}_${crypto.randomBytes(4).toString('hex')}`;
    await atomicWriteJson(paths.accountPendingOauthFile, {
      id: watchId,
      mode: 'watch',
      previousEmail: liveInfo.email || '',
      lastSeenEmail: liveInfo.email || '',
      capturedEmails: [],
      createdAtMs: ts,
      ttlMs: PENDING_OAUTH_TTL_MS,
      consumed: false,
    });

    return {
      ok: true,
      watching: true,
      watchId,
      previousEmail: liveInfo.email || '',
      capturedCurrent,
    };
  }

  async function stopOauthWatch() {
    await fsp.rm(paths.accountPendingOauthFile, { force: true }).catch(() => {});
    return { ok: true, watching: false };
  }

  async function cancelDirectBrowserOauth() {
    if (!activeDirectOauth) {
      return { ok: true, active: false };
    }
    const session = activeDirectOauth;
    activeDirectOauth = null;
    session.status = 'cancelled';
    try {
      session.server?.closeAllConnections?.();
      session.server?.close?.();
    } catch {}
    return { ok: true, cancelled: true };
  }

  function getDirectBrowserOauthStatus() {
    if (!activeDirectOauth) {
      return { ok: true, status: 'idle', active: false };
    }
    const nowMs = now();
    if (nowMs - activeDirectOauth.startedAtMs > activeDirectOauth.timeoutMs) {
      cancelDirectBrowserOauth();
      return { ok: true, status: 'timeout', error: 'OAuth 认证超时，请重新点击授权' };
    }
    return {
      ok: true,
      status: activeDirectOauth.status,
      authUrl: activeDirectOauth.authUrl,
      error: activeDirectOauth.error || null,
      result: activeDirectOauth.result || null,
    };
  }

  async function startDirectBrowserOauth({ remark = '' } = {}, deps = {}) {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持 DPAPI 安全入库（仅支持 Windows）' };
    }

    if (activeDirectOauth) {
      await cancelDirectBrowserOauth();
    }

    const oauthClient = deps.oauthClient || (await discoverLocalOAuthClient());
    if (!oauthClient?.clientId || !oauthClient?.clientSecret) {
      return {
        ok: false,
        status: 500,
        error:
          '未能从本机 Antigravity 客户端读取 OAuth 配置，请确认已安装 Antigravity 或配置 ANTIGRAVITY_OAUTH_CLIENT_ID / ANTIGRAVITY_OAUTH_CLIENT_SECRET',
      };
    }
    const clientId = oauthClient.clientId;
    const clientSecret = oauthClient.clientSecret;
    const candidateSecrets = oauthClient.candidateSecrets || [clientSecret];
    const state = crypto.randomBytes(32).toString('base64url');
    const { codeVerifier, codeChallenge } = generatePkce();
    const startedAtMs = now();
    const timeoutMs = 180_000;

    const session = {
      state,
      codeVerifier,
      remark: sanitizeRemark(remark),
      startedAtMs,
      timeoutMs,
      status: 'waiting_user_auth',
      callbackHandled: false,
      authUrl: '',
      server: null,
      port: 0,
      result: null,
      error: null,
    };
    activeDirectOauth = session;

    const httpModule = deps.http || http;
    const fetchImpl = deps.fetch || proxyAwareFetch;
    const openExternal = deps.openExternal || openExternalUrl;

    const closeCallbackServer = () => {
      try {
        server.closeAllConnections?.();
        server.close();
      } catch {}
    };

    const sendHtmlResponse = (res, statusCode, html, shouldCloseServer = false) => {
      res.writeHead(statusCode, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        Connection: 'close',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(html, () => {
        if (shouldCloseServer) {
          closeCallbackServer();
        }
      });
    };

    const server = httpModule.createServer(async (req, res) => {
      let reqUrl;
      try {
        reqUrl = new URL(req.url || '/', `http://${req.headers?.host || '127.0.0.1'}`);
      } catch {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Bad Request');
        return;
      }

      if (req.method !== 'GET' || reqUrl.pathname !== '/oauth-callback') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
      }

      const callbackState = reqUrl.searchParams.get('state') || '';
      const code = reqUrl.searchParams.get('code') || '';
      const oauthError = reqUrl.searchParams.get('error') || '';

      if (callbackState !== session.state) {
        sendHtmlResponse(res, 403, renderOauthErrorHtml('无效或过期的 OAuth State 状态码'), false);
        return;
      }

      if (session.callbackHandled) {
        if (session.status === 'success') {
          sendHtmlResponse(res, 200, renderOauthSuccessHtml(session.result?.account?.email || ''), false);
        } else {
          sendHtmlResponse(res, 409, renderOauthErrorHtml(session.error || '授权回调正在处理中，请勿重复刷新'), false);
        }
        return;
      }
      session.callbackHandled = true;

      if (oauthError) {
        session.status = 'error';
        session.error = `Google 授权失败或被用户拒绝: ${oauthError}`;
        sendHtmlResponse(res, 400, renderOauthErrorHtml(session.error), true);
        return;
      }

      if (!code) {
        session.status = 'error';
        session.error = '未收到 Google 授权码 (Authorization Code)';
        sendHtmlResponse(res, 400, renderOauthErrorHtml(session.error), true);
        return;
      }

      session.status = 'exchanging_token';
      try {
        const redirectUri = `http://127.0.0.1:${session.port}/oauth-callback`;
        const tokenPayload = await exchangeOAuthCode(
          {
            code,
            codeVerifier: session.codeVerifier,
            redirectUri,
            clientId,
            clientSecret,
            candidateSecrets,
          },
          fetchImpl,
        );

        const profile = await fetchGoogleProfile(tokenPayload.access_token, fetchImpl);
        let email = sanitizeEmail(profile?.email || '');
        if (!email && tokenPayload.id_token) {
          email = sanitizeEmail(extractEmailFromCred({ id_token: tokenPayload.id_token }));
        }
        if (!email) {
          email = `google-account-${crypto
            .createHash('sha1')
            .update(tokenPayload.refresh_token || 'antigravity')
            .digest('hex')
            .slice(0, 8)}@gmail.com`;
        }

        const expiryIso = new Date(
          Date.now() + (Number(tokenPayload.expires_in) || 3600) * 1000,
        ).toISOString();
        const norm = normalizeCredentialObject(
          {
            token: {
              access_token: tokenPayload.access_token || '',
              refresh_token: tokenPayload.refresh_token || '',
              token_type: tokenPayload.token_type || 'Bearer',
              expiry: expiryIso,
              expires_in: Number(tokenPayload.expires_in) || 3600,
              id_token: tokenPayload.id_token || '',
            },
            auth_method: 'consumer',
            id_token_email: email,
          },
          email,
        );

        if (!norm) {
          throw new Error('Google 未返回有效的 refresh_token');
        }

        const ts = now();
        const liveInfo = await readLiveEmailSafe();
        let savedAccount = null;
        let isNew = false;

        await withStoreLock(async () => {
          const [index, vault] = await Promise.all([readIndex(), readVault()]);
          let existing = index.accounts.find((a) => sanitizeEmail(a.email) === email);
          isNew = !existing;
          if (!existing) {
            existing = {
              id: `acc_${crypto.randomBytes(6).toString('hex')}`,
              email,
              remark: sanitizeRemark(session.remark),
              enabled: true,
              authMethod: norm.credObj.auth_method || 'consumer',
              source: 'oauth',
              createdAtMs: ts,
              updatedAtMs: ts,
              lastUsedAtMs: 0,
              quota: null,
            };
            index.accounts.push(existing);
          } else {
            existing.updatedAtMs = ts;
            existing.authMethod = norm.credObj.auth_method || 'consumer';
            if (session.remark && sanitizeRemark(session.remark)) {
              existing.remark = sanitizeRemark(session.remark);
            }
          }

          vault.secrets[existing.id] = {
            credTarget: 'gemini:antigravity',
            credUserName: 'antigravity',
            credPersist: 2,
            credJson: JSON.stringify(norm.credObj),
            credentialUserScope: '',
            capturedAtMs: ts,
          };

          await writeVault(vault);
          await writeIndex(index);
          savedAccount = formatPublicAccount(existing, liveInfo.email, ts);
        });

        session.status = 'success';
        session.result = {
          ok: true,
          isNew,
          account: savedAccount,
        };

        sendHtmlResponse(res, 200, renderOauthSuccessHtml(savedAccount?.email || email), true);

        if (savedAccount && allowBackgroundRemoteRefresh) {
          void refreshAccountQuota(savedAccount.id).catch(() => {});
        }
      } catch (err) {
        session.status = 'error';
        session.error = err?.message || '换取或保存 Google 账号凭据失败';
        sendHtmlResponse(res, 502, renderOauthErrorHtml(session.error), true);
      }
    });

    session.server = server;

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        session.port = typeof address === 'object' && address ? address.port : 0;
        resolve();
      });
    });

    const redirectUri = `http://127.0.0.1:${session.port}/oauth-callback`;
    const authUrl = buildAuthorizationUrl({
      clientId,
      redirectUri,
      state,
      codeChallenge,
    });
    session.authUrl = authUrl;

    try {
      openExternal(authUrl);
    } catch {}

    return {
      ok: true,
      status: 'waiting_user_auth',
      authUrl,
      port: session.port,
    };
  }

  /**
   * Emergency offline rollback to the most recent pre-switch DPAPI backup snapshot.
   */
  async function rollbackLatestBackup() {
    if (!activeDriver.isSupported()) {
      return { ok: false, status: 501, error: '当前系统不支持原生回滚（仅支持 Windows）' };
    }
    const backups = await listBackups();
    if (backups.length === 0) {
      return { ok: false, status: 404, error: '暂无可回滚的切号备份快照' };
    }
    const launchCfg = await activeDriver.detectAntigravityLaunchConfig();
    if (!launchCfg?.exePath) {
      return { ok: false, status: 500, error: '未定位到 Antigravity.exe 路径' };
    }

    const ts = now();
    const txId = `rb_${ts}_${crypto.randomBytes(4).toString('hex')}`;
    await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});

    const txData = {
      id: txId,
      mode: 'rollback',
      stage: 'queued',
      targetAccountId: '',
      targetEmail: '',
      roamingDir: activeDriver.getRoamingDir(),
      antigravityExe: launchCfg.exePath,
      launchArgs: launchCfg.launchArgs || '',
      workDir: launchCfg.workDir || '',
      restoreBackupFile: backups[0].path,
      startedAtMs: ts,
      updatedAtMs: ts,
    };
    await atomicWriteJson(paths.accountSwitchTxFile, txData);

    if (typeof onBeforeHostClose === 'function') {
      await Promise.resolve(onBeforeHostClose()).catch(() => {});
    } else {
      await restoreHostOpacityFallback(paths).catch(() => {});
    }

    await activeDriver.launchSwitchDaemon(paths.accountSwitchTxFile);
    return { ok: true, rollingBack: true, backupName: backups[0].name, transactionId: txId };
  }

  async function cancelPendingResume() {
    await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});
    return { ok: true };
  }

  /**
   * One tick of post-restart lifecycle coordinator:
   * - Auto-captures newly signed-in OAuth account if `pending_oauth_capture.json` is active
   * - Waits for new account quota RPC readiness, then At-Most-Once dispatches `pending_resume.json`
   */
  async function runLifecycleTick() {
    if (watcherBusy) return;
    watcherBusy = true;
    try {
      const nowMs = now();

      // 1. Live non-destructive OAuth credential watcher (supports capturing multiple new logins continuously)
      const pendingOauth = readJsonFileSafe(paths.accountPendingOauthFile, null);
      if (pendingOauth && !pendingOauth.consumed) {
        const age = nowMs - Number(pendingOauth.createdAtMs || 0);
        if (age > Number(pendingOauth.ttlMs || PENDING_OAUTH_TTL_MS)) {
          await fsp.rm(paths.accountPendingOauthFile, { force: true }).catch(() => {});
        } else {
          const liveInfo = await readLiveEmailSafe();
          const lastSeen = sanitizeEmail(pendingOauth.lastSeenEmail || pendingOauth.previousEmail || '');
          if (liveInfo.found && liveInfo.email && liveInfo.email !== lastSeen) {
            const cap = await captureCurrentAccount({ source: 'oauth' }).catch(() => null);
            const prevCaptured = Array.isArray(pendingOauth.capturedEmails) ? pendingOauth.capturedEmails : [];
            const nextCaptured = prevCaptured.includes(liveInfo.email)
              ? prevCaptured
              : [...prevCaptured, liveInfo.email];
            await atomicWriteJson(paths.accountPendingOauthFile, {
              ...pendingOauth,
              lastSeenEmail: liveInfo.email,
              capturedEmails: nextCaptured,
              updatedAtMs: nowMs,
            }).catch(() => {});
            if (cap?.ok) {
              lastOauthCaptureResult = {
                ok: true,
                email: cap.account?.email || liveInfo.email,
                capturedAtMs: nowMs,
              };
            }
          }
        }
      }

      // 2. Pending At-Most-Once session auto-resume after account switch (ONLY genuinely running conversations)
      const pendingResume = readJsonFileSafe(paths.accountPendingResumeFile, null);
      if (pendingResume && !pendingResume.consumed) {
        const age = nowMs - Number(pendingResume.createdAtMs || 0);
        if (age > Number(pendingResume.ttlMs || PENDING_RESUME_TTL_MS)) {
          await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});
        } else {
          const targets = Array.isArray(pendingResume.conversations)
            ? pendingResume.conversations.filter((c) => c && c.id)
            : pendingResume.conversationId
              ? [{ id: pendingResume.conversationId, title: pendingResume.conversationTitle || '' }]
              : [];

          if (targets.length === 0) {
            await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});
          } else {
            // Wait until local language_server confirms the switched account is authenticated & ready
            const liveQuota = await fetchLiveQuotaNormalized();
            if (liveQuota) {
              const liveInfo = await readLiveEmailSafe();
              const targetEmail = sanitizeEmail(pendingResume.targetEmail || '');
              if (!targetEmail || !liveInfo.email || liveInfo.email === targetEmail) {
                // STRICT At-Most-Once: mark consumed & remove file BEFORE dispatching any message
                await atomicWriteJson(paths.accountPendingResumeFile, {
                  ...pendingResume,
                  consumed: true,
                  consumedAtMs: nowMs,
                }).catch(() => {});
                await fsp.rm(paths.accountPendingResumeFile, { force: true }).catch(() => {});

                // Sync fresh 3-category quota onto the newly activated account
                await syncActiveAccountQuotaFromLive(
                  { ok: true, ...liveQuota },
                  { skipAutoSwitch: true },
                ).catch(() => {});

                if (sidecarBridge && typeof sidecarBridge.sendMessage === 'function') {
                  const resumedIds = [];
                  let lastErr = '';
                  for (const conv of targets) {
                    try {
                      await Promise.resolve(
                        sidecarBridge.sendMessage(conv.id, pendingResume.prompt),
                      );
                      resumedIds.push(conv.id);
                    } catch (err) {
                      lastErr = err?.message || '自动恢复会话发送失败';
                    }
                  }
                  lastResumeResult = {
                    ok: resumedIds.length > 0,
                    resumedCount: resumedIds.length,
                    conversationIds: resumedIds,
                    targetEmail: liveInfo.email || targetEmail,
                    ...(lastErr && resumedIds.length === 0 ? { error: lastErr } : {}),
                    resumedAtMs: nowMs,
                  };
                }
              }
            }
          }
        }
      }
      // 3. Fast quota-exhausted error watcher (detects `step_type = 17` QUOTA_EXHAUSTED in conversations/*.db)
      // Checked BEFORE scheduled bucket switch so a halted conversation is always captured for auto-resume.
      const indexForSchedule = await readIndex();
      const settings = normalizeAccountSettings(indexForSchedule.settings);
      let switchedThisTick = false;

      if (
        settings.autoSwitchEnabled &&
        indexForSchedule.accounts.length > 1 &&
        paths?.conversationsDir
      ) {
        const persistedState = normalizeAutoSwitchState(indexForSchedule.autoSwitchState);
        const lastTx = readJsonFileSafe(paths.accountSwitchTxFile, null);
        const minErrorAtMs = Math.max(
          persistedState.lastAutoSwitchAtMs,
          Number(lastTx?.startedAtMs || 0),
        );
        const quotaErr = await detectRecentQuotaExhaustedError(paths.conversationsDir, {
          nowMs,
          minCreatedAtMs: minErrorAtMs,
          handledErrorKeys: new Set(persistedState.handledErrorIds),
          fileStampCache: quotaErrorFileStampCache,
          summariesDbPath: paths.summariesDbPath || '',
        }).catch(() => null);

        if (quotaErr) {
          const liveInfo = await readLiveEmailSafe();
          if (liveInfo.email) {
            const errSw = await maybeTriggerAutoSwitch(liveInfo.email, null, {
              quotaError: quotaErr,
            }).catch(() => null);
            if (errSw?.triggered) switchedThisTick = true;
          }
        }
      }

      // 4. Scheduled automatic quota refresh + 5h/weekly-exhausted auto-switch check
      const refreshIntervalMs = settings.quotaRefreshIntervalMin * 60 * 1000;
      const shouldAutoRefresh =
        !switchedThisTick &&
        refreshIntervalMs > 0 &&
        (lastAutoRefreshAtMs === 0 || nowMs - lastAutoRefreshAtMs >= refreshIntervalMs);
      if (shouldAutoRefresh && indexForSchedule.accounts.length > 0) {
        lastAutoRefreshAtMs = nowMs;
        const liveInfo = await readLiveEmailSafe();
        const freshQuota = await fetchLiveQuotaNormalized();
        if (freshQuota && liveInfo.email) {
          await syncActiveAccountQuotaFromLive(
            { ok: true, ...freshQuota },
            { skipAutoSwitch: true },
          ).catch(() => {});
        }
        // Also refresh stale enabled inactive accounts via Cockpit Tools OAuth CloudCode API
        if (allowBackgroundRemoteRefresh) {
          for (const acc of indexForSchedule.accounts) {
            if (!acc || acc.enabled === false) continue;
            if (liveInfo.email && sanitizeEmail(acc.email) === liveInfo.email) continue;
            const fetchedAt = Number(acc.quota?.fetchedAtMs || 0);
            if (!fetchedAt || nowMs - fetchedAt >= refreshIntervalMs) {
              await refreshAccountQuota(acc.id).catch(() => {});
            }
          }
        }
        if (freshQuota && liveInfo.email) {
          await maybeTriggerAutoSwitch(liveInfo.email, freshQuota).catch(() => {});
        }
      }
    } finally {
      watcherBusy = false;
    }
  }

  function startLifecycleWatcher({ intervalMs = 2000 } = {}) {
    if (watcherTimer) return;
    void activeDriver.ensureReady?.().catch(() => {});
    // Run an initial delayed check once host finishes boot
    setTimeout(() => {
      void runLifecycleTick();
    }, 1500).unref?.();
    watcherTimer = setInterval(() => {
      void runLifecycleTick();
    }, intervalMs);
    watcherTimer.unref?.();
  }

  function stopLifecycleWatcher() {
    if (watcherTimer) {
      clearInterval(watcherTimer);
      watcherTimer = null;
    }
  }

  return {
    listAccounts,
    updateAccountSettings,
    captureCurrentAccount,
    importAccounts,
    toggleAccountEnabled,
    updateAccountRemark,
    deleteAccount,
    exportAccountJson,
    refreshAccountQuota,
    switchAccount,
    maybeTriggerAutoSwitch,
    startOauthWatch,
    stopOauthWatch,
    startOfficialOauthAdd: startOauthWatch,
    startDirectBrowserOauth,
    getDirectBrowserOauthStatus,
    cancelDirectBrowserOauth,
    rollbackLatestBackup,
    cancelPendingResume,
    syncActiveAccountQuotaFromLive,
    runLifecycleTick,
    startLifecycleWatcher,
    stopLifecycleWatcher,
  };
}
