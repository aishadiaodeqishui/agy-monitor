import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  clearCdpBridgeCaches,
  createCdpThemeBridge,
} from '../sidecars/agy_monitor/backend/cdp_theme_bridge.mjs';
import { resolvePaths } from '../sidecars/agy_monitor/backend/paths.mjs';
import {
  createHostLivenessWatcher,
  createSidecarOwnershipLease,
  parseLoopbackLsAddress,
} from '../sidecars/agy_monitor/backend/sidecar_lifecycle.mjs';
import { startSidecarServer } from '../sidecars/agy_monitor/main.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REAL_PLUGIN_ROOT = path.resolve(__dirname, '..');

async function getFreePort() {
  const srv = net.createServer();
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const { port } = srv.address();
  await new Promise((resolve) => srv.close(resolve));
  return port;
}

test('parseLoopbackLsAddress accepts loopback host:port/URLs and rejects non-loopback targets', () => {
  assert.deepEqual(parseLoopbackLsAddress('127.0.0.1:61251'), { host: '127.0.0.1', port: 61251 });
  assert.deepEqual(parseLoopbackLsAddress('http://localhost:8080'), { host: 'localhost', port: 8080 });
  assert.deepEqual(parseLoopbackLsAddress('https://[::1]:54321'), { host: '::1', port: 54321 });
  assert.equal(parseLoopbackLsAddress('192.168.1.10:8080'), null);
  assert.equal(parseLoopbackLsAddress('example.com:443'), null);
  assert.equal(parseLoopbackLsAddress('127.0.0.1'), null);
  assert.equal(parseLoopbackLsAddress(''), null);
});

test('createSidecarOwnershipLease detects superseding sidecar and preserves newer owner file on release', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-lease-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const paths = resolvePaths({
    appDataDir: path.join(root, 'agy'),
    geminiConfigDir: path.join(root, 'cfg'),
  });

  let supersededBy = null;
  const leaseA = createSidecarOwnershipLease(paths, {
    pid: 1001,
    port: 50001,
    pollIntervalMs: 50,
    onSuperseded(doc) {
      supersededBy = doc;
    },
  });
  const leaseB = createSidecarOwnershipLease(paths, {
    pid: 2002,
    port: 50002,
    pollIntervalMs: 50,
  });

  t.after(async () => {
    await leaseA.release();
    await leaseB.release();
  });

  await leaseA.claim();
  leaseA.startWatching();
  assert.equal(leaseA.isOwner(), true);
  assert.equal(leaseA.isSuperseded(), false);

  const claimB = await leaseB.claim();
  assert.equal(claimB.previousOwner?.pid, 1001);
  assert.equal(claimB.previousOwner?.instanceId, leaseA.instanceId);

  const deadline = Date.now() + 2000;
  while (!supersededBy && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }

  assert.ok(supersededBy, 'older lease must detect takeover by newer sidecar');
  assert.equal(supersededBy.pid, 2002);
  assert.equal(leaseA.isSuperseded(), true);
  assert.equal(leaseA.isOwner(), false);

  // Older instance releasing must NOT delete newer instance's owner file
  await leaseA.release();
  const ownerOnDisk = JSON.parse(fs.readFileSync(paths.sidecarOwnerFile, 'utf8'));
  assert.equal(ownerOnDisk.instanceId, leaseB.instanceId);

  // Current owner releasing removes the file cleanly
  await leaseB.release();
  assert.equal(fs.existsSync(paths.sidecarOwnerFile), false);
});

test('createHostLivenessWatcher requires initial reachability by default and triggers after consecutive refusals', async () => {
  const results = ['refused', 'refused', 'refused', 'refused'];
  let lostCount = 0;
  const unreachedWatcher = createHostLivenessWatcher({
    lsAddress: '127.0.0.1:19999',
    checkIntervalMs: 0,
    failThreshold: 2,
    requireInitialReachable: true,
    probeFn: async () => results.shift() || 'refused',
    onHostLost: () => {
      lostCount += 1;
    },
  });

  for (let i = 0; i < 4; i += 1) {
    await unreachedWatcher.checkOnce();
  }
  assert.equal(unreachedWatcher.hasSeenAlive(), false);
  assert.equal(unreachedWatcher.isLost(), false);
  assert.equal(lostCount, 0, 'never-reachable dummy port must not trigger orphan self-exit');
  unreachedWatcher.stop();

  const liveSeq = ['ok', 'refused', 'timeout', 'refused', 'refused', 'refused'];
  let lostInfo = null;
  const liveWatcher = createHostLivenessWatcher({
    lsAddress: '127.0.0.1:19998',
    checkIntervalMs: 0,
    failThreshold: 3,
    requireInitialReachable: true,
    probeFn: async () => liveSeq.shift() || 'refused',
    onHostLost: (info) => {
      lostInfo = info;
    },
  });

  assert.equal(await liveWatcher.checkOnce(), 'ok');
  assert.equal(liveWatcher.hasSeenAlive(), true);
  assert.equal(await liveWatcher.checkOnce(), 'refused');
  // Transient timeout resets consecutive refusal streak
  assert.equal(await liveWatcher.checkOnce(), 'timeout');
  assert.equal(await liveWatcher.checkOnce(), 'refused');
  assert.equal(await liveWatcher.checkOnce(), 'refused');
  assert.equal(liveWatcher.isLost(), false);
  assert.equal(await liveWatcher.checkOnce(), 'lost');
  assert.equal(liveWatcher.isLost(), true);
  assert.equal(lostInfo?.port, 19998);
  liveWatcher.stop();
});

test('createHostLivenessWatcher detects real loopback TCP server shutdown end-to-end', async (t) => {
  const srv = net.createServer((sock) => sock.end());
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const { port } = srv.address();
  t.after(() => {
    try {
      srv.close();
    } catch {
      // ignore
    }
  });

  let lost = false;
  const watcher = createHostLivenessWatcher({
    lsAddress: `127.0.0.1:${port}`,
    checkIntervalMs: 0,
    failThreshold: 2,
    requireInitialReachable: true,
    onHostLost: () => {
      lost = true;
    },
  });
  t.after(() => watcher.stop());

  assert.equal(await watcher.checkOnce(), 'ok');
  assert.equal(watcher.hasSeenAlive(), true);

  await new Promise((resolve) => srv.close(resolve));
  assert.equal(await watcher.checkOnce(), 'refused');
  assert.equal(lost, false);
  assert.equal(await watcher.checkOnce(), 'lost');
  assert.equal(lost, true);
});

test('CDP bridge relinquishes host control when superseded and preserves host DOM on handoff dispose', async (t) => {
  clearCdpBridgeCaches();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-cdp-owner-test-'));
  const wpDir = path.join(root, 'wallpapers');
  fs.mkdirSync(wpDir, { recursive: true });
  fs.writeFileSync(path.join(wpDir, 'wp-1.webp'), Buffer.from('FAKE_WEBP_BYTES'));

  const evalLog = [];
  const targetWsUrl = 'ws://127.0.0.1:1/devtools/page/mock-owner';
  const httpServer = http.createServer((req, res) => {
    if (req.url === '/json/list') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify([
          {
            type: 'page',
            url: 'https://127.0.0.1:55555/c/test-owner',
            title: 'Mock - Antigravity',
            webSocketDebuggerUrl: targetWsUrl,
          },
        ]),
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const cdpPort = httpServer.address().port;

  const OrigWebSocket = globalThis.WebSocket;
  let closedCount = 0;

  class MockWs {
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      this._listeners = new Map();
      queueMicrotask(() => {
        this.readyState = 1;
        this._emit('open', {});
      });
    }
    addEventListener(type, fn) {
      if (!this._listeners.has(type)) this._listeners.set(type, new Set());
      this._listeners.get(type).add(fn);
    }
    removeEventListener(type, fn) {
      this._listeners.get(type)?.delete(fn);
    }
    _emit(type, evt) {
      for (const fn of [...(this._listeners.get(type) || [])]) fn(evt);
    }
    send(raw) {
      const msg = JSON.parse(raw);
      const expr = String(msg?.params?.expression || '');
      evalLog.push(expr);
      queueMicrotask(() => {
        this._emit('message', {
          data: JSON.stringify({
            id: msg.id,
            result: { result: { value: { hudInjected: true, activeView: null, focused: true } } },
          }),
        });
      });
    }
    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      closedCount += 1;
      this._emit('close', {});
    }
  }

  globalThis.WebSocket = MockWs;
  let ownerActive = true;

  const paths = resolvePaths({
    appDataDir: path.join(root, 'agy'),
    geminiConfigDir: path.join(root, 'cfg'),
    wallpapersDir: wpDir,
    allowLiveCdp: true,
    devToolsActivePortFile: '',
  });
  const bridge = createCdpThemeBridge(paths, {
    isOwnerActive: () => ownerActive,
  });

  t.after(async () => {
    await bridge.dispose({ preserveHostDom: true });
    globalThis.WebSocket = OrigWebSocket;
    await new Promise((resolve) => httpServer.close(resolve));
    clearCdpBridgeCaches();
    fs.rmSync(root, { recursive: true, force: true });
  });

  const themes = {
    hostThemeMode: 'cdp',
    cdpPort,
    backdropEnabled: true,
    activeWallpaperId: 'wp-1',
    hudEnabled: true,
    hudInjectionMode: 'cdp',
  };

  await bridge.sync(themes, { hostLanguage: 'zh-CN' });
  const evalsWhileOwner = evalLog.length;
  assert.ok(evalsWhileOwner > 0, 'active owner should sync wallpaper and HUD over CDP');
  assert.equal(bridge.getStatus(themes).connected, true);

  // Lose ownership -> further sync/updateHudData must close WS and never write DOM
  ownerActive = false;
  const hudRes = await bridge.updateHudData({ percent: 50, totalUsed: 1000, windowCap: 512000 });
  assert.equal(hudRes, false);
  await bridge.sync(themes, { hostLanguage: 'zh-CN' });
  await bridge.dispose({ preserveHostDom: true });

  assert.equal(evalLog.length, evalsWhileOwner, 'superseded bridge must emit zero CDP DOM mutations');
  assert.ok(closedCount >= 1, 'superseded bridge must close open CDP sockets');
});

test('startSidecarServer automatically retires older sidecar when a newer instance takes over same pluginDataDir', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-sidecar-takeover-'));
  const pluginDir = path.join(root, 'plugin');
  const agyDir = path.join(root, 'agy');
  const cfgDir = path.join(root, 'cfg');
  fs.mkdirSync(path.join(pluginDir, 'rules'), { recursive: true });
  fs.mkdirSync(agyDir, { recursive: true });
  fs.mkdirSync(cfgDir, { recursive: true });

  const prevEnv = {
    ANTIGRAVITY_LS_ADDRESS: process.env.ANTIGRAVITY_LS_ADDRESS,
    ANTIGRAVITY_CSRF_TOKEN: process.env.ANTIGRAVITY_CSRF_TOKEN,
    ANTIGRAVITY_SIDECAR_WEB_PORT: process.env.ANTIGRAVITY_SIDECAR_WEB_PORT,
    ANTIGRAVITY_SIDECAR_UI_TOKEN: process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN,
  };

  const portA = await getFreePort();
  const portB = await getFreePort();
  process.env.ANTIGRAVITY_LS_ADDRESS = '127.0.0.1:19999';
  process.env.ANTIGRAVITY_CSRF_TOKEN = 'csrf-takeover';
  process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN = 'token-takeover';

  const sharedOverrides = {
    pluginRoot: pluginDir,
    appDataDir: agyDir,
    geminiConfigDir: cfgDir,
    assetsDir: path.join(REAL_PLUGIN_ROOT, 'assets'),
    wallpapersDir: path.join(REAL_PLUGIN_ROOT, 'assets', 'wallpapers'),
    frontendDir: path.join(REAL_PLUGIN_ROOT, 'sidecars', 'agy_monitor', 'frontend'),
    backdropSourceFile: path.join(REAL_PLUGIN_ROOT, 'sidecars', 'agy_monitor', 'backdrop', 'AgyBackdrop.cs'),
  };

  process.env.ANTIGRAVITY_SIDECAR_WEB_PORT = String(portA);
  const handleA = await startSidecarServer({
    pathsOverrides: sharedOverrides,
    skipWorker: true,
  });

  let handleB = null;
  t.after(async () => {
    await handleA.shutdown().catch(() => {});
    if (handleB) await handleB.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(prevEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  assert.equal(handleA.ownershipLease.isOwner(), true);

  process.env.ANTIGRAVITY_SIDECAR_WEB_PORT = String(portB);
  handleB = await startSidecarServer({
    pathsOverrides: sharedOverrides,
    skipWorker: true,
  });

  // Instance A should detect takeover and shut itself down without disturbing Instance B
  const deadline = Date.now() + 3500;
  while ((!handleA.ownershipLease.isSuperseded() || handleA.server.listening) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 40));
  }

  assert.equal(handleA.ownershipLease.isSuperseded(), true, 'older sidecar must be marked superseded');
  assert.equal(handleA.server.listening, false, 'older sidecar HTTP server must close automatically');
  assert.equal(handleB.ownershipLease.isOwner(), true, 'newer sidecar must remain active owner');
  assert.equal(handleB.server.listening, true, 'newer sidecar HTTP server must remain listening');

  const ownerDoc = JSON.parse(fs.readFileSync(handleB.paths.sidecarOwnerFile, 'utf8'));
  assert.equal(ownerDoc.instanceId, handleB.ownershipLease.instanceId);
});
