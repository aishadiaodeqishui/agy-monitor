import crypto from 'node:crypto';
import fsSync from 'node:fs';
import fsp from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { atomicWriteJson } from './paths.mjs';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/**
 * Parse a loopback host:port or URL from ANTIGRAVITY_LS_ADDRESS.
 * Returns { host, port } only for loopback addresses with a valid TCP port.
 */
export function parseLoopbackLsAddress(raw) {
  const input = typeof raw === 'string' ? raw.trim() : '';
  if (!input) return null;

  let candidate = input;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    candidate = `http://${candidate}`;
  }
  try {
    const parsed = new URL(candidate);
    const host = String(parsed.hostname || '')
      .trim()
      .toLowerCase()
      .replace(/^\[|\]$/g, '');
    if (!LOOPBACK_HOSTS.has(host)) return null;
    const port = Number(parsed.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host, port };
  } catch {
    return null;
  }
}

async function readOwnerFileSafe(filePath) {
  if (!filePath) return null;
  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    const doc = JSON.parse(raw);
    if (!doc || typeof doc !== 'object') return null;
    return doc;
  } catch {
    return null;
  }
}

/**
 * Single-owner lease backed by `<pluginDataDir>/sidecar_owner.json`.
 *
 * When a newer agy_monitor sidecar starts for the same pluginDataDir, it atomically
 * replaces the owner record with its own `instanceId`. Any older/orphaned instance
 * detects the change (via fs.watch + fallback poll) and immediately relinquishes
 * host CDP control and shuts down cleanly without touching host DOM owned by the
 * newer instance.
 */
export function createSidecarOwnershipLease(
  paths,
  {
    pid = process.pid,
    ppid = process.ppid,
    port = 0,
    lsAddress = '',
    pollIntervalMs = 2000,
    onSuperseded = null,
  } = {},
) {
  const ownerFile =
    paths?.sidecarOwnerFile ||
    (paths?.pluginDataDir ? path.join(paths.pluginDataDir, 'sidecar_owner.json') : '');
  const ownerBaseName = ownerFile ? path.basename(ownerFile).toLowerCase() : 'sidecar_owner.json';
  const instanceId = `${pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  let claimed = false;
  let superseded = false;
  let released = false;
  let supersededInfo = null;
  let watcher = null;
  let debounceTimer = null;
  let pollTimer = null;
  let checkInFlight = false;
  let resolvedPort = Number(port) || 0;

  const stopWatching = () => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (watcher) {
      try {
        watcher.close();
      } catch {
        // Ignore watcher close error
      }
      watcher = null;
    }
  };

  const triggerSuperseded = (ownerDoc) => {
    if (superseded || released) return;
    superseded = true;
    supersededInfo = ownerDoc || null;
    stopWatching();
    if (typeof onSuperseded === 'function') {
      try {
        void Promise.resolve(onSuperseded(supersededInfo)).catch(() => {});
      } catch {
        // Ignore callback error
      }
    }
  };

  const checkOwnership = async () => {
    if (!ownerFile || !claimed || superseded || released || checkInFlight) {
      return !superseded && !released;
    }
    checkInFlight = true;
    try {
      const doc = await readOwnerFileSafe(ownerFile);
      if (doc && typeof doc.instanceId === 'string' && doc.instanceId && doc.instanceId !== instanceId) {
        triggerSuperseded(doc);
        return false;
      }
      return true;
    } finally {
      checkInFlight = false;
    }
  };

  const claim = async ({ port: nextPort } = {}) => {
    if (Number.isInteger(Number(nextPort)) && Number(nextPort) > 0) {
      resolvedPort = Number(nextPort);
    }
    if (!ownerFile) {
      claimed = true;
      return { instanceId, previousOwner: null };
    }
    const previousOwner = await readOwnerFileSafe(ownerFile);
    const record = {
      version: 1,
      instanceId,
      pid: Number(pid) || process.pid,
      ppid: Number(ppid) || 0,
      port: resolvedPort,
      lsAddress: typeof lsAddress === 'string' ? lsAddress : '',
      startedAtMs: Date.now(),
    };
    await atomicWriteJson(ownerFile, record);
    claimed = true;
    superseded = false;
    released = false;
    return { instanceId, previousOwner };
  };

  const startWatching = () => {
    if (!ownerFile || superseded || released) return;
    const watchDir = path.dirname(ownerFile);
    if (!watcher) {
      try {
        watcher = fsSync.watch(watchDir, (_evt, filename) => {
          if (superseded || released) return;
          if (!filename || String(filename).toLowerCase() === ownerBaseName) {
            if (debounceTimer) clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
              debounceTimer = null;
              void checkOwnership();
            }, 30);
            debounceTimer.unref?.();
          }
        });
        watcher.on?.('error', () => {});
        watcher.unref?.();
      } catch {
        watcher = null;
      }
    }
    if (!pollTimer && pollIntervalMs > 0) {
      pollTimer = setInterval(() => {
        void checkOwnership();
      }, pollIntervalMs);
      pollTimer.unref?.();
    }
  };

  const release = async () => {
    if (released) return;
    released = true;
    stopWatching();
    if (!ownerFile || !claimed || superseded) return;
    try {
      const doc = await readOwnerFileSafe(ownerFile);
      if (doc && doc.instanceId === instanceId) {
        await fsp.unlink(ownerFile).catch(() => {});
      }
    } catch {
      // Ignore cleanup errors on shutdown
    }
  };

  return {
    instanceId,
    ownerFile,
    claim,
    startWatching,
    stopWatching,
    checkOwnership,
    release,
    isOwner: () => !superseded && !released,
    isSuperseded: () => superseded,
    getSupersededInfo: () => supersededInfo,
  };
}

function defaultTcpProbe(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // Ignore socket destroy error
      }
      resolve(status);
    };

    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('ok'));
    socket.once('timeout', () => finish('timeout'));
    socket.once('error', (err) => {
      finish(err?.code === 'ECONNREFUSED' ? 'refused' : 'error');
    });
  });
}

/**
 * Watches the launching language_server loopback endpoint (`ANTIGRAVITY_LS_ADDRESS`).
 *
 * On Windows, Antigravity launches sidecars via `cmd.exe /c "... main.mjs"`. If the
 * host language_server exits without terminating the cmd child tree, `process.ppid`
 * still points to the surviving cmd.exe wrapper. Probing the host's loopback port
 * detects that the originating language_server is gone and triggers clean self-exit.
 *
 * With `requireInitialReachable: true` (default), self-exit only arms after the
 * endpoint was observed reachable at least once, avoiding false triggers in isolated
 * tests or standalone dev runs with dummy addresses.
 */
export function createHostLivenessWatcher({
  lsAddress = '',
  checkIntervalMs = 5000,
  connectTimeoutMs = 800,
  failThreshold = 3,
  requireInitialReachable = true,
  probeFn = null,
  onHostLost = null,
} = {}) {
  const target = parseLoopbackLsAddress(lsAddress);
  const threshold = Math.max(1, Number(failThreshold) || 3);
  const probe =
    typeof probeFn === 'function'
      ? probeFn
      : (host, port) => defaultTcpProbe(host, port, connectTimeoutMs);

  let timer = null;
  let stopped = false;
  let checking = false;
  let seenAlive = false;
  let consecutiveRefusals = 0;
  let lostTriggered = false;

  const stop = () => {
    stopped = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  };

  const checkOnce = async () => {
    if (!target || stopped || checking || lostTriggered) return 'skipped';
    checking = true;
    try {
      const result = await probe(target.host, target.port);
      if (stopped || lostTriggered) return 'skipped';

      if (result === 'ok') {
        seenAlive = true;
        consecutiveRefusals = 0;
        return 'ok';
      }

      if (result === 'refused') {
        if (!requireInitialReachable || seenAlive) {
          consecutiveRefusals += 1;
          if (consecutiveRefusals >= threshold) {
            lostTriggered = true;
            stop();
            if (typeof onHostLost === 'function') {
              try {
                void Promise.resolve(onHostLost({ ...target, consecutiveRefusals })).catch(() => {});
              } catch {
                // Ignore callback error
              }
            }
            return 'lost';
          }
        }
        return 'refused';
      }

      // Transient timeout / non-refusal error: do not count toward definitive host exit
      consecutiveRefusals = 0;
      return result;
    } catch {
      return 'error';
    } finally {
      checking = false;
    }
  };

  const start = () => {
    if (!target || stopped || timer) return false;
    void checkOnce();
    if (checkIntervalMs > 0) {
      timer = setInterval(() => {
        void checkOnce();
      }, checkIntervalMs);
      timer.unref?.();
    }
    return true;
  };

  return {
    target,
    start,
    stop,
    checkOnce,
    hasSeenAlive: () => seenAlive,
    isLost: () => lostTriggered,
  };
}
