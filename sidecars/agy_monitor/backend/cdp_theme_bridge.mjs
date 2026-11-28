import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { atomicWriteBuffer, atomicWriteJson, atomicWriteText } from './paths.mjs';
import {
  buildHostWallpaperCss,
  buildNativeHudRendererScript,
  buildNativeWallpaperEngineScript,
  HOST_WALLPAPER_STYLE_ID,
  NATIVE_HUD_VERSION,
  readDevToolsActivePort,
  readNativeHudHeartbeat,
} from './hud_injector.mjs';
import {
  buildHostI18nApplyExpr,
  buildHostI18nRescanExpr,
  buildHostI18nRestoreExpr,
  HOST_I18N_VERSION,
} from './host_i18n.mjs';
import {
  createWslCdpLocalProxy,
  detectWindowsHostEnv,
  resolveWindowsHostDirs,
  resolveWslGatewayIp,
  toWindowsPath,
} from './wsl_bridge.mjs';

const execFileAsync = promisify(execFile);

const STYLE_ELEMENT_ID = HOST_WALLPAPER_STYLE_ID;
const HUD_ELEMENT_ID = 'agy-monitor-cdp-hud';
const HUD_POPOVER_ID = 'agy-monitor-cdp-hud-popover';
const HUD_GUIDE_ID = 'agy-monitor-cdp-hud-guide';
const HUD_STYLE_ID = 'agy-monitor-cdp-hud-style';
const DEFAULT_CDP_PORT = 9229;

function normalizeHudDisplayConfig(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  return {
    showSpeed: src.showSpeed !== false,
    showCacheHit: src.showCacheHit !== false,
    showModel: src.showModel !== false,
    showContext: src.showContext !== false,
    showQuota: src.showQuota !== false,
    updatedAtMs: Number.isFinite(Number(src.updatedAtMs)) ? Number(src.updatedAtMs) : 0,
  };
}

const EXT_TO_MIME = new Map([
  ['.webp', 'image/webp'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.gif', 'image/gif'],
]);

const launcherSignatureCache = new Map();
const activeBridgeCacheClearers = new Set();
let cachedRendererBundle = null;

function getNativeHudScriptBundle() {
  if (!cachedRendererBundle) {
    const src = buildNativeHudRendererScript();
    const hash = crypto.createHash('sha256').update(src, 'utf8').digest('hex').slice(0, 16);
    cachedRendererBundle = {
      src,
      scriptSig: `${NATIVE_HUD_VERSION}:${hash}`,
    };
  }
  return cachedRendererBundle;
}

export function getNativeHudScriptSignature() {
  return getNativeHudScriptBundle().scriptSig;
}

function clampInt(val, min, max, fallback) {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function parseHexRgb(hex, fallback = [7, 7, 9]) {
  if (typeof hex !== 'string') return fallback;
  const s = hex.trim().replace(/^#/, '');
  if (!/^[0-9a-fA-F]{6}$/.test(s)) return fallback;
  return [
    parseInt(s.slice(0, 2), 16),
    parseInt(s.slice(2, 4), 16),
    parseInt(s.slice(4, 6), 16),
  ];
}

function escapeVbsString(str) {
  return String(str || '').replace(/"/g, '""');
}

let cachedResolvedExeWin = '';
let cachedLauncherSnapshot = null;

export function clearCdpBridgeCaches() {
  launcherSignatureCache.clear();
  cachedResolvedExeWin = '';
  cachedLauncherSnapshot = null;
  cachedRendererBundle = null;
  for (const clearFn of activeBridgeCacheClearers) {
    try {
      clearFn();
    } catch {
      // ignore per-instance cache clear error
    }
  }
}

/**
 * Locate Antigravity's desktop executable on Windows (or via WSL2 mount).
 */
export function findAntigravityExePath() {
  const hostInfo = detectWindowsHostEnv();
  if (!hostInfo.hasWindowsHost) return '';
  if (hostInfo.isWsl) {
    return cachedResolvedExeWin || '';
  }
  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
  const candidates = [
    path.join(localAppData, 'Programs', 'antigravity', 'Antigravity.exe'),
    path.join(localAppData, 'Programs', 'Antigravity', 'Antigravity.exe'),
    path.join(programFiles, 'Antigravity', 'Antigravity.exe'),
  ];
  for (const cand of candidates) {
    try {
      if (fs.existsSync(cand)) return cand;
    } catch {
      // ignore probe error
    }
  }
  return candidates[0];
}

async function resolveAntigravityExePathAsync(hostInfo = detectWindowsHostEnv()) {
  if (!hostInfo.hasWindowsHost) return { exeWin: '', exeFound: false };
  if (hostInfo.isNativeWindows) {
    const exeWin = findAntigravityExePath();
    return { exeWin, exeFound: Boolean(exeWin && fs.existsSync(exeWin)) };
  }
  const dirs = await resolveWindowsHostDirs(hostInfo);
  const candidates = [];
  if (dirs.localAppDataWin && dirs.localAppDataPosix) {
    candidates.push(
      {
        win: `${dirs.localAppDataWin}\\Programs\\antigravity\\Antigravity.exe`,
        posix: `${dirs.localAppDataPosix}/Programs/antigravity/Antigravity.exe`,
      },
      {
        win: `${dirs.localAppDataWin}\\Programs\\Antigravity\\Antigravity.exe`,
        posix: `${dirs.localAppDataPosix}/Programs/Antigravity/Antigravity.exe`,
      },
    );
  }
  if (dirs.programFilesWin && dirs.programFilesPosix) {
    candidates.push({
      win: `${dirs.programFilesWin}\\Antigravity\\Antigravity.exe`,
      posix: `${dirs.programFilesPosix}/Antigravity/Antigravity.exe`,
    });
  }
  for (const cand of candidates) {
    try {
      if (fs.existsSync(cand.posix)) {
        cachedResolvedExeWin = cand.win;
        return { exeWin: cand.win, exeFound: true };
      }
    } catch {
      // ignore
    }
  }
  const fallback = candidates[0]?.win || '';
  cachedResolvedExeWin = fallback;
  return { exeWin: fallback, exeFound: false };
}

async function createWindowsShortcutLnk({
  lnkPosix,
  lnkWin,
  targetPath,
  args,
  workingDir,
  description,
  hostInfo = detectWindowsHostEnv(),
}) {
  if (!hostInfo.hasWindowsHost || !lnkPosix || !lnkWin || !targetPath) return false;
  const helperVbsPosix = `${lnkPosix}.mk.vbs`;
  const helperVbsWin = `${lnkWin}.mk.vbs`;
  const script = [
    'Set sh = CreateObject("WScript.Shell")',
    `Set sc = sh.CreateShortcut("${escapeVbsString(lnkWin)}")`,
    `sc.TargetPath = "${escapeVbsString(targetPath)}"`,
    `sc.Arguments = "${escapeVbsString(args)}"`,
    `sc.WorkingDirectory = "${escapeVbsString(workingDir)}"`,
    `sc.IconLocation = "${escapeVbsString(targetPath)},0"`,
    `sc.Description = "${escapeVbsString(description)}"`,
    'sc.WindowStyle = 1',
    'sc.Save',
    '',
  ].join('\r\n');

  try {
    await fsp.mkdir(path.dirname(lnkPosix), { recursive: true });
    // WScript reads UTF-16LE BOM cleanly even with Chinese characters in path/description
    const bomBuf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(script, 'utf16le')]);
    await fsp.writeFile(helperVbsPosix, bomBuf);
    await execFileAsync(hostInfo.wscriptPath || 'wscript.exe', ['//Nologo', helperVbsWin], {
      windowsHide: true,
      timeout: 6000,
    });
    return fs.existsSync(lnkPosix);
  } catch {
    return false;
  } finally {
    await fsp.rm(helperVbsPosix, { force: true }).catch(() => {});
  }
}

/**
 * Emit zero-console desktop launchers (.lnk native shortcut + silent .vbs + self-closing .cmd)
 * that start Antigravity with --remote-debugging-port without leaving any cmd window open
 * and without touching app.asar or any installation files.
 * Supports both native Windows and Win + WSL2 via Windows NTFS staging dir.
 */
export async function ensureCdpLauncher(paths, cdpPort = DEFAULT_CDP_PORT) {
  const hostInfo = detectWindowsHostEnv();
  const port = clampInt(cdpPort, 1024, 65535, DEFAULT_CDP_PORT);
  const { exeWin, exeFound } = await resolveAntigravityExePathAsync(hostInfo);
  const cdpArg = `--remote-debugging-port=${port}`;

  let launcherVbsPosix = paths?.cdpLauncherVbs || '';
  let launcherVbsWin = launcherVbsPosix;
  let launcherCmdPosix = paths?.cdpLauncherCmd || '';
  let launcherCmdWin = launcherCmdPosix;
  let shortcutLnkPosix = paths?.cdpShortcutLnk || '';
  let shortcutLnkWin = shortcutLnkPosix;

  if (hostInfo.isWsl && hostInfo.hasWindowsHost) {
    const dirs = await resolveWindowsHostDirs(hostInfo);
    if (dirs.stagingDirPosix && dirs.stagingDirWin) {
      launcherVbsPosix = `${dirs.stagingDirPosix}/launch_antigravity_cdp.vbs`;
      launcherVbsWin = `${dirs.stagingDirWin}\\launch_antigravity_cdp.vbs`;
      launcherCmdPosix = `${dirs.stagingDirPosix}/启动_Antigravity_高清壁纸模式_CDP.cmd`;
      launcherCmdWin = `${dirs.stagingDirWin}\\启动_Antigravity_高清壁纸模式_CDP.cmd`;
      shortcutLnkPosix = `${dirs.stagingDirPosix}/Antigravity (高清壁纸).lnk`;
      shortcutLnkWin = `${dirs.stagingDirWin}\\Antigravity (高清壁纸).lnk`;
    } else {
      launcherVbsWin = await toWindowsPath(launcherVbsPosix, hostInfo);
      launcherCmdWin = await toWindowsPath(launcherCmdPosix, hostInfo);
      shortcutLnkWin = await toWindowsPath(shortcutLnkPosix, hostInfo);
    }
  }

  const launchCommand = launcherVbsWin
    ? `wscript.exe //Nologo "${launcherVbsWin}"`
    : exeWin
      ? `"${exeWin}" ${cdpArg}`
      : '';

  const cacheKey = `${exeWin}|${port}|${launcherVbsWin}|${launcherCmdWin}|${shortcutLnkWin}`;
  const allExist =
    !hostInfo.hasWindowsHost ||
    ((!launcherVbsPosix || fs.existsSync(launcherVbsPosix)) &&
      (!launcherCmdPosix || fs.existsSync(launcherCmdPosix)) &&
      (!shortcutLnkPosix || fs.existsSync(shortcutLnkPosix)));

  if (
    hostInfo.hasWindowsHost &&
    exeWin &&
    (!allExist || launcherSignatureCache.get(launcherCmdWin || shortcutLnkWin) !== cacheKey)
  ) {
    if (launcherVbsPosix) {
      await fsp.mkdir(path.dirname(launcherVbsPosix), { recursive: true }).catch(() => {});
      const vbsContent = [
        'Set sh = CreateObject("WScript.Shell")',
        `sh.Run """${escapeVbsString(exeWin)}"" ${cdpArg}", 1, False`,
        '',
      ].join('\r\n');
      const vbsBuf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(vbsContent, 'utf16le')]);
      await atomicWriteBuffer(launcherVbsPosix, vbsBuf).catch(() => {});
    }

    if (launcherCmdPosix) {
      await fsp.mkdir(path.dirname(launcherCmdPosix), { recursive: true }).catch(() => {});
      const cmdContent = launcherVbsWin
        ? [
            '@echo off',
            'chcp 65001 >nul',
            'rem 静默无黑窗启动 Antigravity 高清壁纸模式 (纯 CSS CDP 通道，不修改 app.asar)',
            `start "" wscript.exe //Nologo "${launcherVbsWin}"`,
            'exit /b 0',
            '',
          ].join('\r\n')
        : [
            '@echo off',
            'chcp 65001 >nul',
            `start "" /b "${exeWin}" ${cdpArg}`,
            'exit /b 0',
            '',
          ].join('\r\n');
      await atomicWriteText(launcherCmdPosix, cmdContent).catch(() => {});
    }

    if (shortcutLnkPosix && shortcutLnkWin) {
      const workDirWin = exeWin.replace(/[\\/][^\\/]+$/, '');
      await createWindowsShortcutLnk({
        lnkPosix: shortcutLnkPosix,
        lnkWin: shortcutLnkWin,
        targetPath: exeWin,
        args: cdpArg,
        workingDir: workDirWin,
        description: `Antigravity (高清壁纸 CDP :${port})`,
        hostInfo,
      });
    }

    launcherSignatureCache.set(launcherCmdWin || shortcutLnkWin, cacheKey);
  }

  const info = {
    port,
    exePath: exeWin,
    exeFound,
    launcherVbsPath: launcherVbsWin,
    launcherCmdPath: launcherCmdWin,
    shortcutLnkPath: shortcutLnkPosix && fs.existsSync(shortcutLnkPosix) ? shortcutLnkWin : '',
    launchCommand,
    directArgs: cdpArg,
  };
  cachedLauncherSnapshot = info;
  return info;
}

/**
 * Build surgical pure-CSS wallpaper & palette styling for Antigravity's Electron shell.
 * Uses the exact same optical veil formula as Scheme 1 + AGY Console so wallpaper brightness
 * matches 1:1 while keeping all text, code, icons, and popovers 100% solid & crisp.
 */
export function buildCdpThemeCss(themes = {}, wallpaperDataUri = '', options = {}) {
  return buildHostWallpaperCss(themes, wallpaperDataUri, options);
}

export function isAntigravityAppTarget(target) {
  if (!target || !target.webSocketDebuggerUrl) return false;
  const tType = String(target.type || '').toLowerCase();
  if (tType !== 'page' && tType !== 'webview' && tType !== 'iframe') return false;
  const url = String(target.url || '').trim();
  const low = url.toLowerCase();
  const title = String(target.title || '').trim();
  const lowTitle = title.toLowerCase();
  if (!low) return false;
  if (
    low.startsWith('devtools://') ||
    low.startsWith('chrome-extension://') ||
    low.startsWith('chrome://') ||
    low.startsWith('plugin://') ||
    low.startsWith('about:') ||
    low.startsWith('blob:') ||
    low.startsWith('data:')
  ) {
    return false;
  }
  // Never inject host wallpaper into AGY Monitor's own sidecar console or other plugin iframes
  // (check pathname/origin only — ignore query params like ?tab=sidecar__agy-monitor%2Fagy_monitor__%2F on the main host page!)
  const pathOnly = low.split(/[?#]/)[0];
  if (
    lowTitle === 'antigravity monitor' ||
    lowTitle === 'agy 控制台' ||
    pathOnly.includes('agy_monitor') ||
    pathOnly.includes('agy-monitor')
  ) {
    return false;
  }
  // Local loopback HTTP/HTTPS targets: allow Antigravity WSL Remote / Web workbench host pages
  // (e.g. https://127.0.0.1:<port>/... with title "... - Antigravity" or "Antigravity"),
  // while still rejecting sidecar webviews and unrelated local dev servers.
  const isLoopbackHttp =
    low.startsWith('https://127.0.0.1:') ||
    low.startsWith('https://localhost:') ||
    low.startsWith('http://127.0.0.1:') ||
    low.startsWith('http://localhost:');
  if (isLoopbackHttp) {
    if (tType !== 'page') return false;
    return (
      lowTitle === 'antigravity' ||
      lowTitle.endsWith(' - antigravity') ||
      lowTitle.includes('antigravity')
    );
  }
  if (low.startsWith('https://') || low.startsWith('http://')) {
    return false;
  }
  return true;
}

export function rewriteTargetWsUrl(wsUrl, activePort, proxyHost, proxyPort) {
  if (typeof wsUrl !== 'string' || !wsUrl) return '';
  if (!proxyHost || !proxyPort) return wsUrl;
  try {
    const parsed = new URL(wsUrl);
    const isLocalHost = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
    const portNum = Number(parsed.port || activePort);
    if (isLocalHost && portNum === Number(activePort)) {
      parsed.hostname = proxyHost;
      parsed.port = String(proxyPort);
      return parsed.toString();
    }
  } catch {
    // Fallback string replace below
  }
  return wsUrl.replace(
    new RegExp(`^(wss?:\\/\\/)(?:127\\.0\\.0\\.1|localhost):${Number(activePort)}\\b`, 'i'),
    `$1${proxyHost}:${Number(proxyPort)}`,
  );
}

function buildApplyThemeAndScanExpr(cssText) {
  const engineSrc = buildNativeWallpaperEngineScript();
  return `(function(css){
    if (!window.__agyMonitorWallpaper || window.__agyMonitorWallpaper.version !== ${JSON.stringify(NATIVE_HUD_VERSION)}) {
      try {
        (0, eval)(${JSON.stringify(engineSrc)});
      } catch (e) {
        return false;
      }
    }
    if (!window.__agyMonitorWallpaper || typeof window.__agyMonitorWallpaper.apply !== 'function') {
      return false;
    }
    return window.__agyMonitorWallpaper.apply(css);
  })(${JSON.stringify(cssText)})`;
}

function buildRemoveThemeExpr() {
  return `(function(){
    if (window.__agyMonitorWallpaper && typeof window.__agyMonitorWallpaper.remove === 'function') {
      return window.__agyMonitorWallpaper.remove();
    }
    if (window.__agyMonLayerEngine && typeof window.__agyMonLayerEngine.stop === 'function') {
      window.__agyMonLayerEngine.stop();
    }
    var el = document.getElementById(${JSON.stringify(STYLE_ELEMENT_ID)});
    if (el && el.parentNode) el.parentNode.removeChild(el);
    return true;
  })()`;
}

function buildNormalizedHudPayload(
  hudPayload,
  accentColor,
  displayConfig = null,
  themeVisual = null,
  { guideImageDataUri = '', includeGuide = true } = {},
) {
  const disp = normalizeHudDisplayConfig(displayConfig);
  const bubbleColor =
    typeof themeVisual?.bubbleColor === 'string' && /^#[0-9a-fA-F]{6}$/.test(themeVisual.bubbleColor)
      ? themeVisual.bubbleColor
      : '#212533';
  const hostBlendPct = clampInt(themeVisual?.hostBlendPct, 5, 42, 25);
  const payload = {
    activeConvId: typeof hudPayload?.activeConvId === 'string' ? hudPayload.activeConvId : '',
    percent: clampInt(hudPayload?.percent, 0, 999, 0),
    totalUsed: Math.max(0, Math.round(Number(hudPayload?.totalUsed) || 0)),
    windowCap: Math.max(1, Math.round(Number(hudPayload?.windowCap) || 512000)),
    tokPerSec:
      typeof hudPayload?.tokPerSec === 'number' && Number.isFinite(hudPayload.tokPerSec) && hudPayload.tokPerSec > 0
        ? hudPayload.tokPerSec
        : null,
    cacheHitPct:
      typeof hudPayload?.cacheHitPct === 'number' && Number.isFinite(hudPayload.cacheHitPct)
        ? clampInt(hudPayload.cacheHitPct, 0, 100, 0)
        : null,
    upstreamModelId: typeof hudPayload?.upstreamModelId === 'string' ? hudPayload.upstreamModelId : '',
    quota: hudPayload?.quotaQueryEnabled === false
      ? null
      : (hudPayload?.quota && typeof hudPayload.quota === 'object' ? hudPayload.quota : null),
    quotaQueryEnabled: hudPayload?.quotaQueryEnabled !== false,
    sessions: Array.isArray(hudPayload?.sessions) ? hudPayload.sessions : [],
    accent:
      typeof accentColor === 'string' && /^#[0-9a-fA-F]{6}$/.test(accentColor)
        ? accentColor
        : '#5b8cff',
    bubbleColor,
    hostBlendPct,
    liteMode: Boolean(themeVisual?.liteMode),
    display: disp,
  };
  if (includeGuide) {
    payload.guideImageDataUri = typeof guideImageDataUri === 'string' ? guideImageDataUri : '';
  }
  return payload;
}

export function buildHudMountExpr(
  hudPayload,
  accentColor,
  displayConfig = null,
  guideImageDataUri = '',
  themeVisual = null,
) {
  const safePayload = JSON.stringify(
    buildNormalizedHudPayload(hudPayload, accentColor, displayConfig, themeVisual, {
      guideImageDataUri,
      includeGuide: true,
    }),
  );
  const { src: rendererSrc, scriptSig } = getNativeHudScriptBundle();

  return `(function(data){
    var sig = ${JSON.stringify(scriptSig)};
    if (!window.__agyMonitorNativeHud || window.__agyMonitorNativeHud.version !== ${JSON.stringify(NATIVE_HUD_VERSION)} || window.__agyMonitorNativeHud.scriptSig !== sig) {
      try {
        if (window.__agyMonitorNativeHud && typeof window.__agyMonitorNativeHud.dispose === 'function') {
          window.__agyMonitorNativeHud.dispose();
        }
        (0, eval)(${JSON.stringify(rendererSrc)});
        if (window.__agyMonitorNativeHud) {
          window.__agyMonitorNativeHud.scriptSig = sig;
        }
      } catch (e) {
        return { hudInjected: false };
      }
    }
    if (!window.__agyMonitorNativeHud || typeof window.__agyMonitorNativeHud.sync !== 'function') {
      return { hudInjected: false };
    }
    var res = window.__agyMonitorNativeHud.sync(data);
    if (res && typeof res === 'object') {
      res.mountedSig = window.__agyMonitorNativeHud.scriptSig || sig;
    }
    return res;
  })(${safePayload})`;
}

export function buildHudDeltaExpr(
  hudPayload,
  accentColor,
  displayConfig = null,
  themeVisual = null,
  { guideImageDataUri = '', includeGuide = false, scriptSig = '' } = {},
) {
  const sig = scriptSig || getNativeHudScriptBundle().scriptSig;
  const safePayload = JSON.stringify(
    buildNormalizedHudPayload(hudPayload, accentColor, displayConfig, themeVisual, {
      guideImageDataUri,
      includeGuide,
    }),
  );
  return `(function(data){
    var hud = window.__agyMonitorNativeHud;
    if (!hud || hud.version !== ${JSON.stringify(NATIVE_HUD_VERSION)} || hud.scriptSig !== ${JSON.stringify(sig)} || typeof hud.update !== 'function') {
      return { needsMount: true, hudInjected: false };
    }
    return hud.update(data);
  })(${safePayload})`;
}

function buildHudSyncExpr(
  hudPayload,
  accentColor,
  displayConfig = null,
  guideImageDataUri = '',
  themeVisual = null,
) {
  return buildHudMountExpr(hudPayload, accentColor, displayConfig, guideImageDataUri, themeVisual);
}

function buildRemoveHudExpr() {
  return `(function(){
    try {
      if (window.__agyMonitorNativeHud && typeof window.__agyMonitorNativeHud.dispose === 'function') {
        window.__agyMonitorNativeHud.dispose();
      }
    } catch (e) {}
    if (window.__agyMonHudObserver) {
      try { window.__agyMonHudObserver.disconnect(); } catch (e) {}
      delete window.__agyMonHudObserver;
    }
    if (window.__agyMonHudPopDocClick) {
      document.removeEventListener('mousedown', window.__agyMonHudPopDocClick, true);
      delete window.__agyMonHudPopDocClick;
    }
    if (window.__agyMonHudPopKeyDown) {
      document.removeEventListener('keydown', window.__agyMonHudPopKeyDown, true);
      delete window.__agyMonHudPopKeyDown;
    }
    delete window.__agyMonHudPopDismissInstalled;
    var g = document.getElementById(${JSON.stringify(HUD_GUIDE_ID)});
    if (g && g.parentNode) g.parentNode.removeChild(g);
    var pop = document.getElementById(${JSON.stringify(HUD_POPOVER_ID)});
    if (pop && pop.parentNode) pop.parentNode.removeChild(pop);
    var el = document.getElementById(${JSON.stringify(HUD_ELEMENT_ID)});
    if (el && el.parentNode) el.parentNode.removeChild(el);
    var st = document.getElementById(${JSON.stringify(HUD_STYLE_ID)});
    if (st && st.parentNode) st.parentNode.removeChild(st);
    return true;
  })()`;
}

// Host UI Chinese localization is now unified in ./host_i18n.mjs (MIT curated dictionary + protected DOM engine).

/**
 * Create a lightweight multi-target CDP bridge that:
 * 1) Injects Scheme 2 pure-CSS wallpaper across ALL Antigravity app targets with self-discovering layer lifting;
 * 2) Renders a 120fps native inline composer HUD when CDP is connected (zero drag lag!);
 * 3) Provides reversible in-memory Chinese UI localization for Antigravity host without editing app.asar.
 */
export function createCdpThemeBridge(
  paths,
  { onHudStateChange = null, isOwnerActive = null, resolveLatestState = null } = {},
) {
  /** @type {Map<string, { ws: WebSocket, wsUrl: string, title: string, url: string, type: string, cssApplied: boolean, hudInjected: boolean, hudMountedSig: string, hudGuideSig: string, hostLocalized: boolean }>} */
  const sessions = new Map();
  const connectingUrls = new Set();
  let lastError = '';
  let activePort = DEFAULT_CDP_PORT;
  let activeTransport = 'direct';
  let wslProxy = null;
  let cmdSeq = 1;
  let retryTimer = null;
  let retryTickCount = 0;
  let hudTickTimer = null;
  let latestThemes = null;
  let latestHostLanguage = 'zh-CN';
  let latestLiteMode = false;
  let latestHudData = null;
  let lastActiveViewKey = '';
  let lastNotifiedHudInjected = false;
  let disposed = false;

  const notifyHudStateIfChanged = () => {
    const next = isHudInjected();
    if (next !== lastNotifiedHudInjected) {
      lastNotifiedHudInjected = next;
      try {
        onHudStateChange?.(next);
      } catch {
        // Ignore callback error
      }
    }
  };

  let cachedWpId = '';
  let cachedWpMtime = 0;
  let cachedWpSize = 0;
  let cachedWpDataUri = '';

  let cachedGuideMtime = -1;
  let cachedGuideSize = -1;
  let cachedGuideDataUri = '';

  let cachedDisplayMtime = -1;
  let cachedDisplaySize = -1;
  let cachedDisplayConfig = null;

  const clearWallpaperCache = () => {
    cachedWpId = '';
    cachedWpMtime = 0;
    cachedWpSize = 0;
    cachedWpDataUri = '';
  };

  const clearCaches = () => {
    clearWallpaperCache();
    cachedGuideMtime = -1;
    cachedGuideSize = -1;
    cachedGuideDataUri = '';
    cachedDisplayMtime = -1;
    cachedDisplaySize = -1;
    cachedDisplayConfig = null;
    lastActiveViewKey = '';
  };
  activeBridgeCacheClearers.add(clearCaches);

  const closeAllSessions = () => {
    for (const entry of sessions.values()) {
      try {
        entry.ws.close();
      } catch {
        // ignore close error
      }
    }
    sessions.clear();
  };

  const hasOpenSessions = () => {
    for (const entry of sessions.values()) {
      if (entry.ws && entry.ws.readyState === 1) return true;
    }
    return false;
  };

  const isAnyStyleApplied = () => {
    for (const entry of sessions.values()) {
      if (entry.ws && entry.ws.readyState === 1 && entry.cssApplied) return true;
    }
    return false;
  };

  const isHudInjected = () => {
    for (const entry of sessions.values()) {
      if (entry.ws && entry.ws.readyState === 1 && entry.hudInjected) return true;
    }
    return false;
  };

  const isAnyHostLocalized = () => {
    for (const entry of sessions.values()) {
      if (entry.ws && entry.ws.readyState === 1 && entry.hostLocalized) return true;
    }
    return false;
  };

  const resolveWallpaperDataUri = async (themes) => {
    const wpId = typeof themes?.activeWallpaperId === 'string' ? themes.activeWallpaperId.trim() : '';
    if (!wpId) {
      clearWallpaperCache();
      return '';
    }

    let filePath = '';
    if (/^wp-\d+$/i.test(wpId) && paths?.wallpapersDir) {
      filePath = path.join(paths.wallpapersDir, `${path.basename(wpId)}.webp`);
    } else if (Array.isArray(themes?.customWallpapers) && paths?.customWallpapersDir) {
      const match = themes.customWallpapers.find((w) => w && w.id === wpId && w.filename);
      if (match) {
        filePath = path.join(paths.customWallpapersDir, path.basename(match.filename));
      }
    }
    if (!filePath) {
      clearWallpaperCache();
      return '';
    }

    try {
      const st = await fsp.stat(filePath);
      if (wpId === cachedWpId && st.mtimeMs === cachedWpMtime && st.size === cachedWpSize && cachedWpDataUri) {
        return cachedWpDataUri;
      }
      const ext = path.extname(filePath).toLowerCase();
      const mime = EXT_TO_MIME.get(ext) || 'image/webp';
      const buf = await fsp.readFile(filePath);
      cachedWpId = wpId;
      cachedWpMtime = st.mtimeMs;
      cachedWpSize = st.size;
      cachedWpDataUri = `data:${mime};base64,${buf.toString('base64')}`;
      return cachedWpDataUri;
    } catch {
      clearWallpaperCache();
      return '';
    }
  };

  const resolveGuideImageMeta = async () => {
    const filePath = paths?.assetsDir ? path.join(paths.assetsDir, 'open_console_guide.jpg') : '';
    if (!filePath) return { filePath: '', guideSig: 'none', mtimeMs: -1, size: -1 };
    try {
      const st = await fsp.stat(filePath);
      return {
        filePath,
        guideSig: `${filePath}|${st.mtimeMs}|${st.size}`,
        mtimeMs: st.mtimeMs,
        size: st.size,
      };
    } catch {
      return { filePath: '', guideSig: 'none', mtimeMs: -1, size: -1 };
    }
  };

  const resolveGuideImageDataUri = async (meta = null) => {
    const info = meta || (await resolveGuideImageMeta());
    if (!info.filePath) {
      cachedGuideMtime = -1;
      cachedGuideSize = -1;
      cachedGuideDataUri = '';
      return '';
    }
    try {
      if (info.mtimeMs === cachedGuideMtime && info.size === cachedGuideSize && cachedGuideDataUri) {
        return cachedGuideDataUri;
      }
      const buf = await fsp.readFile(info.filePath);
      cachedGuideMtime = info.mtimeMs;
      cachedGuideSize = info.size;
      cachedGuideDataUri = `data:image/jpeg;base64,${buf.toString('base64')}`;
      return cachedGuideDataUri;
    } catch {
      cachedGuideMtime = -1;
      cachedGuideSize = -1;
      cachedGuideDataUri = '';
      return '';
    }
  };

  const sendEvaluateOn = (entry, expression) =>
    new Promise((resolve, reject) => {
      const sock = entry?.ws;
      if (!sock || sock.readyState !== 1) {
        reject(new Error('CDP WebSocket not open'));
        return;
      }
      const id = cmdSeq++;
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        sock.removeEventListener?.('message', onMsg);
        sock.removeEventListener?.('close', onClose);
        sock.removeEventListener?.('error', onError);
      };

      const fail = (err) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      };

      const succeed = (val) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(val);
      };

      const timer = setTimeout(() => {
        fail(new Error('CDP evaluate timeout'));
      }, 1500);

      const onClose = () => fail(new Error('CDP WebSocket closed'));
      const onError = () => fail(new Error('CDP WebSocket error'));

      const onMsg = (evt) => {
        try {
          const parsed = JSON.parse(String(evt.data || ''));
          if (parsed.id === id) {
            if (parsed.error) {
              fail(new Error(parsed.error.message || 'CDP error'));
            } else if (parsed.result?.exceptionDetails) {
              const exMsg =
                parsed.result.exceptionDetails.exception?.description ||
                parsed.result.exceptionDetails.text ||
                'CDP evaluation exception';
              fail(new Error(exMsg));
            } else {
              succeed(parsed.result);
            }
          }
        } catch {
          // ignore non-matching frames
        }
      };

      sock.addEventListener('message', onMsg);
      sock.addEventListener('close', onClose);
      sock.addEventListener('error', onError);
      try {
        sock.send(
          JSON.stringify({
            id,
            method: 'Runtime.evaluate',
            params: { expression, returnByValue: true },
          }),
        );
      } catch (err) {
        fail(err instanceof Error ? err : new Error('CDP send failed'));
      }
    });

  const openSession = (target) =>
    new Promise((resolve) => {
      const url = target.webSocketDebuggerUrl;
      if (disposed || !url) {
        resolve(null);
        return;
      }
      const existing = sessions.get(url);
      if (existing && existing.ws && existing.ws.readyState === 1) {
        existing.title = String(target.title || existing.title || '');
        resolve(existing);
        return;
      }
      if (connectingUrls.has(url)) {
        resolve(null);
        return;
      }
      connectingUrls.add(url);

      let settled = false;
      const finish = (val) => {
        if (settled) return;
        settled = true;
        connectingUrls.delete(url);
        resolve(val);
      };

      try {
        const sock = new globalThis.WebSocket(url);
        const openTimer = setTimeout(() => {
          try {
            sock.close();
          } catch {
            // ignore
          }
          finish(null);
        }, 750);

        sock.addEventListener('open', () => {
          clearTimeout(openTimer);
          if (disposed) {
            try {
              sock.close();
            } catch {
              // ignore
            }
            finish(null);
            return;
          }
          const prev = sessions.get(url);
          if (prev && prev.ws && prev.ws !== sock) {
            try {
              prev.ws.close();
            } catch {
              // ignore
            }
          }
          const entry = {
            ws: sock,
            wsUrl: url,
            title: String(target.title || ''),
            url: String(target.url || ''),
            type: String(target.type || 'page'),
            cssApplied: false,
            hudInjected: false,
            hudMountedSig: '',
            hudGuideSig: '',
            hostLocalized: false,
          };
          sessions.set(url, entry);
          finish(entry);
        });

        sock.addEventListener('close', () => {
          clearTimeout(openTimer);
          const cur = sessions.get(url);
          if (cur && cur.ws === sock) {
            sessions.delete(url);
            notifyHudStateIfChanged();
          }
          finish(null);
        });

        sock.addEventListener('error', () => {
          clearTimeout(openTimer);
          finish(null);
        });
      } catch {
        finish(null);
      }
    });

  const fetchTargetsFrom = async (host, port, timeoutMs = 450) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`http://${host}:${port}/json/list`, {
        signal: controller.signal,
        headers: { Connection: 'close' },
      });
      if (!res.ok) {
        return { ok: false, status: res.status, targets: [] };
      }
      const json = await res.json();
      return { ok: true, status: 200, targets: Array.isArray(json) ? json : [] };
    } catch {
      return { ok: false, status: 0, targets: [] };
    } finally {
      clearTimeout(timer);
    }
  };

  const closeWslProxy = () => {
    if (wslProxy) {
      try {
        wslProxy.close();
      } catch {
        // ignore
      }
      wslProxy = null;
    }
  };

  const ensureConnected = async (port) => {
    if (disposed || typeof globalThis.WebSocket !== 'function') {
      lastError = '当前 Node 环境缺少 WebSocket 客户端';
      return false;
    }

    const configuredPort = clampInt(port, 1024, 65535, DEFAULT_CDP_PORT);
    if (paths?.disableLiveCdp === true) {
      activePort = configuredPort;
      lastError = '测试隔离环境已跳过本机实时 CDP 探测';
      return false;
    }
    const devToolsPort = await readDevToolsActivePort(paths).catch(() => 0);
    const candidatePorts = [configuredPort];
    if (devToolsPort >= 1024 && devToolsPort <= 65535 && devToolsPort !== configuredPort) {
      candidatePorts.push(devToolsPort);
    }
    const hostInfo = detectWindowsHostEnv();

    let targets = [];
    let wsRewriteHost = '';
    let wsRewritePort = 0;
    let connectedPort = configuredPort;
    let directHttpStatus = 0;
    let connectedOk = false;

    for (const candPort of candidatePorts) {
      if (wslProxy && wslProxy.targetPort !== candPort) {
        closeWslProxy();
      }
      // Tier 1: Direct loopback (native Windows, WSL2 mirrored mode, or manual port forwarding)
      const directRes = await fetchTargetsFrom('127.0.0.1', candPort, hostInfo.isWsl ? 300 : 450);
      if (directRes.ok) {
        targets = directRes.targets;
        activeTransport = 'direct';
        connectedPort = candPort;
        connectedOk = true;
        break;
      }
      if (directRes.status > 0) directHttpStatus = directRes.status;

      if (hostInfo.isWsl && hostInfo.hasWindowsHost) {
        // Tier 2: WSL2 NAT zero-config Interop tunnel
        if (!wslProxy) {
          wslProxy = await createWslCdpLocalProxy(candPort, { hostInfo }).catch(() => null);
        }
        let tunnelOk = false;
        if (wslProxy && wslProxy.localPort > 0) {
          const tunRes = await fetchTargetsFrom('127.0.0.1', wslProxy.localPort, 1800);
          if (tunRes.ok) {
            targets = tunRes.targets;
            wsRewriteHost = '127.0.0.1';
            wsRewritePort = wslProxy.localPort;
            activeTransport = 'wsl_tunnel';
            connectedPort = candPort;
            tunnelOk = true;
          }
        }
        // Tier 3: Fallback to WSL2 NAT Windows gateway IP
        if (!tunnelOk) {
          const gwIp = resolveWslGatewayIp();
          if (gwIp) {
            const gwRes = await fetchTargetsFrom(gwIp, candPort, 450);
            if (gwRes.ok) {
              targets = gwRes.targets;
              wsRewriteHost = gwIp;
              wsRewritePort = candPort;
              activeTransport = 'wsl_gateway';
              connectedPort = candPort;
              tunnelOk = true;
            }
          }
        }
        if (tunnelOk) {
          connectedOk = true;
          break;
        }
      }
    }

    activePort = connectedPort;
    if (!connectedOk) {
      lastError = hostInfo.isWsl && hostInfo.hasWindowsHost
        ? `未检测到 Windows 侧 CDP 端口 ${configuredPort}（WSL2 NAT 已自动启用桥接，请用调试参数或持久化注入重启 Antigravity）`
        : directHttpStatus > 0
          ? `CDP 端口 ${configuredPort} 返回 HTTP ${directHttpStatus}`
          : `未检测到本地 CDP 端口 ${configuredPort}`;
      return false;
    }

    const matched = targets
      .filter(isAntigravityAppTarget)
      .map((t) =>
        wsRewriteHost && wsRewritePort
          ? {
              ...t,
              webSocketDebuggerUrl: rewriteTargetWsUrl(
                t.webSocketDebuggerUrl,
                activePort,
                wsRewriteHost,
                wsRewritePort,
              ),
            }
          : t,
      );
    if (matched.length === 0) {
      lastError = `端口 ${activePort} 上未找到 Antigravity 主窗口目标`;
      return false;
    }

    const liveUrls = new Set(matched.map((t) => t.webSocketDebuggerUrl));
    for (const [u, entry] of sessions.entries()) {
      if (!liveUrls.has(u) || entry.ws.readyState !== 1) {
        try {
          entry.ws.close();
        } catch {
          // ignore
        }
        sessions.delete(u);
      }
    }

    await Promise.allSettled(matched.map((t) => openSession(t)));
    if (!hasOpenSessions()) {
      lastError = '连接 CDP WebSocket 超时';
      return false;
    }

    lastError = '';
    return true;
  };

  const applyCssAll = async (cssText) => {
    const expr = buildApplyThemeAndScanExpr(cssText);
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState !== 1) return;
        await sendEvaluateOn(entry, expr);
        entry.cssApplied = true;
      }),
    );
  };

  const removeCssAll = async () => {
    const expr = buildRemoveThemeExpr();
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState === 1) {
          await sendEvaluateOn(entry, expr).catch(() => {});
        }
        entry.cssApplied = false;
      }),
    );
  };

  const maybeWriteActiveView = async (view, { focused = true } = {}) => {
    if (!view || !paths?.hudActiveViewFile) return;
    if (sessions.size > 1 && !focused) return;
    const isNewConv = Boolean(view.isNewConversation);
    const convId = typeof view.convId === 'string' ? view.convId.trim() : '';
    const title = String(view.title || '').trim();
    const workspace = String(view.workspace || '').trim();
    if (!isNewConv && !convId && (!title || title.length < 2)) return;
    const key = isNewConv ? '__new_conversation__' : `${convId}|${workspace}|${title}`;
    if (key === lastActiveViewKey) return;

    // Preserve recent explicit sidecar_focus selections from being clobbered by title-only DOM reads
    if (!convId) {
      try {
        const existingRaw = await fsp.readFile(paths.hudActiveViewFile, 'utf8');
        const existing = JSON.parse(existingRaw);
        if (
          existing &&
          existing.source === 'sidecar_focus' &&
          typeof existing.conversationId === 'string' &&
          existing.conversationId.trim()
        ) {
          const ageMs = Date.now() - Number(existing.updatedAtMs || 0);
          if (ageMs >= 0 && ageMs < 3000) {
            return;
          }
          if (!isNewConv && String(existing.title || '').trim().toLowerCase() === title.toLowerCase()) {
            lastActiveViewKey = key;
            return;
          }
        }
      } catch {
        // ignore missing/corrupt active view file
      }
    }

    lastActiveViewKey = key;
    await atomicWriteJson(paths.hudActiveViewFile, {
      ...(convId ? { conversationId: convId, convId } : {}),
      workspace,
      title,
      isNewConversation: isNewConv,
      source: convId ? 'native_dom_route' : 'cdp_header',
      updatedAtMs: Date.now(),
    }).catch(() => {});
  };

  const readHudDisplayConfig = async () => {
    if (!paths?.hudDisplayFile) return normalizeHudDisplayConfig(null);
    try {
      const st = await fsp.stat(paths.hudDisplayFile);
      if (cachedDisplayConfig && st.mtimeMs === cachedDisplayMtime && st.size === cachedDisplaySize) {
        return cachedDisplayConfig;
      }
      const raw = await fsp.readFile(paths.hudDisplayFile, 'utf8');
      cachedDisplayConfig = normalizeHudDisplayConfig(JSON.parse(raw));
      cachedDisplayMtime = st.mtimeMs;
      cachedDisplaySize = st.size;
      return cachedDisplayConfig;
    } catch {
      cachedDisplayMtime = -1;
      cachedDisplaySize = -1;
      cachedDisplayConfig = null;
      return normalizeHudDisplayConfig(null);
    }
  };

  const syncHudAll = async () => {
    if (!canControlHost()) {
      relinquishHostControl();
      notifyHudStateIfChanged();
      return false;
    }
    if (!hasOpenSessions()) {
      notifyHudStateIfChanged();
      return false;
    }
    const hudEnabled = latestThemes?.hudEnabled !== false;
    if (!hudEnabled) {
      const rem = buildRemoveHudExpr();
      await Promise.allSettled(
        [...sessions.values()].map(async (entry) => {
          if (entry.ws.readyState === 1) {
            await sendEvaluateOn(entry, rem).catch(() => {});
          }
          entry.hudInjected = false;
          entry.hudMountedSig = '';
          entry.hudGuideSig = '';
        }),
      );
      notifyHudStateIfChanged();
      return false;
    }

    const accent = latestThemes?.colors?.accent || '#5b8cff';
    const bubbleColor = latestThemes?.colors?.bubble || '#212533';
    const hostBlendPct = clampInt(latestThemes?.hostBlendPct, 5, 42, 25);
    const displayCfg = await readHudDisplayConfig();
    const { scriptSig } = getNativeHudScriptBundle();
    const guideMeta = await resolveGuideImageMeta();
    const themeVisual = {
      bubbleColor,
      hostBlendPct,
      liteMode: latestLiteMode,
    };

    let guideUriPromise = null;
    const ensureGuideDataUri = () => {
      if (!guideUriPromise) {
        guideUriPromise = resolveGuideImageDataUri(guideMeta);
      }
      return guideUriPromise;
    };

    let mountExprPromise = null;
    const ensureMountExpr = () => {
      if (!mountExprPromise) {
        mountExprPromise = ensureGuideDataUri().then((guideDataUri) =>
          buildHudMountExpr(latestHudData || {}, accent, displayCfg, guideDataUri, themeVisual),
        );
      }
      return mountExprPromise;
    };

    let deltaExprNoGuide = '';
    const getDeltaExprNoGuide = () => {
      if (!deltaExprNoGuide) {
        deltaExprNoGuide = buildHudDeltaExpr(latestHudData || {}, accent, displayCfg, themeVisual, {
          includeGuide: false,
          scriptSig,
        });
      }
      return deltaExprNoGuide;
    };

    let deltaExprWithGuidePromise = null;
    const ensureDeltaExprWithGuide = () => {
      if (!deltaExprWithGuidePromise) {
        deltaExprWithGuidePromise = ensureGuideDataUri().then((guideDataUri) =>
          buildHudDeltaExpr(latestHudData || {}, accent, displayCfg, themeVisual, {
            guideImageDataUri: guideDataUri,
            includeGuide: true,
            scriptSig,
          }),
        );
      }
      return deltaExprWithGuidePromise;
    };

    let anyInjected = false;
    let latestPatch = null;
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState !== 1) return;
        let val = null;
        if (entry.hudMountedSig === scriptSig) {
          const needGuide = entry.hudGuideSig !== guideMeta.guideSig;
          const deltaExpr = needGuide ? await ensureDeltaExprWithGuide() : getDeltaExprNoGuide();
          const res = await sendEvaluateOn(entry, deltaExpr).catch(() => null);
          val = res?.result?.value || null;
          if (!val || val.needsMount === true) {
            // Page reloaded, window.__agyMonitorNativeHud missing, or script signature changed: fall back cleanly to full mount
            entry.hudMountedSig = '';
            entry.hudGuideSig = '';
            const mountRes = await sendEvaluateOn(entry, await ensureMountExpr()).catch(() => null);
            val = mountRes?.result?.value || null;
            if (val?.mountedSig === scriptSig) {
              entry.hudMountedSig = scriptSig;
              entry.hudGuideSig = guideMeta.guideSig;
            }
          } else if (needGuide) {
            entry.hudGuideSig = guideMeta.guideSig;
          }
        } else {
          const mountRes = await sendEvaluateOn(entry, await ensureMountExpr()).catch(() => null);
          val = mountRes?.result?.value || null;
          if (val?.mountedSig === scriptSig) {
            entry.hudMountedSig = scriptSig;
            entry.hudGuideSig = guideMeta.guideSig;
          }
        }

        entry.hudInjected = Boolean(val?.hudInjected);
        if (entry.hudInjected) anyInjected = true;
        if (val?.activeView) {
          await maybeWriteActiveView(val.activeView, { focused: val?.focused !== false });
        }
        if (val?.displayPatch && typeof val.displayPatch === 'object') {
          const normPatch = normalizeHudDisplayConfig(val.displayPatch);
          if (!latestPatch || normPatch.updatedAtMs >= latestPatch.updatedAtMs) {
            latestPatch = normPatch;
          }
        }
      }),
    );
    if (latestPatch && paths?.hudDisplayFile) {
      cachedDisplayConfig = latestPatch;
      cachedDisplayMtime = -1;
      cachedDisplaySize = -1;
      await atomicWriteJson(paths.hudDisplayFile, latestPatch).catch(() => {});
    }
    notifyHudStateIfChanged();
    return anyInjected;
  };

  const removeHudAll = async () => {
    const rem = buildRemoveHudExpr();
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState === 1) {
          await sendEvaluateOn(entry, rem).catch(() => {});
        }
        entry.hudInjected = false;
        entry.hudMountedSig = '';
        entry.hudGuideSig = '';
      }),
    );
    notifyHudStateIfChanged();
  };

  const applyHostI18nAll = async () => {
    const rescanExpr = buildHostI18nRescanExpr();
    let fullExpr = '';
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState !== 1) return;
        try {
          if (entry.hostLocalized && entry.hostI18nVersion === HOST_I18N_VERSION) {
            const res = await sendEvaluateOn(entry, rescanExpr);
            if (res?.result?.value === true) return;
          }
          if (!fullExpr) fullExpr = buildHostI18nApplyExpr();
          await sendEvaluateOn(entry, fullExpr);
          entry.hostLocalized = true;
          entry.hostI18nVersion = HOST_I18N_VERSION;
        } catch {
          entry.hostLocalized = false;
          entry.hostI18nVersion = '';
        }
      }),
    );
  };

  const restoreHostI18nAll = async () => {
    const expr = buildHostI18nRestoreExpr();
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState === 1) {
          await sendEvaluateOn(entry, expr).catch(() => {});
        }
        entry.hostLocalized = false;
        entry.hostI18nVersion = '';
      }),
    );
  };

  const applyCurrentHostLang = async () => {
    if (!hasOpenSessions()) return;
    if (latestHostLanguage === 'zh-CN') {
      await applyHostI18nAll();
    } else {
      await restoreHostI18nAll();
    }
  };

  const wantDomHudFor = (themes = latestThemes) =>
    Boolean(themes && themes.hudEnabled !== false && themes.hudInjectionMode !== 'uia');

  const isNativeMainProcessAlive = () => {
    try {
      return readNativeHudHeartbeat(paths).alive;
    } catch {
      return false;
    }
  };

  const isNativeWallpaperAlive = () => {
    try {
      return Boolean(readNativeHudHeartbeat(paths).wallpaperAlive);
    } catch {
      return false;
    }
  };

  const wantCdpCssFor = (themes = latestThemes) => {
    if (!themes || !themes.backdropEnabled || !themes.activeWallpaperId) return false;
    if (themes.hostThemeMode === 'cdp') return true;
    const isInject = themes.hostThemeMode === 'inject' || !themes.hostThemeMode;
    return isInject && !isNativeWallpaperAlive();
  };

  const probeSessionMarkers = async (needCss, needI18n, needHud) => {
    const probeExpr = `(function(){ return { hasCss: Boolean(document.getElementById(${JSON.stringify(STYLE_ELEMENT_ID)})), hasI18n: Boolean(window.__agyHostI18nApplied && window.__agyMonitorHostI18n && window.__agyMonitorHostI18n.version === ${JSON.stringify(HOST_I18N_VERSION)}), hasHud: Boolean(window.__agyMonitorNativeHud && document.getElementById('agy-monitor-native-hud')) }; })()`;
    let needsResync = false;
    await Promise.allSettled(
      [...sessions.values()].map(async (entry) => {
        if (entry.ws.readyState !== 1) return;
        const res = await sendEvaluateOn(entry, probeExpr).catch(() => null);
        const val = res?.result?.value;
        if (!val) return;
        if (needCss && !val.hasCss) {
          entry.cssApplied = false;
          needsResync = true;
        }
        if (needI18n && !val.hasI18n) {
          entry.hostLocalized = false;
          entry.hostI18nVersion = '';
          needsResync = true;
        }
        if (needHud && !val.hasHud) {
          entry.hudInjected = false;
          entry.hudMountedSig = '';
          entry.hudGuideSig = '';
          needsResync = true;
        }
      }),
    );
    return needsResync;
  };

  const canControlHost = () =>
    !disposed && (typeof isOwnerActive !== 'function' || Boolean(isOwnerActive()));

  const relinquishHostControl = () => {
    ensureLoops(false);
    closeAllSessions();
  };

  let refreshStatePromise = null;
  const refreshLatestStateFromDisk = async () => {
    if (typeof resolveLatestState !== 'function' || !canControlHost()) return;
    if (!refreshStatePromise) {
      refreshStatePromise = Promise.resolve()
        .then(() => resolveLatestState())
        .then((fresh) => {
          if (!fresh || typeof fresh !== 'object' || !canControlHost()) return;
          if (fresh.themes && typeof fresh.themes === 'object') {
            latestThemes = fresh.themes;
          }
          if (fresh.hostLanguage === 'zh-CN' || fresh.hostLanguage === 'en') {
            latestHostLanguage = fresh.hostLanguage;
          }
          if (typeof fresh.liteMode === 'boolean') {
            latestLiteMode = fresh.liteMode;
          } else if (typeof fresh.themes?.liteMode === 'boolean') {
            latestLiteMode = fresh.themes.liteMode;
          }
        })
        .catch(() => {})
        .finally(() => {
          refreshStatePromise = null;
        });
    }
    await refreshStatePromise;
  };

  const ensureLoops = (wantCdp) => {
    if (wantCdp && !retryTimer && canControlHost()) {
      retryTimer = setInterval(() => {
        if (!canControlHost()) {
          relinquishHostControl();
          return;
        }
        if (!latestThemes) return;
        const wantHud = wantDomHudFor(latestThemes);
        const isCdpMode = latestThemes.hostThemeMode === 'cdp';
        const needCss = wantCdpCssFor(latestThemes);
        const stillWant =
          isCdpMode ||
          needCss ||
          wantHud ||
          (hasOpenSessions() && latestHostLanguage === 'zh-CN');
        if (!stillWant) {
          clearInterval(retryTimer);
          retryTimer = null;
          return;
        }
        retryTickCount += 1;
        const needI18n = latestHostLanguage === 'zh-CN';
        const needCdpHud = wantHud && !isNativeMainProcessAlive();
        if (!hasOpenSessions()) {
          // Avoid noisy reconnect loops every 2s when native main-process already handles HUD & wallpaper
          if (isCdpMode || needCss || needCdpHud || retryTickCount % 6 === 0) {
            void (async () => {
              await refreshLatestStateFromDisk();
              if (!canControlHost() || !latestThemes) return;
              await sync(latestThemes, { hostLanguage: latestHostLanguage, liteMode: latestLiteMode });
            })();
          }
          return;
        }
        if ((needCss && !isAnyStyleApplied()) || (needI18n && !isAnyHostLocalized()) || (needCdpHud && !isHudInjected())) {
          void (async () => {
            await refreshLatestStateFromDisk();
            if (!canControlHost() || !latestThemes) return;
            await sync(latestThemes, { hostLanguage: latestHostLanguage, liteMode: latestLiteMode });
          })();
          return;
        }
        // Periodically detect newly opened windows & Ctrl+R page reloads whose DOM lost injected nodes
        if (retryTickCount % 3 === 0) {
          void (async () => {
            await refreshLatestStateFromDisk();
            if (!canControlHost() || !latestThemes) return;
            const freshWantHud = wantDomHudFor(latestThemes);
            const freshNeedCss = wantCdpCssFor(latestThemes);
            const freshNeedI18n = latestHostLanguage === 'zh-CN';
            const freshNeedCdpHud = freshWantHud && !isNativeMainProcessAlive();
            const lostMarkers = await probeSessionMarkers(freshNeedCss, freshNeedI18n, freshNeedCdpHud);
            if (!canControlHost() || !latestThemes) return;
            if (lostMarkers) {
              await sync(latestThemes, { hostLanguage: latestHostLanguage, liteMode: latestLiteMode });
              return;
            }
            const prevCount = sessions.size;
            const ok = await ensureConnected(activePort);
            if (canControlHost() && ok && sessions.size > prevCount) {
              await sync(latestThemes, { hostLanguage: latestHostLanguage, liteMode: latestLiteMode });
            }
          })();
        }
      }, 2200);
      if (typeof retryTimer.unref === 'function') retryTimer.unref();
    } else if ((!wantCdp || !canControlHost()) && retryTimer) {
      clearInterval(retryTimer);
      retryTimer = null;
      retryTickCount = 0;
    }

    if (wantCdp && !hudTickTimer && canControlHost()) {
      hudTickTimer = setInterval(() => {
        if (!canControlHost()) {
          relinquishHostControl();
          return;
        }
        if (!hasOpenSessions()) return;
        const wantHud = wantDomHudFor(latestThemes);
        if (wantHud && (latestThemes?.hostThemeMode === 'cdp' || !isNativeMainProcessAlive())) {
          void syncHudAll();
        }
      }, 900);
      if (typeof hudTickTimer.unref === 'function') hudTickTimer.unref();
    } else if ((!wantCdp || !canControlHost()) && hudTickTimer) {
      clearInterval(hudTickTimer);
      hudTickTimer = null;
    }
  };

  const updateHudData = async (hudPayload) => {
    latestHudData = hudPayload || null;
    if (!canControlHost()) {
      relinquishHostControl();
      return false;
    }
    if (!hasOpenSessions() || !wantDomHudFor(latestThemes)) return false;
    if (latestThemes?.hostThemeMode !== 'cdp' && isNativeMainProcessAlive()) {
      return true;
    }
    return await syncHudAll();
  };

  const sync = async (themes = {}, options = {}) => {
    if (!canControlHost()) {
      relinquishHostControl();
      return getStatus(themes);
    }
    latestThemes = themes;
    if (options.hostLanguage === 'zh-CN' || options.hostLanguage === 'en') {
      latestHostLanguage = options.hostLanguage;
    }
    if (typeof options.liteMode === 'boolean') {
      latestLiteMode = options.liteMode;
    } else if (typeof themes?.liteMode === 'boolean') {
      latestLiteMode = themes.liteMode;
    }
    const port = clampInt(themes.cdpPort, 1024, 65535, DEFAULT_CDP_PORT);
    if (port !== activePort && sessions.size > 0 && !options.keepConnectedPort) {
      const devToolsPort = await readDevToolsActivePort(paths).catch(() => 0);
      if (activePort !== devToolsPort) {
        await restoreHostI18nAll().catch(() => {});
        if (!(themes.hostThemeMode === 'inject' && isNativeWallpaperAlive())) {
          await removeCssAll().catch(() => {});
        }
        await removeHudAll().catch(() => {});
        closeAllSessions();
      }
    }
    await ensureCdpLauncher(paths, port);

    const isCdpMode = themes.hostThemeMode === 'cdp';
    const isInjectMode = themes.hostThemeMode === 'inject' || !themes.hostThemeMode;
    const nativeWpAlive = isNativeWallpaperAlive();
    const wantDomHud = wantDomHudFor(themes);
    const wantCdpCss = wantCdpCssFor(themes);
    if (!wantCdpCss) {
      clearWallpaperCache();
    }
    const shouldConnect = isCdpMode || wantCdpCss || wantDomHud || Boolean(options.probeForLang) || hasOpenSessions();

    if (!shouldConnect) {
      ensureLoops(false);
      return getStatus(themes);
    }

    const ok = await ensureConnected(port);
    ensureLoops(isCdpMode || wantCdpCss || wantDomHud || (hasOpenSessions() && latestHostLanguage === 'zh-CN'));
    if (!ok) {
      return getStatus(themes);
    }

    try {
      if (wantCdpCss) {
        const dataUri = await resolveWallpaperDataUri(themes);
        if (!dataUri) {
          if (!(isInjectMode && nativeWpAlive)) {
            await removeCssAll();
          }
        } else {
          const css = buildCdpThemeCss(themes, dataUri, { liteMode: latestLiteMode });
          await applyCssAll(css);
        }
      } else if (!(isInjectMode && nativeWpAlive && Boolean(themes.backdropEnabled) && Boolean(themes.activeWallpaperId))) {
        await removeCssAll();
      }

      if (wantDomHud) {
        await syncHudAll();
      } else {
        await removeHudAll();
      }

      await applyCurrentHostLang();
    } catch (err) {
      lastError = err?.message || 'CDP 样式应用失败';
    }
    return getStatus(themes);
  };

  const syncHostLanguage = async (language, themes = latestThemes || {}, options = {}) => {
    latestHostLanguage = language === 'en' ? 'en' : 'zh-CN';
    const nextLiteMode =
      typeof options?.liteMode === 'boolean'
        ? options.liteMode
        : typeof themes?.liteMode === 'boolean'
          ? themes.liteMode
          : latestLiteMode;
    return await sync(themes, {
      ...options,
      hostLanguage: latestHostLanguage,
      liteMode: nextLiteMode,
      probeForLang: true,
    });
  };

  const getStatus = (themes = latestThemes || {}) => {
    const hostInfo = detectWindowsHostEnv();
    const port = clampInt(themes?.cdpPort, 1024, 65535, activePort || DEFAULT_CDP_PORT);
    const exePath = cachedLauncherSnapshot?.exePath || findAntigravityExePath();
    const connected = hasOpenSessions();
    let title = '';
    for (const entry of sessions.values()) {
      if (entry.ws.readyState === 1 && entry.title) {
        title = entry.title;
        break;
      }
    }
    const lnkPath = cachedLauncherSnapshot?.shortcutLnkPath || paths?.cdpShortcutLnk || '';
    const vbsPath = cachedLauncherSnapshot?.launcherVbsPath || paths?.cdpLauncherVbs || '';
    const cmdPath = cachedLauncherSnapshot?.launcherCmdPath || paths?.cdpLauncherCmd || '';
    return {
      supported: hostInfo.hasWindowsHost,
      isWsl: hostInfo.isWsl,
      transport: activeTransport,
      port,
      connected,
      targetCount: sessions.size,
      styleApplied: Boolean(connected && isAnyStyleApplied()),
      hudInjected: Boolean(connected && isHudInjected()),
      hostLanguage: latestHostLanguage,
      liteMode: latestLiteMode,
      hostLocalized: Boolean(connected && isAnyHostLocalized()),
      targetTitle: connected ? title : '',
      shortcutLnkPath: lnkPath,
      launcherVbsPath: vbsPath,
      launcherCmdPath: cmdPath,
      launchCommand:
        cachedLauncherSnapshot?.launchCommand ||
        (vbsPath
          ? `wscript.exe //Nologo "${vbsPath}"`
          : exePath
            ? `"${exePath}" --remote-debugging-port=${port}`
            : ''),
      lastError: connected ? '' : lastError,
    };
  };

  const dispose = async ({ preserveHostDom = false } = {}) => {
    disposed = true;
    ensureLoops(false);
    if (!preserveHostDom) {
      await restoreHostI18nAll().catch(() => {});
      if (!(latestThemes?.hostThemeMode === 'inject' && isNativeWallpaperAlive())) {
        await removeCssAll().catch(() => {});
      }
      if (!isNativeMainProcessAlive()) {
        await removeHudAll().catch(() => {});
      }
    }
    closeAllSessions();
    closeWslProxy();
    clearCaches();
    activeBridgeCacheClearers.delete(clearCaches);
  };

  return {
    sync,
    syncHostLanguage,
    updateHudData,
    isHudInjected,
    getStatus,
    clearCaches,
    dispose,
  };
}
