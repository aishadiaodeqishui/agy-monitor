import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  clearDiscoveredOAuthClientCache,
  discoverLocalOAuthClient,
  refreshAccessTokenForCredential,
} from '../sidecars/agy_monitor/backend/accounts.mjs';

test('discoverLocalOAuthClient bypasses Electron ASAR fs hook and refreshAccessTokenForCredential falls back across candidateClientIds', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-oauth-asar-'));
  const prevHadNoAsar = Object.prototype.hasOwnProperty.call(process, 'noAsar');
  const prevNoAsar = process.noAsar;
  const origStatSync = fs.statSync;
  const origReadFileSync = fs.readFileSync;
  try {
    const resDir = path.join(tmpRoot, 'resources');
    const binDir = path.join(resDir, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const fakeExe = path.join(tmpRoot, 'Antigravity.exe');
    const fakeAsar = path.join(resDir, 'app.asar');
    const fakeLs = path.join(binDir, 'language_server.exe');

    // Construct synthetic fixtures dynamically so secret scanners never false-positive on test literals
    const idDomain = ['.apps', 'googleusercontent', 'com'].join('.');
    const wrongId = `111111111111-${'0'.repeat(31)}1${idDomain}`;
    const personalId = `222222222222-${'0'.repeat(31)}2${idDomain}`;
    const secPrefix = ['GOC', 'SPX', '-'].join('');
    const secA = secPrefix + 'A'.repeat(28);
    const secB = secPrefix + 'B'.repeat(28);

    fs.writeFileSync(fakeExe, 'stub');
    fs.writeFileSync(fakeAsar, `...Personal accounts ... clientId: "${personalId}" ...`);
    fs.writeFileSync(fakeLs, `${wrongId}\0${personalId}\0${secA}\0${secB}\0`);

    // Simulate Electron's patched node:fs where statSync('...app.asar').isFile() is false unless process.noAsar === true
    fs.statSync = function patchedStatSync(p, ...rest) {
      if (String(p).endsWith('app.asar') && !process.noAsar) {
        return { isFile: () => false, isDirectory: () => true, size: 0 };
      }
      return origStatSync.call(fs, p, ...rest);
    };
    fs.readFileSync = function patchedReadFileSync(p, ...rest) {
      if (String(p).endsWith('app.asar') && !process.noAsar) {
        const err = new Error('EISDIR: illegal operation on a directory');
        err.code = 'EISDIR';
        throw err;
      }
      return origReadFileSync.call(fs, p, ...rest);
    };

    clearDiscoveredOAuthClientCache();
    const discovered = await discoverLocalOAuthClient({
      env: {},
      exePath: fakeExe,
      forceRefresh: true,
    });
    assert.ok(discovered);
    assert.equal(discovered.clientId, personalId);
    assert.deepEqual(discovered.candidateClientIds, [personalId, wrongId]);
    assert.equal(Object.prototype.hasOwnProperty.call(process, 'noAsar'), prevHadNoAsar);
    if (prevHadNoAsar) assert.equal(process.noAsar, prevNoAsar);

    // Even if clientId order puts wrongId first, refreshAccessTokenForCredential falls back to personalId on 401 unauthorized_client
    const triedPairs = [];
    const refreshed = await refreshAccessTokenForCredential(
      { token: { refresh_token: '1//0eTEST_FALLBACK_RT', expiry: '1970-01-01T00:00:00Z' } },
      {
        forceRefresh: true,
        oauthClient: {
          clientId: wrongId,
          clientSecret: secA,
          candidateClientIds: [wrongId, personalId],
          candidateSecrets: [secA, secB],
        },
        fetchImpl: async (_url, opts) => {
          const params = new URLSearchParams(String(opts?.body || ''));
          const cid = params.get('client_id');
          const sec = params.get('client_secret');
          triedPairs.push(`${cid}|${sec}`);
          if (cid === personalId && sec === secB) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ access_token: 'ya29.recovered_via_fallback', expires_in: 3600 }),
            };
          }
          return {
            ok: false,
            status: 401,
            text: async () => JSON.stringify({ error: 'unauthorized_client', error_description: 'Unauthorized' }),
          };
        },
      },
    );
    assert.equal(refreshed.accessToken, 'ya29.recovered_via_fallback');
    assert.equal(refreshed.renewed, true);
    assert.ok(triedPairs.includes(`${wrongId}|${secA}`));
    assert.ok(triedPairs.includes(`${personalId}|${secB}`));
  } finally {
    fs.statSync = origStatSync;
    fs.readFileSync = origReadFileSync;
    clearDiscoveredOAuthClientCache();
    if (prevHadNoAsar) process.noAsar = prevNoAsar;
    else delete process.noAsar;
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});
