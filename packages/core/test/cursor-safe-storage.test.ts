import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CursorSafeStorageError,
  isPlainCursorAccessToken,
  isSealedCursorAccessToken,
  resetCursorSafeStorageCache,
  sealCursorAccessTokenForTests,
  unwrapCursorAccessToken,
} from '../src/subscription/readers/cursor-safe-storage.js';

const PASSWORD = 'fixture-cursor-keychain-password';

function jwtFor(sub: string): string {
  return `header.${Buffer.from(JSON.stringify({ sub })).toString('base64url')}.sig`;
}

test('plaintext JWTs pass through unchanged for older Cursor builds', async () => {
  resetCursorSafeStorageCache();
  const jwt = jwtFor('auth0|user_plain');
  assert.equal(isPlainCursorAccessToken(jwt), true);
  assert.equal(isSealedCursorAccessToken(jwt), false);
  assert.equal(await unwrapCursorAccessToken(jwt, { platform: 'darwin' }), jwt);
});

test('CSV sync can skip Keychain while subscription reads may prompt once', async () => {
  resetCursorSafeStorageCache();
  const jwt = jwtFor('auth0|user_sealed');
  const sealed = sealCursorAccessTokenForTests(jwt, PASSWORD);
  assert.equal(isSealedCursorAccessToken(sealed), true);
  assert.match(sealed, /^cursor-safe-storage:v1:/);

  let keychainReads = 0;
  const readPassword = async () => {
    keychainReads += 1;
    return PASSWORD;
  };

  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, { platform: 'darwin', readKeychainPassword: readPassword }),
    (error: unknown) => error instanceof CursorSafeStorageError
      && error.kind === 'keychain-required'
      && /刷新|始终允许/.test(error.message),
  );
  assert.equal(keychainReads, 0);

  const plain = await unwrapCursorAccessToken(sealed, {
    platform: 'darwin',
    allowKeychainPrompt: true,
    readKeychainPassword: readPassword,
  });
  assert.equal(plain, jwt);
  assert.equal(keychainReads, 1);

  // After a successful grant, automatic reads reuse the in-memory cache with no prompt.
  assert.equal(
    await unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      readKeychainPassword: readPassword,
    }),
    jwt,
  );
  assert.equal(keychainReads, 1);
});

test('Keychain denial suppresses later auto prompts until a forced refresh', async () => {
  resetCursorSafeStorageCache();
  const { isCursorKeychainDenied } = await import('../src/subscription/readers/cursor-safe-storage.js');
  const jwt = jwtFor('auth0|user_denied');
  const sealed = sealCursorAccessTokenForTests(jwt, PASSWORD);
  let keychainReads = 0;

  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      allowKeychainPrompt: true,
      readKeychainPassword: async () => {
        keychainReads += 1;
        throw new Error('denied');
      },
    }),
    (error: unknown) => error instanceof CursorSafeStorageError && error.kind === 'keychain-denied',
  );
  assert.equal(keychainReads, 1);
  assert.equal(isCursorKeychainDenied(), true);

  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      allowKeychainPrompt: false,
      readKeychainPassword: async () => {
        keychainReads += 1;
        return PASSWORD;
      },
    }),
    (error: unknown) => error instanceof CursorSafeStorageError && error.kind === 'keychain-denied',
  );
  assert.equal(keychainReads, 1);

  assert.equal(
    await unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      allowKeychainPrompt: true,
      forceKeychainRefresh: true,
      readKeychainPassword: async () => {
        keychainReads += 1;
        return PASSWORD;
      },
    }),
    jwt,
  );
  assert.equal(keychainReads, 2);
  assert.equal(isCursorKeychainDenied(), false);
});

test('forceKeychainRefresh re-reads the keychain after a failed decrypt cache', async () => {
  resetCursorSafeStorageCache();
  const jwt = jwtFor('auth0|user_refresh');
  const sealed = sealCursorAccessTokenForTests(jwt, PASSWORD);
  let keychainReads = 0;
  const readPassword = async () => {
    keychainReads += 1;
    return keychainReads === 1 ? 'wrong-password' : PASSWORD;
  };

  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      allowKeychainPrompt: true,
      readKeychainPassword: readPassword,
    }),
    (error: unknown) => error instanceof CursorSafeStorageError && error.kind === 'decrypt-failed',
  );
  assert.equal(keychainReads, 1);

  assert.equal(
    await unwrapCursorAccessToken(sealed, {
      platform: 'darwin',
      allowKeychainPrompt: true,
      readKeychainPassword: readPassword,
      forceKeychainRefresh: true,
    }),
    jwt,
  );
  assert.equal(keychainReads, 2);
});

test('Windows and Linux sealed-token messages stay platform-specific', async () => {
  resetCursorSafeStorageCache();
  const jwt = jwtFor('auth0|user_win');
  const sealed = sealCursorAccessTokenForTests(jwt, PASSWORD);
  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, { platform: 'win32' }),
    (error: unknown) => error instanceof CursorSafeStorageError
      && error.kind === 'unsupported-platform'
      && error.message.includes('Windows')
      && !error.message.includes('钥匙串'),
  );
  await assert.rejects(
    () => unwrapCursorAccessToken(sealed, { platform: 'linux' }),
    (error: unknown) => error instanceof CursorSafeStorageError
      && error.kind === 'unsupported-platform'
      && error.message.includes('当前系统暂不支持')
      && !error.message.includes('钥匙串'),
  );
  assert.equal(
    await unwrapCursorAccessToken(sealed, {
      platform: 'win32',
      decryptString: () => jwt,
    }),
    jwt,
  );
});

test('malformed sealed payloads surface a structured error', async () => {
  resetCursorSafeStorageCache();
  await assert.rejects(
    () => unwrapCursorAccessToken('cursor-safe-storage:v1:@@@', { platform: 'darwin' }),
    (error: unknown) => error instanceof CursorSafeStorageError && error.kind === 'malformed',
  );
  await assert.rejects(
    () => unwrapCursorAccessToken('not-a-token', { platform: 'darwin' }),
    (error: unknown) => error instanceof CursorSafeStorageError && error.kind === 'malformed',
  );
});
