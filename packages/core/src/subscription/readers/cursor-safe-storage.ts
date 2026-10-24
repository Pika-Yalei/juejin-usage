import { execFile } from 'node:child_process';
import { createCipheriv, createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Cursor wraps Electron/Chromium safeStorage ciphertext with this prefix in state.vscdb. */
export const CURSOR_SAFE_STORAGE_PREFIX = 'cursor-safe-storage:v1:';

const KEYCHAIN_SERVICE = 'Cursor Safe Storage';
const KEYCHAIN_ACCOUNT = 'Cursor Key';
const PBKDF2_SALT = 'saltysalt';
const PBKDF2_ITERATIONS = 1003;
const PBKDF2_KEY_LENGTH = 16;
const V10_PREFIX = 'v10';

export type CursorSafeStorageErrorKind =
  | 'unsupported-platform'
  | 'keychain-required'
  | 'keychain-denied'
  | 'decrypt-failed'
  | 'malformed';

export class CursorSafeStorageError extends Error {
  constructor(readonly kind: CursorSafeStorageErrorKind, message: string) {
    super(message);
    this.name = 'CursorSafeStorageError';
  }
}

const KEYCHAIN_PROMPT = '点击刷新并允许钥匙串访问（建议选「始终允许」）';
const KEYCHAIN_DENIED = '无法读取 Cursor 登录信息，请点刷新并在钥匙串弹窗选择「始终允许」';

export interface CursorSafeStorageOptions {
  platform?: NodeJS.Platform;
  /** Injected decryptor for Windows DPAPI / tests; receives raw v10/v11 ciphertext. */
  decryptString?: (encrypted: Buffer) => string;
  readKeychainPassword?: () => Promise<string>;
  /**
   * When false/omitted, never invoke `security` if the Keychain password is not
   * already cached — used by background CSV sync.
   * Subscription reads should pass true unless a denial was already recorded.
   */
  allowKeychainPrompt?: boolean;
  /** Drop any cached Keychain password before reading (manual refresh). */
  forceKeychainRefresh?: boolean;
}

let cachedKeychainPassword: string | null = null;
let keychainInFlight: Promise<string> | null = null;
/** After the user denies Keychain access, skip auto prompts until a manual refresh. */
let keychainDeniedThisSession = false;

/** Test seam / process shutdown. */
export function resetCursorSafeStorageCache(): void {
  cachedKeychainPassword = null;
  keychainInFlight = null;
  keychainDeniedThisSession = false;
}

/** True after a Keychain denial in this process; subscription auto-loads should not re-prompt. */
export function isCursorKeychainDenied(): boolean {
  return keychainDeniedThisSession;
}

export function isSealedCursorAccessToken(value: string): boolean {
  return value.startsWith(CURSOR_SAFE_STORAGE_PREFIX);
}

/** True for a three-segment JWT that older Cursor builds stored in plaintext. */
export function isPlainCursorAccessToken(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function decodeSealedCursorCiphertext(value: string): Buffer {
  if (!isSealedCursorAccessToken(value)) {
    throw new CursorSafeStorageError('malformed', 'Cursor access token is not sealed');
  }
  const encoded = value.slice(CURSOR_SAFE_STORAGE_PREFIX.length).trim();
  if (!encoded) throw new CursorSafeStorageError('malformed', 'Cursor sealed token is empty');
  const ciphertext = Buffer.from(encoded, 'base64');
  if (ciphertext.length < 4) {
    throw new CursorSafeStorageError('malformed', 'Cursor sealed token ciphertext is truncated');
  }
  return ciphertext;
}

/** Chromium/Electron macOS os_crypt key derivation. */
export function deriveCursorOsCryptKey(keychainPassword: string): Buffer {
  return pbkdf2Sync(keychainPassword, PBKDF2_SALT, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH, 'sha1');
}

/**
 * Decrypt Chromium v10 ciphertext. Some Electron builds store a raw 16-byte key
 * as base64 in Keychain; try PBKDF2 first, then that direct key.
 */
export function decryptCursorV10Ciphertext(ciphertext: Buffer, keychainPassword: string): string {
  if (ciphertext.subarray(0, V10_PREFIX.length).toString('utf8') !== V10_PREFIX) {
    throw new CursorSafeStorageError('malformed', 'Unsupported Cursor storage format');
  }
  const body = ciphertext.subarray(V10_PREFIX.length);
  const iv = Buffer.alloc(16, 0x20);
  const attempts: Buffer[] = [deriveCursorOsCryptKey(keychainPassword)];
  try {
    const raw = Buffer.from(keychainPassword, 'base64');
    if (raw.length === PBKDF2_KEY_LENGTH) attempts.push(raw);
  } catch {
    // Ignore invalid base64; PBKDF2 path remains.
  }

  let lastError: unknown;
  for (const key of attempts) {
    try {
      const decipher = createDecipheriv('aes-128-cbc', key, iv);
      const plain = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
      if (!plain.trim()) throw new Error('empty plaintext');
      return plain;
    } catch (error) {
      lastError = error;
    } finally {
      key.fill(0);
    }
  }
  throw new CursorSafeStorageError(
    'decrypt-failed',
    lastError instanceof Error ? lastError.message : 'Unable to decrypt Cursor access token',
  );
}

/** Build a sealed token for unit tests (macOS os_crypt v10 scheme). */
export function sealCursorAccessTokenForTests(plaintext: string, keychainPassword: string): string {
  const key = deriveCursorOsCryptKey(keychainPassword);
  try {
    const cipher = createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
    const ciphertext = Buffer.concat([
      Buffer.from(V10_PREFIX),
      cipher.update(Buffer.from(plaintext, 'utf8')),
      cipher.final(),
    ]);
    return `${CURSOR_SAFE_STORAGE_PREFIX}${ciphertext.toString('base64')}`;
  } finally {
    key.fill(0);
  }
}

async function readMacKeychainPassword(): Promise<string> {
  // Do not use osascript/System Events to raise SecurityAgent: that triggers a
  // separate Automation permission dialog for "Juejin Usage" controlling System Events.
  const { stdout } = await execFileAsync(
    '/usr/bin/security',
    ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w'],
    { encoding: 'utf8', timeout: 60_000, maxBuffer: 4096 },
  );
  const password = stdout.trim();
  if (!password) throw new Error('Cursor keychain item is empty');
  return password;
}

/**
 * Resolve a Cursor accessToken cell to a usable JWT.
 * Plaintext JWTs from older builds pass through unchanged.
 */
export async function unwrapCursorAccessToken(
  value: string,
  options: CursorSafeStorageOptions = {},
): Promise<string> {
  const trimmed = value.trim();
  if (!trimmed) throw new CursorSafeStorageError('malformed', 'Cursor access token is empty');
  if (!isSealedCursorAccessToken(trimmed)) {
    if (isPlainCursorAccessToken(trimmed)) return trimmed;
    throw new CursorSafeStorageError('malformed', 'Cursor access token format is unsupported');
  }

  const platform = options.platform ?? process.platform;
  const ciphertext = decodeSealedCursorCiphertext(trimmed);

  if (platform === 'darwin') {
    if (options.forceKeychainRefresh) {
      cachedKeychainPassword = null;
      keychainDeniedThisSession = false;
    }
    if (!cachedKeychainPassword) {
      // Open/focus and CSV sync must not pop the Keychain dialog; only an explicit
      // subscription refresh passes allowKeychainPrompt.
      if (!options.allowKeychainPrompt) {
        throw new CursorSafeStorageError(
          keychainDeniedThisSession ? 'keychain-denied' : 'keychain-required',
          keychainDeniedThisSession ? KEYCHAIN_DENIED : KEYCHAIN_PROMPT,
        );
      }
      try {
        keychainInFlight ??= (options.readKeychainPassword ?? readMacKeychainPassword)();
        cachedKeychainPassword = await keychainInFlight;
        if (!cachedKeychainPassword) throw new Error('Empty Cursor keychain password');
        keychainDeniedThisSession = false;
      } catch (error) {
        if (error instanceof CursorSafeStorageError) throw error;
        cachedKeychainPassword = null;
        keychainDeniedThisSession = true;
        throw new CursorSafeStorageError('keychain-denied', KEYCHAIN_DENIED);
      } finally {
        keychainInFlight = null;
      }
    }
    try {
      return decryptCursorV10Ciphertext(ciphertext, cachedKeychainPassword);
    } catch (error) {
      cachedKeychainPassword = null;
      if (error instanceof CursorSafeStorageError) throw error;
      throw new CursorSafeStorageError('decrypt-failed', '无法解密 Cursor 登录信息，请打开 Cursor 后重试');
    }
  }

  if (platform === 'win32') {
    const decryptString = options.decryptString;
    if (!decryptString) {
      throw new CursorSafeStorageError(
        'unsupported-platform',
        '当前环境无法解密 Cursor 的加密登录信息',
      );
    }
    try {
      const plain = decryptString(ciphertext).trim();
      if (!plain) throw new Error('empty plaintext');
      return plain;
    } catch {
      throw new CursorSafeStorageError('decrypt-failed', '无法解密 Cursor 登录信息，请打开 Cursor 后重试');
    }
  }

  throw new CursorSafeStorageError(
    'unsupported-platform',
    '当前系统暂不支持读取 Cursor 的加密登录信息',
  );
}
