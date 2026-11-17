import { readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { ERROR_CODES, SealedError } from './errors.js';

/**
 * 密钥只从受控目录按清单里已签名确认的 keyId 领取，绝不遍历目录试解。
 * 目录内每个密钥文件形如 `<keyId>.json`，内容为 { "id": "<keyId>", "key": "<base64url|base64|hex>" }。
 * keyId 必须通过白名单校验，避免被清单字段用作路径穿透。
 */
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MIN_KEY_BYTES = 32;

function decodeKeyMaterial(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (/^[a-f0-9]{64}$/i.test(value)) return Buffer.from(value, 'hex');
  let bytes;
  try { bytes = Buffer.from(value, 'base64url'); } catch { return null; }
  // 同时接受标准 base64：Node 的 base64url 解码器对 '+' '/' 也宽容，这里只做长度校验。
  return bytes.length >= MIN_KEY_BYTES ? bytes : null;
}

export function assertKeyId(keyId, context = {}) {
  if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
    throw new SealedError(ERROR_CODES.KEY_UNUSABLE, '密钥标识格式不受控', { ...context, keyId: undefined, detail: 'keyId 未通过白名单校验' });
  }
  return keyId;
}

export class KeyStore {
  constructor(directory) {
    this.directory = resolve(directory);
    this.cache = new Map();
  }

  /** 只返回该 keyId 对应的密钥；不存在就是 KEY_MISSING，不做任何其它密钥的尝试。 */
  async get(keyId, context = {}) {
    assertKeyId(keyId, context);
    if (this.cache.has(keyId)) return this.cache.get(keyId);

    const path = join(this.directory, `${keyId}.json`);
    // 防御：解析后必须仍位于受控目录内。
    if (!resolve(path).startsWith(this.directory + sep)) {
      throw new SealedError(ERROR_CODES.KEY_UNUSABLE, '密钥路径越出受控目录', { ...context, keyId });
    }

    let raw;
    try {
      if (!(await stat(path)).isFile()) throw new Error('not a file');
      raw = await readFile(path, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw new SealedError(ERROR_CODES.KEY_MISSING, `受控目录中缺少密钥 ${keyId}`, { ...context, keyId });
      }
      throw new SealedError(ERROR_CODES.KEY_UNUSABLE, `密钥 ${keyId} 无法读取`, { ...context, keyId, detail: error.message });
    }

    let record;
    try { record = JSON.parse(raw); }
    catch (error) {
      throw new SealedError(ERROR_CODES.KEY_UNUSABLE, `密钥 ${keyId} 不是合法 JSON`, { ...context, keyId, detail: error.message });
    }
    if (record?.id !== keyId) {
      throw new SealedError(ERROR_CODES.KEY_UNUSABLE, `密钥文件内容与标识 ${keyId} 不一致`, { ...context, keyId });
    }
    const material = decodeKeyMaterial(record.key);
    if (!material || material.length !== 32) {
      throw new SealedError(ERROR_CODES.KEY_UNUSABLE, `密钥 ${keyId} 不是 256 位密钥`, { ...context, keyId });
    }

    this.cache.set(keyId, material);
    return material;
  }

  /** 只用于运维排查：列出受控目录里出现过哪些 keyId，不解密也不返回密钥。 */
  async availableKeyIds() {
    try {
      const names = await readdir(this.directory);
      return names.filter(name => name.endsWith('.json'))
        .map(name => name.slice(0, -'.json'.length))
        .filter(name => KEY_ID_PATTERN.test(name))
        .sort();
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
  }
}
