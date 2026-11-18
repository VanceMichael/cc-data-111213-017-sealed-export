import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { MissingKeyError } from './errors.js';

const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SUPPORTED_ALGORITHMS = new Set(['A256GCM']);

// 本地受控密钥目录：每个文件是一份授权 { id, key(base64url, 32 字节) }。
// 只允许按清单给出的 key ID 精确领取，不提供“遍历全部密钥试解”的入口。
export class KeyStore {
  constructor(directory, clock = () => new Date()) {
    this.directory = resolve(directory);
    this.clock = clock;
    // 仅记录访问审计：哪个 key ID 被领取、是否命中；不记录密钥本身。
    this.accessLog = [];
  }

  async listKeyIds() {
    let names;
    try {
      names = (await readdir(this.directory)).filter(n => n.endsWith('.json')).sort();
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return [];
      throw error;
    }
    const ids = [];
    for (const name of names) {
      try {
        const entry = JSON.parse(await readFile(join(this.directory, name), 'utf8'));
        if (entry && typeof entry.id === 'string' && KEY_ID_PATTERN.test(entry.id)) ids.push(entry.id);
      } catch { /* 无法解析的授权文件不参与领取 */ }
    }
    return [...new Set(ids)].sort();
  }

  // 精确领取：只读取与 key ID 匹配的授权文件，返回算法所需的原始密钥字节。
  async claim(keyId, context = {}) {
    const entry = await this.#loadEntry(keyId, context);
    if (!SUPPORTED_ALGORITHMS.has(entry.alg)) {
      throw new MissingKeyError({ keyId, reason: `不支持的密钥算法 ${entry.alg}` });
    }
    let bytes;
    try {
      bytes = Buffer.from(entry.key, 'base64url');
    } catch (cause) {
      throw new MissingKeyError({ keyId, reason: '密钥材料编码无效' }, cause);
    }
    if (bytes.length !== 32) throw new MissingKeyError({ keyId, reason: '密钥长度不是 32 字节' });
    return { keyId: entry.id, alg: entry.alg, bytes };
  }

  async #loadEntry(keyId, context) {
    if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
      throw new MissingKeyError({ keyId: String(keyId), reason: 'key ID 格式不合法' });
    }
    const path = join(this.directory, `${keyId}.json`);
    try {
      const info = await stat(path);
      if (!info.isFile()) throw new MissingKeyError({ keyId, reason: '授权条目不是普通文件' });
      let entry;
      try {
        entry = JSON.parse(await readFile(path, 'utf8'));
      } catch (cause) {
        this.accessLog.push({ at: this.clock().toISOString(), keyId, granted: false, reason: '授权条目无法解析', context });
        throw new MissingKeyError({ keyId, reason: '授权条目无法解析' }, cause);
      }
      if (!entry || entry.id !== keyId || typeof entry.key !== 'string') {
        throw new MissingKeyError({ keyId, reason: '授权条目内容与 key ID 不一致' });
      }
      this.accessLog.push({ at: this.clock().toISOString(), keyId, granted: true, context });
      return { id: entry.id, alg: entry.alg || 'A256GCM', key: entry.key };
    } catch (error) {
      if (error instanceof MissingKeyError) {
        this.accessLog.push({ at: this.clock().toISOString(), keyId, granted: false, reason: error.details.reason, context });
        throw error;
      }
      if (error && (error.code === 'ENOENT' || error.code === 'ENOTDIR')) {
        this.accessLog.push({ at: this.clock().toISOString(), keyId, granted: false, reason: '受控目录中没有该授权', context });
        throw new MissingKeyError({ keyId, reason: '受控目录中没有该授权' });
      }
      throw error;
    }
  }
}
