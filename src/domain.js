import { readFile } from 'node:fs/promises';
import { verify, createHash } from 'node:crypto';
import { dirname, join, isAbsolute, sep, resolve } from 'node:path';
import { ManifestSignatureError, ManifestInvalidError } from './errors.js';

export const sample = 'fixtures/manifest.json';
const SUPPORTED_ALGORITHMS = new Set(['A256GCM']);
const HEX_SHA256 = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function fail(message, details, cause) {
  throw new ManifestInvalidError({ ...details, reason: message }, cause);
}

// 校验清单结构，并核对每个块的附加认证数据（AAD）确实绑定到
// 这份导出的 exportId、version 和该块的 position——解密时只允许使用
// 清单登记的 AAD，防止块被挪到其他导出或其他位置。
export function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') fail('清单不是对象', {});
  const { exportId, version, blocks, cleartextSha256 } = manifest;
  if (typeof exportId !== 'string' || exportId.length === 0 || exportId.length > 128) {
    fail('exportId 不合法', {});
  }
  if (!Number.isInteger(version) || version < 1) fail('version 不合法', { exportId });
  if (!Array.isArray(blocks) || blocks.length === 0) fail('blocks 为空', { exportId });
  if (typeof cleartextSha256 !== 'string' || !HEX_SHA256.test(cleartextSha256)) {
    fail('cleartextSha256 不合法', { exportId });
  }
  const positions = new Set();
  for (const block of blocks) {
    const b = block || {};
    const base = { exportId, position: b.position };
    if (!Number.isInteger(b.position) || b.position < 0 || positions.has(b.position)) {
      fail('块位置缺失或重复', base);
    }
    positions.add(b.position);
    if (typeof b.file !== 'string' || !b.file || b.file.includes(sep) || isAbsolute(b.file)) {
      fail('块文件名不合法', base);
    }
    if (typeof b.keyId !== 'string' || b.keyId.length === 0) fail('块缺少 keyId', base);
    if (!SUPPORTED_ALGORITHMS.has(b.alg)) fail(`不支持的算法 ${b.alg}`, base);
    if (typeof b.iv !== 'string' || !BASE64URL.test(b.iv) || Buffer.from(b.iv, 'base64url').length !== 12) {
      fail('IV 必须是 12 字节 base64url', base);
    }
    if (typeof b.tag !== 'string' || !BASE64URL.test(b.tag) || Buffer.from(b.tag, 'base64url').length !== 16) {
      fail('GCM 标签必须是 16 字节 base64url', base);
    }
    if (typeof b.aad !== 'string' || !BASE64URL.test(b.aad)) fail('AAD 编码不合法', base);
    if (typeof b.sha256 !== 'string' || !HEX_SHA256.test(b.sha256)) fail('块摘要不合法', base);
    let aad;
    try { aad = JSON.parse(Buffer.from(b.aad, 'base64url').toString('utf8')); }
    catch (cause) { fail('AAD 不是合法 JSON', base, cause); }
    if (!aad || aad.exportId !== exportId || aad.version !== version || aad.position !== b.position) {
      fail('AAD 未绑定到该导出或该位置', base);
    }
  }
  return manifest;
}

// 验证清单来源：签名通过后才解析并校验结构。
// 返回的 payloadHash 作为接纳状态的绑定标识，防止重试时混入其他版本。
export async function inspect(filename) {
  const manifestPath = resolve(filename);
  let envelope;
  try {
    envelope = JSON.parse(await readFile(manifestPath, 'utf8'));
  } catch (cause) {
    throw new ManifestInvalidError({ reason: '清单信封不是合法 JSON' }, cause);
  }
  const publicKey = await readFile(join(dirname(manifestPath), 'signing-public.txt'));
  const payload = Buffer.from(envelope.payload, 'base64url');
  let valid;
  try {
    valid = verify(null, payload, publicKey, Buffer.from(envelope.signature, 'base64url'));
  } catch (cause) {
    throw new ManifestSignatureError({ reason: '签名或公钥材料无法解析' }, cause);
  }
  if (!valid) throw new ManifestSignatureError();
  let manifest;
  try {
    manifest = JSON.parse(payload.toString('utf8'));
  } catch (cause) {
    throw new ManifestInvalidError({ reason: '清单负载不是合法 JSON' }, cause);
  }
  validateManifest(manifest);
  return {
    signed: true,
    manifest,
    payloadHash: createHash('sha256').update(payload).digest('hex'),
  };
}
