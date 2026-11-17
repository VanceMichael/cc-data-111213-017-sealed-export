import { readFile } from 'node:fs/promises';
import { createHash, verify } from 'node:crypto';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { ERROR_CODES, SealedError } from './errors.js';

const SHA256_HEX = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const SAFE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SUPPORTED_ALG = 'A256GCM';

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function decodeBase64Url(value, field, expectedBytes, context) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `字段 ${field} 不是合法 base64url`, context);
  }
  const bytes = Buffer.from(value, 'base64url');
  // 严格模式：解码后再编码必须一致，拒绝 Node 宽容解码掩盖的截断或多余字符。
  if (bytes.toString('base64url') !== value) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `字段 ${field} 不是规范 base64url`, context);
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE,
      `字段 ${field} 长度应为 ${expectedBytes} 字节，实际 ${bytes.length}`, context);
  }
  return bytes;
}

function requireString(value, field, context) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `缺少字段 ${field}`, context);
  }
  return value;
}

function requirePosition(value, field, context, max) {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `字段 ${field} 必须是非负整数`, context);
  }
  return value;
}

/**
 * 解析并校验清单结构。这里不做任何解密，只确认：
 * - 导出标识/版本存在且块位置从 0 连续排列、不重复；
 * - 每块的算法受支持、IV/Tag/摘要长度正确；
 * - 每块声明的附加认证数据确实指向“这份导出的这个位置”，
 *   避免把另一份导出或另一个位置的块拼进当前资料。
 */
export function validateManifest(manifest) {
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, '清单必须是 JSON 对象');
  }
  const exportId = requireString(manifest.exportId, 'exportId');
  if (!Number.isInteger(manifest.version) || manifest.version < 1) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, 'version 必须是正整数', { exportId });
  }
  const version = manifest.version;
  const context = { exportId, version };

  if (!Array.isArray(manifest.blocks) || manifest.blocks.length === 0) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, 'blocks 必须是非空数组', context);
  }
  if (!SHA256_HEX.test(manifest.cleartextSha256 ?? '')) {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, 'cleartextSha256 格式不正确', context);
  }

  const count = manifest.blocks.length;
  const seenPositions = new Set();
  const seenFiles = new Set();
  const blocks = manifest.blocks.map((block, index) => {
    const blockContext = { ...context, position: Number.isInteger(block?.position) ? block.position : undefined };
    if (block === null || typeof block !== 'object' || Array.isArray(block)) {
      throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `第 ${index} 个块不是对象`, { ...context, position: index });
    }
    const position = requirePosition(block.position, 'position', blockContext, count - 1);
    if (seenPositions.has(position)) {
      throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, `块位置 ${position} 重复`, blockContext);
    }
    seenPositions.add(position);

    if (block.alg !== SUPPORTED_ALG) {
      throw new SealedError(ERROR_CODES.UNSUPPORTED_ALGORITHM,
        `不支持的算法 ${String(block.alg)}`, blockContext);
    }
    const file = requireString(block.file, 'file', blockContext);
    if (basename(file) !== file || !SAFE_FILENAME.test(file)) {
      throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, `块文件名不受控：${file}`, blockContext);
    }
    if (seenFiles.has(file)) {
      throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, `块文件 ${file} 被引用多次`, blockContext);
    }
    seenFiles.add(file);

    const keyId = requireString(block.keyId, 'keyId', blockContext);
    const iv = decodeBase64Url(block.iv, 'iv', 12, blockContext);
    const tag = decodeBase64Url(block.tag, 'tag', 16, blockContext);
    const aad = decodeBase64Url(block.aad, 'aad', undefined, blockContext);
    if (!SHA256_HEX.test(block.sha256 ?? '')) {
      throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, '块摘要格式不正确', blockContext);
    }

    // 附加认证数据必须与签名清单自身的导出标识/版本/位置一致。
    let aadRecord;
    try { aadRecord = JSON.parse(aad.toString('utf8')); }
    catch { throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, '块附加认证数据不是合法 JSON', blockContext); }
    if (aadRecord?.exportId !== exportId || aadRecord?.version !== version || aadRecord?.position !== position) {
      throw new SealedError(ERROR_CODES.BLOCK_REFERENCE,
        '块的附加认证数据与清单的导出/版本/位置不一致', blockContext);
    }

    return Object.freeze({ position, file, keyId, alg: block.alg, iv, tag, aad, sha256: block.sha256 });
  });

  for (let position = 0; position < count; position += 1) {
    if (!seenPositions.has(position)) {
      throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, `块位置 ${position} 缺失，块顺序不连续`, context);
    }
  }
  blocks.sort((a, b) => a.position - b.position);

  return Object.freeze({
    exportId, version, cleartextSha256: manifest.cleartextSha256, blocks: Object.freeze(blocks)
  });
}

/**
 * 先验证清单来源（签名），再做结构校验。manifestDigest 是对签名载荷字节的摘要，
 * 用作接纳日志的版本绑定，重试时据此拒绝拼接不同版本的块。
 */
export function openSignedManifest(envelopeBytes, publicKey) {
  let envelope;
  try { envelope = JSON.parse(envelopeBytes.toString('utf8')); }
  catch { throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, '清单封装不是合法 JSON'); }
  if (typeof envelope?.payload !== 'string' || typeof envelope?.signature !== 'string') {
    throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, '清单封装缺少 payload 或 signature');
  }
  const payload = decodeBase64Url(envelope.payload, 'payload', undefined, {});
  const signature = decodeBase64Url(envelope.signature, 'signature', undefined, {});

  let payloadJson;
  try { payloadJson = JSON.parse(payload.toString('utf8')); }
  catch { throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, '清单载荷不是合法 JSON'); }

  if (!publicKey) {
    throw new SealedError(ERROR_CODES.SIGNING_KEY_UNAVAILABLE, '缺少清单验签公钥');
  }
  let valid;
  try { valid = verify(null, payload, publicKey, signature); }
  catch (error) {
    throw new SealedError(ERROR_CODES.SIGNING_KEY_UNAVAILABLE, '清单验签公钥不可用', { detail: error.message });
  }
  // 验签通过前不把载荷里的 exportId/version 当作可信信息带给运维，
  // 否则伪造清单可以冒充某份导出；文件路径本身已足以定位来源。
  if (!valid) {
    throw new SealedError(ERROR_CODES.MANIFEST_SIGNATURE, '导出清单签名无效');
  }

  const manifest = validateManifest(payloadJson);
  return Object.freeze({
    manifest,
    manifestDigest: digest(payload),
    signedBytes: payload
  });
}

/** 从磁盘读取清单与同目录下的验签公钥。公钥可由调用方显式指定。 */
export async function loadSignedManifest(manifestPath, { publicKeyPath } = {}) {
  const absolute = resolve(manifestPath);
  let envelopeBytes;
  try { envelopeBytes = await readFile(absolute); }
  catch (error) {
    if (error?.code === 'ENOENT') throw new SealedError(ERROR_CODES.MANIFEST_SHAPE, `找不到清单文件 ${manifestPath}`);
    throw error;
  }
  let publicKey = null;
  const keyPath = publicKeyPath ? resolve(publicKeyPath) : join(dirname(absolute), 'signing-public.txt');
  try { publicKey = await readFile(keyPath); }
  catch (error) {
    if (error?.code !== 'ENOENT' || publicKeyPath) {
      throw new SealedError(ERROR_CODES.SIGNING_KEY_UNAVAILABLE, '清单验签公钥不可读', { detail: error.message });
    }
  }
  const opened = openSignedManifest(envelopeBytes, publicKey);
  return Object.freeze({ ...opened, manifestPath: absolute, directory: dirname(absolute) });
}

/** 解析并限制块密文的磁盘位置，确保不会跳出资料目录。 */
export function resolveBlockPath(manifestDirectory, file) {
  const path = resolve(manifestDirectory, file);
  const root = resolve(manifestDirectory);
  if (path !== resolve(root, file) || !path.startsWith(root + sep)) {
    throw new SealedError(ERROR_CODES.BLOCK_REFERENCE, `块文件越出资料目录：${file}`);
  }
  return path;
}
