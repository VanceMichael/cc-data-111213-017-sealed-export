import { createCipheriv, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * 仅用于演示与测试的合成资料生成器。全部密钥与明文都在临时目录内随机生成，
 * 不读取也不代表任何真实客户资料。
 */
export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function generateLabKey(keyId) {
  return { id: keyId, key: randomBytes(32) };
}

export async function writeLabKey(directory, record) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(join(directory, `${record.id}.json`),
    JSON.stringify({ id: record.id, key: record.key.toString('base64url') }), { mode: 0o600 });
}

export function generateSigningIdentity() {
  const pair = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: pair.privateKey
  };
}

export function signManifest(payload, privateKey) {
  const bytes = Buffer.from(JSON.stringify(payload));
  return {
    payload: bytes.toString('base64url'),
    signature: sign(null, bytes, privateKey).toString('base64url')
  };
}

export async function writeSignedManifest(directory, payload, privateKey, name = 'manifest.json') {
  const envelope = signManifest(payload, privateKey);
  const path = join(directory, name);
  await writeFile(path, JSON.stringify(envelope, null, 2), { mode: 0o600 });
  return path;
}

/**
 * @param {object} options
 * @param {string} options.directory
 * @param {string} options.exportId
 * @param {number} [options.version]
 * @param {Array<{keyId: string, plaintext: string|Buffer, file?: string,
 *   encryptAad?: object}>} options.segments 按位置顺序
 * @param {Map<string, Buffer>|Record<string, Buffer>} options.keys keyId → 32 字节密钥
 * @param {import('node:crypto').KeyObject} options.privateKey
 * @param {boolean} [options.shuffleManifestOrder] 打乱清单里的块数组顺序（位置字段仍然正确）
 */
export async function createSyntheticExport({
  directory, exportId, version = 1, segments, keys, privateKey, shuffleManifestOrder = false
}) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lookup = keys instanceof Map ? keys : new Map(Object.entries(keys));
  const cleartextParts = [];
  const blocks = [];

  for (const [position, segment] of segments.entries()) {
    const key = lookup.get(segment.keyId);
    if (!key) throw new Error(`合成资料缺少密钥 ${segment.keyId}`);
    const plaintext = Buffer.from(segment.plaintext);
    cleartextParts.push(plaintext);
    const aad = Buffer.from(JSON.stringify({ exportId, version, position }));
    const encryptAad = segment.encryptAad
      ? Buffer.from(JSON.stringify(segment.encryptAad)) : aad;
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(encryptAad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const file = segment.file ?? `chunk-${position}.bin`;
    await writeFile(join(directory, file), ciphertext, { mode: 0o600 });
    blocks.push({
      position, file, keyId: segment.keyId, alg: 'A256GCM',
      iv: iv.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
      aad: aad.toString('base64url'),
      sha256: digest(ciphertext)
    });
  }

  const cleartext = Buffer.concat(cleartextParts);
  const payload = {
    exportId, version,
    blocks: shuffleManifestOrder ? [...blocks].reverse() : blocks,
    cleartextSha256: digest(cleartext)
  };
  const manifestPath = await writeSignedManifest(directory, payload, privateKey);
  return { manifestPath, directory, payload, blocks, cleartext, cleartextSha256: digest(cleartext) };
}

export function flipByte(bytes, offset) {
  const copy = Buffer.from(bytes);
  copy[offset % copy.length] ^= 0xff;
  return copy;
}
