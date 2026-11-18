// 合成导出包构建器：只生成合成资料与合成密钥，绝不接触真实客户资料。
// 供测试与演示脚本构造轮换、损坏、调换等场景。
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes, createCipheriv, createHash, sign } from 'node:crypto';
import { join, resolve } from 'node:path';

export function generateKey(id) {
  return { id, alg: 'A256GCM', key: randomBytes(32).toString('base64url') };
}

function aadFor(exportId, version, position) {
  return Buffer.from(JSON.stringify({ exportId, version, position }));
}

// 在指定目录生成一份完整导出：清单、签名公钥、加密块。
// keyByPosition(position) 返回该块使用的密钥条目，用于演示新旧 key ID 共存。
export async function buildExport(directory, {
  exportId = 'export-A',
  version = 1,
  records = ['探头,温度\n', 'P1,3.1\n', 'P2,4.2\n'],
  keyByPosition,
} = {}) {
  const root = resolve(directory);
  await mkdir(join(root, 'keys'), { recursive: true });
  // 默认整份导出使用同一把合成钥匙；轮换场景由调用方按位置返回新旧钥匙。
  const defaultKey = generateKey('lab-2026');
  const pickKey = keyByPosition ?? (() => defaultKey);
  const pair = generateKeyPairSync('ed25519');
  const blocks = [];
  const cleartext = [];
  const usedKeys = new Map();

  for (const [position, text] of records.entries()) {
    const keyEntry = pickKey(position, records.length);
    if (!usedKeys.has(keyEntry.id)) {
      usedKeys.set(keyEntry.id, keyEntry);
      await writeFile(join(root, 'keys', `${keyEntry.id}.json`), JSON.stringify(keyEntry));
    }
    const keyBytes = Buffer.from(keyEntry.key, 'base64url');
    const aad = aadFor(exportId, version, position);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keyBytes, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(text, 'utf8')), cipher.final()]);
    const file = `chunk-${position}.bin`;
    await writeFile(join(root, file), ciphertext);
    blocks.push({
      position, file, keyId: keyEntry.id, alg: 'A256GCM',
      iv: iv.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
      aad: aad.toString('base64url'),
      sha256: createHash('sha256').update(ciphertext).digest('hex'),
    });
    cleartext.push(Buffer.from(text, 'utf8'));
  }

  const fullText = Buffer.concat(cleartext);
  const manifest = {
    exportId, version, blocks,
    cleartextSha256: createHash('sha256').update(fullText).digest('hex'),
  };
  const payload = Buffer.from(JSON.stringify(manifest));
  await writeFile(join(root, 'signing-public.txt'),
    pair.publicKey.export({ type: 'spki', format: 'pem' }));
  await writeFile(join(root, 'manifest.json'), JSON.stringify({
    payload: payload.toString('base64url'),
    signature: sign(null, payload, pair.privateKey).toString('base64url'),
  }, null, 2));

  return { root, manifest, cleartext: fullText, keyIds: [...usedKeys.keys()], signingKey: pair.privateKey };
}

// 重新对清单签名（篡改块后需要保持签名有效，以便隔离到摘要/认证层的错误）。
export async function resignManifest(root, manifest, privateKey) {
  const payload = Buffer.from(JSON.stringify(manifest));
  await writeFile(join(root, 'manifest.json'), JSON.stringify({
    payload: payload.toString('base64url'),
    signature: sign(null, payload, privateKey).toString('base64url'),
  }));
}

// 场景构造：破坏中间块的密文字节（保持签名与清单登记不变）。
export async function tamperBlockBytes(root, manifest, position) {
  const { readFile } = await import('node:fs/promises');
  const block = manifest.blocks.find(b => b.position === position);
  const path = join(root, block.file);
  const bytes = Buffer.from(await readFile(path));
  bytes[0] ^= 0xff;
  await writeFile(path, bytes);
}

// 场景构造：交换两个块的文件名（块位置与文件内容不再对应，AAD/摘要会拦截）。
export async function swapBlockFiles(root, manifest, p1, p2) {
  const { rename } = await import('node:fs/promises');
  const f1 = manifest.blocks.find(b => b.position === p1).file;
  const f2 = manifest.blocks.find(b => b.position === p2).file;
  const tmp = `${f1}.swap-tmp`;
  await rename(join(root, f1), join(root, tmp));
  await rename(join(root, f2), join(root, f1));
  await rename(join(root, tmp), join(root, f2));
}

// 场景构造：删除一个块。
export async function removeBlock(root, manifest, position) {
  const block = manifest.blocks.find(b => b.position === position);
  await rm(join(root, block.file), { force: true });
}

// 场景构造：用错误密钥重加密指定块（清单仍登记原 key ID，模拟授权不匹配）。
export async function reencryptWithWrongKey(root, manifest, position, wrongKeyEntry) {
  const { readFile } = await import('node:fs/promises');
  const block = manifest.blocks.find(b => b.position === position);
  const wrong = Buffer.from(wrongKeyEntry.key, 'base64url');
  const iv = randomBytes(12);
  const aad = Buffer.from(block.aad, 'base64url');
  const cipher = createCipheriv('aes-256-gcm', wrong, iv);
  cipher.setAAD(aad);
  const dummy = Buffer.concat([cipher.update(Buffer.from('not-the-plaintext')), cipher.final()]);
  await writeFile(join(root, block.file), dummy);
}
