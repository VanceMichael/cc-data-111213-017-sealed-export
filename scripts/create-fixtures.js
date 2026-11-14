// 重建全部合成资料：受控钥匙目录、密文块、签名清单。
// 运行后 fixtures/ 是一个全新但自洽的合成集合，不包含任何真实客户资料。
import { mkdir, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes, createCipheriv, createHash, sign } from 'node:crypto';
import { join } from 'node:path';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

const keys = {
  'lab-2026': randomBytes(32),    // 旧钥匙（轮换前）
  'lab-2026-r2': randomBytes(32), // 新钥匙（轮换后）
  'lab-2027': randomBytes(32),    // 下一批钥匙：只用于加密，不发布到受控目录
};

await mkdir('fixtures/keys', { recursive: true });
for (const [id, key] of Object.entries(keys)) {
  if (id === 'lab-2027') continue; // lab-2027 不进入受控目录，用于演示“未领取到钥匙”
  await writeFile(join('fixtures/keys', `${id}.json`), JSON.stringify({ id, key: key.toString('base64url') }));
}

const pair = generateKeyPairSync('ed25519');
const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });

async function buildExport(directory, { exportId, version, rows, keyIdFor }) {
  await mkdir(directory, { recursive: true });
  const blocks = [];
  for (const [position, text] of rows.entries()) {
    const keyId = keyIdFor(position);
    const aad = Buffer.from(JSON.stringify({ exportId, version, position }));
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keys[keyId], iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
    await writeFile(join(directory, `chunk-${position}.bin`), ciphertext);
    blocks.push({ position, file: `chunk-${position}.bin`, keyId, alg: 'A256GCM',
      iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
      aad: aad.toString('base64url'), sha256: sha256(ciphertext) });
  }
  const payload = Buffer.from(JSON.stringify({ exportId, version, blocks, cleartextSha256: sha256(rows.join('')) }));
  await writeFile(join(directory, 'signing-public.txt'), publicPem);
  await writeFile(join(directory, 'manifest.json'), JSON.stringify({ payload: payload.toString('base64url'),
    signature: sign(null, payload, pair.privateKey).toString('base64url') }, null, 2));
}

// export-A v1：全部使用旧钥匙（保持既有布局与行为）
await buildExport('fixtures', { exportId: 'export-A', version: 1,
  rows: ['探头,温度\n', 'P1,3.1\n', 'P2,4.2\n'], keyIdFor: () => 'lab-2026' });
// export-A v2：轮换期间混合 key ID，块 0 用旧钥匙，块 1、2 用新钥匙
await buildExport('fixtures/rotation', { exportId: 'export-A', version: 2,
  rows: ['探头,温度\n', 'P1,3.3\n', 'P2,4.4\n'], keyIdFor: position => (position === 0 ? 'lab-2026' : 'lab-2026-r2') });
// export-B v1：引用受控目录中不存在的 lab-2027，用于演示授权领取失败
await buildExport('fixtures/missing-key', { exportId: 'export-B', version: 1,
  rows: ['批次,结果\n', 'B1,合格\n'], keyIdFor: () => 'lab-2027' });
