import { mkdir as ensureFixtureDirectory } from 'node:fs/promises';
await ensureFixtureDirectory('fixtures', {recursive:true});

import { mkdir, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes, createCipheriv, createHash, sign } from 'node:crypto';
await mkdir('fixtures/keys', { recursive: true });
const key = randomBytes(32);
await writeFile('fixtures/keys/lab-2026.json', JSON.stringify({ id: 'lab-2026', key: key.toString('base64url') }));
const blocks = [];
for (const [position, text] of ['探头,温度\n', 'P1,3.1\n', 'P2,4.2\n'].entries()) {
  const aad = Buffer.from(JSON.stringify({ exportId: 'export-A', version: 1, position }));
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
  await writeFile(`fixtures/chunk-${position}.bin`, ciphertext);
  blocks.push({ position, file: `chunk-${position}.bin`, keyId: 'lab-2026', alg: 'A256GCM',
    iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), aad: aad.toString('base64url'),
    sha256: createHash('sha256').update(ciphertext).digest('hex') });
}
const pair = generateKeyPairSync('ed25519');
await writeFile('fixtures/signing-public.txt', pair.publicKey.export({ type: 'spki', format: 'pem' }));
const payload = Buffer.from(JSON.stringify({ exportId: 'export-A', version: 1, blocks,
  cleartextSha256: createHash('sha256').update('探头,温度\nP1,3.1\nP2,4.2\n').digest('hex') }));
await writeFile('fixtures/manifest.json', JSON.stringify({ payload: payload.toString('base64url'),
  signature: sign(null, payload, pair.privateKey).toString('base64url') }, null, 2));
