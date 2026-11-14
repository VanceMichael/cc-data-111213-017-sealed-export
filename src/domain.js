import { readFile } from 'node:fs/promises';
import { createHash, verify } from 'node:crypto';
import { dirname, join } from 'node:path';
export const sample = 'fixtures/manifest.json';
export async function inspect(filename) {
  const envelope = JSON.parse(await readFile(filename, 'utf8'));
  const publicKey = await readFile(join(dirname(filename), 'signing-public.txt'));
  const payload = Buffer.from(envelope.payload, 'base64url');
  const valid = verify(null, payload, publicKey, Buffer.from(envelope.signature, 'base64url'));
  if (!valid) throw new Error('导出清单签名无效');
  return { signed: true, manifest: JSON.parse(payload),
    manifestSha256: createHash('sha256').update(payload).digest('hex') };
}
