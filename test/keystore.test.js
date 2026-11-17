import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ERROR_CODES, SealedError, classifyError } from '../src/errors.js';
import { KeyStore } from '../src/keystore.js';

async function folder(t) {
  const directory = await mkdtemp(join(tmpdir(), 'keystore-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('密钥只按 keyId 领取，不会因大小写或路径变体命中别的密钥', async (t) => {
  const directory = await folder(t);
  await writeFile(join(directory, 'lab-2026.json'),
    JSON.stringify({ id: 'lab-2026', key: Buffer.alloc(32, 7).toString('base64url') }));
  const store = new KeyStore(directory);
  const key = await store.get('lab-2026');
  assert.equal(key.length, 32);
  await assert.rejects(store.get('lab-2027'), (error) => {
    assert.equal(error.code, ERROR_CODES.KEY_MISSING);
    assert.equal(classifyError(error.code), 'authorization');
    return true;
  });
  await assert.rejects(store.get('../lab-2026'), (error) => error.code === ERROR_CODES.KEY_UNUSABLE);
  await assert.rejects(store.get('lab-2026/../lab-2026'), (error) => error.code === ERROR_CODES.KEY_UNUSABLE);
});

test('密钥文件损坏或身份不符时与“缺密钥”区分开', async (t) => {
  const directory = await folder(t);
  await writeFile(join(directory, 'broken.json'), '{not json');
  await writeFile(join(directory, 'mismatch.json'),
    JSON.stringify({ id: 'other', key: Buffer.alloc(32).toString('base64url') }));
  await writeFile(join(directory, 'short.json'),
    JSON.stringify({ id: 'short', key: Buffer.alloc(16).toString('base64url') }));
  const store = new KeyStore(directory);
  await assert.rejects(store.get('broken'), (error) => error.code === ERROR_CODES.KEY_UNUSABLE);
  await assert.rejects(store.get('mismatch'), (error) => error.code === ERROR_CODES.KEY_UNUSABLE);
  await assert.rejects(store.get('short'), (error) => error.code === ERROR_CODES.KEY_UNUSABLE);
  await assert.rejects(store.get('absent'), (error) => error.code === ERROR_CODES.KEY_MISSING);
  assert.deepEqual(await store.availableKeyIds(), ['broken', 'mismatch', 'short']);
});

test('缺失的受控目录不会被当成“全部密钥都缺失”以外的错误', async (t) => {
  const directory = await folder(t);
  const store = new KeyStore(join(directory, 'empty'));
  assert.deepEqual(await store.availableKeyIds(), []);
  await assert.rejects(store.get('lab-2026'), (error) => error.code === ERROR_CODES.KEY_MISSING);
});

test('错误分类把缺密钥归为授权、认证与摘要归为完整性', () => {
  assert.equal(classifyError(ERROR_CODES.KEY_MISSING), 'authorization');
  assert.equal(classifyError(ERROR_CODES.AUTH_FAILED), 'integrity');
  assert.equal(classifyError(ERROR_CODES.CIPHERTEXT_DIGEST), 'integrity');
  assert.equal(classifyError(ERROR_CODES.BLOCK_MISSING), 'integrity');
  assert.equal(classifyError(ERROR_CODES.RESUME_MISMATCH), 'state');
});

test('既有清单仍可验签，未签名清单被拒绝', async (t) => {
  const { loadSignedManifest } = await import('../src/manifest.js');
  const opened = await loadSignedManifest('fixtures/manifest.json');
  assert.equal(opened.manifest.exportId, 'export-A');
  assert.equal(opened.manifest.blocks[1].keyId, 'lab-2026');
  const directory = await folder(t);
  await mkdir(join(directory), { recursive: true });
  await writeFile(join(directory, 'signing-public.txt'), await (await import('node:fs/promises')).readFile('fixtures/signing-public.txt'));
  await writeFile(join(directory, 'manifest.json'), JSON.stringify({
    payload: Buffer.from(JSON.stringify({ exportId: 'x', version: 1, blocks: [], cleartextSha256: '0'.repeat(64) })).toString('base64url'),
    signature: Buffer.alloc(64).toString('base64url')
  }));
  await assert.rejects(loadSignedManifest(join(directory, 'manifest.json')), (error) => {
    assert.ok(error instanceof SealedError);
    assert.equal(error.code, ERROR_CODES.MANIFEST_SIGNATURE);
    return true;
  });
});
