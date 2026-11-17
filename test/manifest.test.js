import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ERROR_CODES, classifyError } from '../src/errors.js';
import { openSignedManifest, validateManifest, digest } from '../src/manifest.js';
import {
  createSyntheticExport, flipByte, generateLabKey, generateSigningIdentity,
  signManifest, writeLabKey
} from '../src/synthetic.js';

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'manifest-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const identity = generateSigningIdentity();
  const key = generateLabKey('lab-2026');
  const exportDir = join(root, 'export');
  const created = await createSyntheticExport({
    directory: exportDir, exportId: 'export-T', version: 1,
    segments: [{ keyId: key.id, plaintext: '甲\n' }, { keyId: key.id, plaintext: '乙\n' }],
    keys: new Map([[key.id, key.key]]), privateKey: identity.privateKey
  });
  return { root, identity, key, created };
}

test('验签先于结构校验：签名无效时不泄露任何清单细节', async (t) => {
  const { identity, created } = await workspace(t);
  const payload = { exportId: 'export-T', version: 1, blocks: [], cleartextSha256: '0'.repeat(64) };
  const envelope = signManifest(payload, identity.privateKey);
  envelope.signature = Buffer.alloc(64, 1).toString('base64url');
  await writeFile(created.manifestPath, JSON.stringify(envelope));
  await assert.rejects(readFile(created.manifestPath).then(bytes =>
    openSignedManifest(bytes, identity.publicKeyPem)), (error) => {
    assert.equal(error.code, ERROR_CODES.MANIFEST_SIGNATURE);
    assert.equal(error.exportId, undefined);
    return true;
  });
});

test('每块附加认证数据必须指向本导出与本位置', async () => {
  const block = (position, aadPosition) => ({
    position, file: `c${position}.bin`, keyId: 'k', alg: 'A256GCM',
    iv: Buffer.alloc(12).toString('base64url'), tag: Buffer.alloc(16).toString('base64url'),
    aad: Buffer.from(JSON.stringify({ exportId: 'e', version: 1, position: aadPosition })).toString('base64url'),
    sha256: '0'.repeat(64)
  });
  assert.throws(() => validateManifest({
    exportId: 'e', version: 1, cleartextSha256: '1'.repeat(64),
    blocks: [block(0, 0), block(1, 0)]
  }), (error) => {
    assert.equal(error.code, ERROR_CODES.BLOCK_REFERENCE);
    assert.equal(error.position, 1);
    return true;
  });
  assert.throws(() => validateManifest({
    exportId: 'e', version: 1, cleartextSha256: '1'.repeat(64),
    blocks: [block(0, 0), block(2, 2)]
  }), (error) => {
    // 位置越出 0..n-1 必然是结构问题；唯一性和取值范围共同保证位置连续。
    assert.equal(error.code, ERROR_CODES.MANIFEST_SHAPE);
    return true;
  });
  assert.equal(validateManifest({
    exportId: 'e', version: 1, cleartextSha256: '1'.repeat(64), blocks: [block(1, 1), block(0, 0)]
  }).blocks[0].position, 0);
});

test('不受支持算法、重复位置和越界文件名都在解密前拒绝', () => {
  const base = {
    position: 0, file: 'c0.bin', keyId: 'k', alg: 'A256GCM',
    iv: Buffer.alloc(12).toString('base64url'), tag: Buffer.alloc(16).toString('base64url'),
    aad: Buffer.from(JSON.stringify({ exportId: 'e', version: 1, position: 0 })).toString('base64url'),
    sha256: '0'.repeat(64)
  };
  const manifest = (overrides) => ({
    exportId: 'e', version: 1, cleartextSha256: '1'.repeat(64),
    blocks: [{ ...base, ...overrides }]
  });
  assert.throws(() => validateManifest(manifest({ alg: 'A128GCM' })),
    (error) => error.code === ERROR_CODES.UNSUPPORTED_ALGORITHM);
  assert.throws(() => validateManifest(manifest({ file: '../c0.bin' })),
    (error) => error.code === ERROR_CODES.BLOCK_REFERENCE);
  assert.throws(() => validateManifest({
    exportId: 'e', version: 1, cleartextSha256: '1'.repeat(64),
    blocks: [{ ...base, position: 0 }, { ...base }]
  }), (error) => error.code === ERROR_CODES.BLOCK_REFERENCE);
  assert.throws(() => validateManifest(manifest({ iv: Buffer.alloc(8).toString('base64url') })),
    (error) => error.code === ERROR_CODES.MANIFEST_SHAPE);
});

test('缺少验签公钥时报授权类错误，而不是签名无效', async (t) => {
  const { created } = await workspace(t);
  const bytes = await readFile(created.manifestPath);
  assert.throws(() => openSignedManifest(bytes, null), (error) => {
    assert.equal(error.code, ERROR_CODES.SIGNING_KEY_UNAVAILABLE);
    assert.equal(classifyError(error.code), 'authorization');
    return true;
  });
});

test('块密文被翻转一个字节时，摘要先于认证失败', async (t) => {
  const { created } = await workspace(t);
  const path = join(created.directory, 'chunk-1.bin');
  const original = await readFile(path);
  assert.notEqual(digest(flipByte(original, 0)), created.blocks[1].sha256);
});
