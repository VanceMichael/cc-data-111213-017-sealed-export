import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { KeyStore } from '../src/keystore.js';
import { MissingKeyError } from '../src/errors.js';

async function withTemp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'keystore-'));
  try { await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

const keyEntry = (id = 'lab-2026') => ({ id, alg: 'A256GCM', key: randomBytes(32).toString('base64url') });

test('按 key ID 精确领取授权，返回 32 字节原始密钥', async () => withTemp(async dir => {
  const entry = keyEntry();
  await writeFile(join(dir, 'lab-2026.json'), JSON.stringify(entry));
  const store = new KeyStore(dir);
  const granted = await store.claim('lab-2026');
  assert.equal(granted.keyId, 'lab-2026');
  assert.equal(granted.alg, 'A256GCM');
  assert.equal(granted.bytes.length, 32);
  assert.deepEqual((await store.listKeyIds()), ['lab-2026']);
}));

test('新旧 key ID 可共存，只领取清单指定的那一个', async () => withTemp(async dir => {
  await writeFile(join(dir, 'lab-2026.json'), JSON.stringify(keyEntry('lab-2026')));
  await writeFile(join(dir, 'lab-2027.json'), JSON.stringify(keyEntry('lab-2027')));
  const store = new KeyStore(dir);
  const granted = await store.claim('lab-2027', { position: 1 });
  assert.equal(granted.keyId, 'lab-2027');
  assert.deepEqual(store.accessLog.map(e => e.keyId), ['lab-2027']);
  assert.equal(store.accessLog[0].granted, true);
}));

test('缺少授权时抛出分类错误 MISSING_KEY，且不触碰其他密钥', async () => withTemp(async dir => {
  await writeFile(join(dir, 'lab-2026.json'), JSON.stringify(keyEntry('lab-2026')));
  const store = new KeyStore(dir);
  await assert.rejects(store.claim('lab-2099'), error => {
    assert.ok(error instanceof MissingKeyError);
    assert.equal(error.code, 'MISSING_KEY');
    assert.equal(error.details.keyId, 'lab-2099');
    return true;
  });
  assert.equal(store.accessLog[0].granted, false);
}));

test('密钥长度错误与非法 key ID 都报 MISSING_KEY', async () => withTemp(async dir => {
  await writeFile(join(dir, 'short.json'), JSON.stringify({ id: 'short', key: randomBytes(16).toString('base64url') }));
  const store = new KeyStore(dir);
  await assert.rejects(store.claim('short'), error => error.code === 'MISSING_KEY');
  await assert.rejects(store.claim('../escape'), error => error.code === 'MISSING_KEY');
  await assert.rejects(store.claim('a/b'), error => error.code === 'MISSING_KEY');
}));

test('不存在的受控目录报缺授权而不是文件系统错误', async () => withTemp(async dir => {
  const store = new KeyStore(join(dir, 'absent'));
  await assert.rejects(store.claim('lab-2026'), error => error.code === 'MISSING_KEY');
  assert.deepEqual(await store.listKeyIds(), []);
}));

test('审计日志只记录 key ID 与命中情况，不记录密钥材料', async () => withTemp(async dir => {
  const entry = keyEntry();
  await writeFile(join(dir, 'lab-2026.json'), JSON.stringify(entry));
  const store = new KeyStore(dir);
  await store.claim('lab-2026');
  await assert.rejects(store.claim('nope'));
  assert.ok(!JSON.stringify(store.accessLog).includes(entry.key));
}));

test('空目录与损坏授权文件被安全忽略', async () => withTemp(async dir => {
  await mkdir(join(dir, 'empty'), { recursive: true });
  const store = new KeyStore(join(dir, 'empty'));
  assert.deepEqual(await store.listKeyIds(), []);
  await writeFile(join(dir, 'broken.json'), '不是 JSON');
  const store2 = new KeyStore(dir);
  assert.deepEqual(await store2.listKeyIds(), []);
  await assert.rejects(store2.claim('broken'), error => error.code === 'MISSING_KEY');
}));
