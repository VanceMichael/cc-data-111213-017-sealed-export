import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, copyFile, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomBytes, createCipheriv, createHash, sign } from 'node:crypto';
import { Archive, digest } from '../src/archive.js';
import { Intake, IntakeError, KeyDirectory } from '../src/intake.js';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// 在临时目录合成一份导出：钥匙、密文块、签名清单，返回签名私钥以便构造篡改变体
async function makeExport(directory, { exportId = 'exp-t', version = 1, rows, keys, keyIdFor, encryptAadFor }) {
  await mkdir(directory, { recursive: true });
  const pair = generateKeyPairSync('ed25519');
  await writeFile(join(directory, 'signing-public.txt'), pair.publicKey.export({ type: 'spki', format: 'pem' }));
  const blocks = [];
  for (const [position, text] of rows.entries()) {
    const keyId = keyIdFor(position);
    const manifestAad = Buffer.from(JSON.stringify({ exportId, version, position }));
    // encryptAadFor 只影响加密时使用的 AAD；清单中始终记录规范 AAD，用于构造“密文与清单不符”的场景
    const encryptAad = encryptAadFor?.(position)
      ? Buffer.from(JSON.stringify(encryptAadFor(position))) : manifestAad;
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keys.get(keyId), iv);
    cipher.setAAD(encryptAad);
    const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
    await writeFile(join(directory, `chunk-${position}.bin`), ciphertext);
    blocks.push({ position, file: `chunk-${position}.bin`, keyId, alg: 'A256GCM',
      iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
      aad: manifestAad.toString('base64url'), sha256: sha256(ciphertext) });
  }
  const manifest = { exportId, version, blocks, cleartextSha256: sha256(rows.join('')) };
  await writeManifest(directory, manifest, pair.privateKey);
  return { manifest, privateKey: pair.privateKey };
}

async function writeManifest(directory, manifest, privateKey) {
  const payload = Buffer.from(JSON.stringify(manifest));
  await writeFile(join(directory, 'manifest.json'), JSON.stringify({ payload: payload.toString('base64url'),
    signature: sign(null, payload, privateKey).toString('base64url') }, null, 2));
}

async function writeKeys(directory, keys, only) {
  await mkdir(directory, { recursive: true });
  for (const [id, key] of keys) {
    if (only && !only.includes(id)) continue;
    await writeFile(join(directory, `${id}.json`), JSON.stringify({ id, key: key.toString('base64url') }));
  }
}

function makeKeys(...ids) {
  return new Map(ids.map(id => [id, randomBytes(32)]));
}

function makeIntake(root, archiveDirectory, keysDirectory) {
  const archive = new Archive(archiveDirectory);
  return { intake: new Intake({ root, archive, keys: new KeyDirectory(keysDirectory) }), archive };
}

async function journalEntries(root) {
  return (await readFile(join(root, 'journal.log'), 'utf8')).split('\n').filter(Boolean).map(JSON.parse);
}

test('既有清单可完整接纳，暂存明文随接纳清除', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const { intake, archive } = makeIntake(join(folder, 'in'), join(folder, 'arc'), 'fixtures/keys');
    const { receipt, session, resumed, alreadyAccepted } = await intake.run('fixtures/manifest.json');
    assert.equal(resumed, false);
    assert.equal(alreadyAccepted, false);
    assert.equal(session.status, 'accepted');
    assert.equal((await archive.read(receipt.sha256)).toString(), '探头,温度\nP1,3.1\nP2,4.2\n');
    assert.deepEqual(receipt.metadata.keyIds, ['lab-2026']);
    const sessionDir = join(folder, 'in', 'sessions', 'export-A', 'v1');
    assert.deepEqual((await readdir(sessionDir)).sort(), ['session.json']); // staging 已清除
    assert.equal((await archive.receipts()).length, 1);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('轮换期间新旧 key ID 共存，按块精确领取', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const { intake, archive } = makeIntake(join(folder, 'in'), join(folder, 'arc'), 'fixtures/keys');
    const { receipt } = await intake.run('fixtures/rotation/manifest.json');
    assert.equal(receipt.metadata.version, 2);
    assert.deepEqual(receipt.metadata.keyIds, ['lab-2026', 'lab-2026-r2']);
    assert.equal((await archive.read(receipt.sha256)).toString(), '探头,温度\nP1,3.3\nP2,4.4\n');
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('未领取到钥匙报授权问题而非文件损坏，读者看不到任何内容', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const { intake, archive } = makeIntake(join(folder, 'in'), join(folder, 'arc'), 'fixtures/keys');
    const error = await intake.run('fixtures/missing-key/manifest.json').then(() => null, error => error);
    assert.equal(error.code, 'KEY_MISSING');
    assert.equal(error.category, 'authorization');
    assert.match(error.message, /授权领取问题，不是文件损坏/);
    assert.equal((await archive.receipts()).length, 0);
    const { sessions } = await intake.status();
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].status, 'failed');
    assert.equal(sessions[0].lastFailure.category, 'authorization');
    // key ID 路径穿越同样按授权失败处理，不会读出目录外文件
    await assert.rejects(new KeyDirectory('fixtures/keys').load('../../etc/passwd'), /格式不合法/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('缺块、块损坏、顺序调换分别报告为不同的完整性问题', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const copySet = async name => {
      const directory = join(folder, name);
      await mkdir(directory, { recursive: true });
      for (const file of ['manifest.json', 'signing-public.txt', 'chunk-0.bin', 'chunk-1.bin', 'chunk-2.bin']) {
        await copyFile(join('fixtures', file), join(directory, file));
      }
      return directory;
    };
    // 缺块
    const missing = await copySet('missing');
    await rm(join(missing, 'chunk-1.bin'));
    let error = await makeIntake(join(folder, 'in1'), join(folder, 'a1'), 'fixtures/keys')
      .intake.run(join(missing, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'BLOCK_MISSING');
    assert.equal(error.category, 'integrity');
    assert.equal(error.details.position, 1);
    // 中间块损坏
    const corrupted = await copySet('corrupted');
    const damagedPath = join(corrupted, 'chunk-1.bin');
    const bytes = await readFile(damagedPath);
    bytes[0] ^= 0xff;
    await writeFile(damagedPath, bytes);
    error = await makeIntake(join(folder, 'in2'), join(folder, 'a2'), 'fixtures/keys')
      .intake.run(join(corrupted, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'BLOCK_DIGEST_MISMATCH');
    assert.equal(error.details.position, 1);
    // 顺序调换
    const swapped = await copySet('swapped');
    await rename(join(swapped, 'chunk-0.bin'), join(swapped, 'chunk.tmp'));
    await rename(join(swapped, 'chunk-2.bin'), join(swapped, 'chunk-0.bin'));
    await rename(join(swapped, 'chunk.tmp'), join(swapped, 'chunk-2.bin'));
    error = await makeIntake(join(folder, 'in3'), join(folder, 'a3'), 'fixtures/keys')
      .intake.run(join(swapped, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'BLOCK_DIGEST_MISMATCH');
    assert.equal(error.details.position, 0);
    assert.match(error.message, /调换/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('清单声明的 key ID 即使不对也绝不试其他钥匙', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k-old', 'k-new');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys);
    // 块实际用 k-old 加密，清单却声明 k-new：即使 k-old 就在目录里，也必须认证失败
    const set = join(folder, 'set');
    await mkdir(set, { recursive: true });
    const pair = generateKeyPairSync('ed25519');
    await writeFile(join(set, 'signing-public.txt'), pair.publicKey.export({ type: 'spki', format: 'pem' }));
    const rows = ['甲\n', '乙\n'];
    const blocks = [];
    for (const [position, text] of rows.entries()) {
      const aad = Buffer.from(JSON.stringify({ exportId: 'exp-t', version: 1, position }));
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keys.get('k-old'), iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
      await writeFile(join(set, `chunk-${position}.bin`), ciphertext);
      blocks.push({ position, file: `chunk-${position}.bin`, keyId: 'k-new', alg: 'A256GCM',
        iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
        aad: aad.toString('base64url'), sha256: sha256(ciphertext) });
    }
    await writeManifest(set, { exportId: 'exp-t', version: 1, blocks, cleartextSha256: sha256(rows.join('')) }, pair.privateKey);
    const error = await makeIntake(join(folder, 'in'), join(folder, 'arc'), keysDir)
      .intake.run(join(set, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'BLOCK_AUTH_FAILED');
    assert.equal(error.category, 'integrity');
    assert.equal(error.details.keyId, 'k-new');
    assert.match(error.message, /不会尝试其他钥匙/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('附加认证数据必须指向当前导出与位置', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k1');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys);
    // 清单内 AAD 字段被改成别的位置（重新签名）
    const setA = join(folder, 'set-a');
    const { manifest, privateKey } = await makeExport(setA, { rows: ['甲\n', '乙\n', '丙\n'], keys, keyIdFor: () => 'k1' });
    manifest.blocks[1].aad = Buffer.from(JSON.stringify({ exportId: 'exp-t', version: 1, position: 2 })).toString('base64url');
    await writeManifest(setA, manifest, privateKey);
    let error = await makeIntake(join(folder, 'in1'), join(folder, 'a1'), keysDir)
      .intake.run(join(setA, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'AAD_MISMATCH');
    assert.equal(error.details.position, 1);
    // 密文用别的 AAD 加密，清单 AAD 正确：GCM 认证失败
    const setB = join(folder, 'set-b');
    await makeExport(setB, { rows: ['甲\n', '乙\n'], keys, keyIdFor: () => 'k1',
      encryptAadFor: position => (position === 1 ? { exportId: 'exp-t', version: 1, position: 9 } : undefined) });
    // encryptAadFor 返回 undefined 的位置回退到默认 AAD
    error = await makeIntake(join(folder, 'in2'), join(folder, 'a2'), keysDir)
      .intake.run(join(setB, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'BLOCK_AUTH_FAILED');
    assert.equal(error.details.position, 1);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('整体明文摘要不符时不发布任何内容', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k1');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys);
    const set = join(folder, 'set');
    const { manifest, privateKey } = await makeExport(set, { rows: ['甲\n', '乙\n'], keys, keyIdFor: () => 'k1' });
    manifest.cleartextSha256 = '0'.repeat(64);
    await writeManifest(set, manifest, privateKey);
    const { intake, archive } = makeIntake(join(folder, 'in'), join(folder, 'arc'), keysDir);
    const error = await intake.run(join(set, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'CLEARTEXT_DIGEST_MISMATCH');
    assert.equal((await archive.receipts()).length, 0);
    const { sessions } = await intake.status();
    assert.equal(sessions[0].lastFailure.code, 'CLEARTEXT_DIGEST_MISMATCH');
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('断点续传不重复解密已认证的块', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k-old', 'k-new');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys, ['k-old']); // 新钥匙尚未下发
    const set = join(folder, 'set');
    await makeExport(set, { rows: ['甲\n', '乙\n', '丙\n'], keys,
      keyIdFor: position => (position === 0 ? 'k-old' : 'k-new') });
    const root = join(folder, 'in');
    const archiveDir = join(folder, 'arc');
    const first = makeIntake(root, archiveDir, keysDir);
    const error = await first.intake.run(join(set, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'KEY_MISSING');
    assert.equal(error.details.keyId, 'k-new');
    // 新钥匙到位后继续
    await writeKeys(keysDir, keys);
    const second = makeIntake(root, archiveDir, keysDir);
    const { receipt, session, resumed } = await second.intake.run(join(set, 'manifest.json'));
    assert.equal(resumed, true);
    assert.equal(session.status, 'accepted');
    assert.equal((await second.archive.read(receipt.sha256)).toString(), '甲\n乙\n丙\n');
    const verified = (await journalEntries(root)).filter(entry => entry.event === 'block-verified');
    assert.deepEqual(verified.map(entry => entry.position), [0, 1, 2]);
    assert.equal(verified.filter(entry => entry.position === 0).length, 1); // 块 0 只解密过一次
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('不同版本会话互不拼凑，同版本不同清单被拒绝合并', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k1');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys);
    const root = join(folder, 'in');
    const archiveDir = join(folder, 'arc');
    // v1 缺块，会话保持失败
    const v1 = join(folder, 'v1');
    await makeExport(v1, { version: 1, rows: ['一\n'], keys, keyIdFor: () => 'k1' });
    await rm(join(v1, 'chunk-0.bin'));
    const first = makeIntake(root, archiveDir, keysDir);
    const missing = await first.intake.run(join(v1, 'manifest.json')).then(() => null, error => error);
    assert.equal(missing.code, 'BLOCK_MISSING');
    // v2 独立会话正常接纳
    const v2 = join(folder, 'v2');
    await makeExport(v2, { version: 2, rows: ['二\n'], keys, keyIdFor: () => 'k1' });
    const second = makeIntake(root, archiveDir, keysDir);
    const { session } = await second.intake.run(join(v2, 'manifest.json'));
    assert.equal(session.status, 'accepted');
    // 同一 exportId+version 出现内容不同的清单：拒绝合并
    const v1altered = join(folder, 'v1-altered');
    await makeExport(v1altered, { version: 1, rows: ['一改\n'], keys, keyIdFor: () => 'k1' });
    const conflict = await makeIntake(root, archiveDir, keysDir)
      .intake.run(join(v1altered, 'manifest.json')).then(() => null, error => error);
    assert.equal(conflict.code, 'SESSION_MANIFEST_MISMATCH');
    const { sessions } = await makeIntake(root, archiveDir, keysDir).intake.status();
    assert.equal(sessions.length, 2);
    assert.equal(sessions.find(session => session.version === 1).status, 'failed');
    assert.equal(sessions.find(session => session.version === 2).status, 'accepted');
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('保留策略清理失败残留与日志，保留已接纳回执', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const keys = makeKeys('k1');
    const keysDir = join(folder, 'keys');
    await writeKeys(keysDir, keys);
    const root = join(folder, 'in');
    const archiveDir = join(folder, 'arc');
    // 一份失败（缺块），一份接纳
    const bad = join(folder, 'bad');
    await makeExport(bad, { exportId: 'exp-bad', rows: ['坏\n'], keys, keyIdFor: () => 'k1' });
    await rm(join(bad, 'chunk-0.bin'));
    await makeIntake(root, archiveDir, keysDir).intake.run(join(bad, 'manifest.json')).catch(() => {});
    const good = join(folder, 'good');
    await makeExport(good, { exportId: 'exp-good', rows: ['好\n'], keys, keyIdFor: () => 'k1' });
    await makeIntake(root, archiveDir, keysDir).intake.run(join(good, 'manifest.json'));
    assert.equal((await makeIntake(root, archiveDir, keysDir).intake.status()).sessions.length, 2);
    // TTL 未到期：失败残留保留
    const kept = await makeIntake(root, archiveDir, keysDir).intake.prune({ olderThanMs: 10 ** 9 });
    assert.deepEqual(kept.removedSessions, []);
    assert.equal((await makeIntake(root, archiveDir, keysDir).intake.status()).sessions.length, 2);
    // 全部过期：失败残留清除，已接纳会话与回执保留
    const pruned = await makeIntake(root, archiveDir, keysDir).intake.prune({ olderThanMs: 0 });
    assert.deepEqual(pruned.removedSessions, ['exp-bad/v1']);
    const { sessions } = await makeIntake(root, archiveDir, keysDir).intake.status();
    assert.deepEqual(sessions.map(session => session.exportId), ['exp-good']);
    const archive = new Archive(archiveDir);
    assert.equal((await archive.receipts()).length, 1);
    const journal = await journalEntries(root);
    assert.ok(journal.some(entry => entry.event === 'pruned'));
    assert.ok(journal.every(entry => !JSON.stringify(entry).includes('好\n'))); // 日志不含明文
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('签名无效的清单一律拒绝', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const set = join(folder, 'set');
    await mkdir(set, { recursive: true });
    for (const file of ['manifest.json', 'signing-public.txt', 'chunk-0.bin']) {
      await copyFile(join('fixtures', file), join(set, file));
    }
    const envelope = JSON.parse(await readFile(join(set, 'manifest.json'), 'utf8'));
    const payload = Buffer.from(envelope.payload, 'base64url');
    payload[0] ^= 0xff; // 篡改清单内容，签名必然失效
    envelope.payload = payload.toString('base64url');
    await writeFile(join(set, 'manifest.json'), JSON.stringify(envelope));
    const error = await makeIntake(join(folder, 'in'), join(folder, 'arc'), 'fixtures/keys')
      .intake.run(join(set, 'manifest.json')).then(() => null, error => error);
    assert.equal(error.code, 'MANIFEST_SIGNATURE_INVALID');
    assert.equal(error.category, 'manifest');
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('重复领取幂等，不产生第二份回执', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'intake-'));
  try {
    const root = join(folder, 'in');
    const archiveDir = join(folder, 'arc');
    const first = await makeIntake(root, archiveDir, 'fixtures/keys').intake.run('fixtures/manifest.json');
    const second = await makeIntake(root, archiveDir, 'fixtures/keys').intake.run('fixtures/manifest.json');
    assert.equal(second.alreadyAccepted, true);
    assert.equal(second.receipt.id, first.receipt.id);
    assert.equal((await new Archive(archiveDir).receipts()).length, 1);
  } finally { await rm(folder, { recursive: true, force: true }); }
});
