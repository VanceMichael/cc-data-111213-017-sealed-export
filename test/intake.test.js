import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Archive } from '../src/archive.js';
import { ERROR_CODES, classifyError } from '../src/errors.js';
import { IntakeService } from '../src/intake.js';
import { KeyStore } from '../src/keystore.js';
import { digest } from '../src/manifest.js';
import {
  createSyntheticExport, flipByte, generateLabKey, generateSigningIdentity,
  writeLabKey, writeSignedManifest
} from '../src/synthetic.js';

async function harness(t) {
  const root = await mkdtemp(join(tmpdir(), 'intake-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const identity = generateSigningIdentity();
  const publicKeyPath = join(root, 'signing-public.txt');
  await writeFile(publicKeyPath, identity.publicKeyPem);
  const keysDirectory = join(root, 'keys');
  await mkdir(keysDirectory, { recursive: true });
  const stateDirectory = join(root, 'state');
  const keyA = generateLabKey('lab-2026');
  const keyB = generateLabKey('lab-2027');
  await writeLabKey(keysDirectory, keyA);
  await writeLabKey(keysDirectory, keyB);
  const archive = new Archive(join(stateDirectory, 'archive'));
  const service = new IntakeService({
    stateDirectory, keyStore: new KeyStore(keysDirectory), archive,
    signingPublicKeyPath: publicKeyPath
  });
  await service.initialize();
  return { root, identity, publicKeyPath, keysDirectory, stateDirectory, keyA, keyB, service, archive };
}

function segments(count, keyId, prefix = 'row') {
  return Array.from({ length: count }, (_, index) => ({ keyId, plaintext: `${prefix},${index}\n` }));
}

async function walk(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await walk(path));
    else found.push(path);
  }
  return found;
}

test('新旧 keyId 共存时按块声明的 keyId 领取，不遍历试解', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'mix'), exportId: 'export-mix', version: 1,
    segments: [{ keyId: h.keyA.id, plaintext: 'a\n' }, { keyId: h.keyB.id, plaintext: 'b\n' },
      { keyId: h.keyA.id, plaintext: 'c\n' }],
    keys: new Map([[h.keyA.id, h.keyA.key], [h.keyB.id, h.keyB.key]]),
    privateKey: h.identity.privateKey
  });
  const result = await h.service.accept({ manifestPath: created.manifestPath });
  assert.equal(result.status, 'published');
  const readable = await h.archive.read(result.receipt.sha256);
  assert.equal(readable.toString(), 'a\nb\nc\n');
  assert.equal(result.receipt.metadata.exportId, 'export-mix');
});

test('缺密钥是授权阻塞，补钥后可继续，且期间没有明文落盘', async (t) => {
  const h = await harness(t);
  const future = generateLabKey('lab-2028');
  const created = await createSyntheticExport({
    directory: join(h.root, 'future'), exportId: 'export-future', version: 1,
    segments: [{ keyId: h.keyA.id, plaintext: 'first\n' }, { keyId: future.id, plaintext: 'later\n' }],
    keys: new Map([[h.keyA.id, h.keyA.key], [future.id, future.key]]),
    privateKey: h.identity.privateKey
  });
  const error = await h.service.accept({ manifestPath: created.manifestPath }).then(
    () => assert.fail('应当缺少密钥'), (caught) => caught);
  assert.equal(error.code, ERROR_CODES.KEY_MISSING);
  assert.equal(classifyError(error.code), 'authorization');
  assert.equal(error.phase, 'blocked');
  assert.equal(error.stagedRetained, true);
  assert.equal(error.position, 1);
  const blocked = await h.service.store.readJournal(error.intakeId);
  assert.equal(blocked.phase, 'blocked');
  // 已认证块以密文暂存，状态目录里没有明文。
  for (const path of await walk(h.stateDirectory)) {
    const bytes = await readFile(path);
    assert.ok(!bytes.toString('latin1').includes('first'), `明文出现在 ${path}`);
  }
  const log = await h.service.store.readLog(error.intakeId);
  assert.ok(log.some(entry => entry.event === 'intake-failed' && entry.code === 'KEY_MISSING'));

  await writeLabKey(h.keysDirectory, future);
  const resumed = await h.service.accept({ manifestPath: created.manifestPath, resumeIntakeId: error.intakeId });
  assert.equal(resumed.status, 'published');
  assert.equal(resumed.resumedFrom, error.intakeId);
  assert.equal((await h.archive.read(resumed.receipt.sha256)).toString(), 'first\nlater\n');
  assert.equal((await h.service.store.readJournal(error.intakeId)).phase, 'published');
  // 发布后暂存目录被清理。
  await assert.rejects(stat(join(h.stateDirectory, 'intakes', error.intakeId)), /ENOENT/);
});

test('认证失败不发布任何部分明文，并清除暂存', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'bad'), exportId: 'export-bad', version: 1,
    segments: segments(3, h.keyA.id),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  // 块 1 的密文被替换成另一把密钥加密的数据：摘要先失败。
  const other = generateLabKey('lab-2026');
  const forged = await createSyntheticExport({
    directory: join(h.root, 'forged'), exportId: 'export-bad', version: 1,
    segments: segments(3, h.keyA.id),
    keys: new Map([[h.keyA.id, other.key]]), privateKey: h.identity.privateKey
  });
  await writeFile(join(created.directory, 'chunk-1.bin'), await readFile(join(forged.directory, 'chunk-1.bin')));
  const error = await h.service.accept({ manifestPath: created.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(error.code, ERROR_CODES.CIPHERTEXT_DIGEST);
  assert.equal(classifyError(error.code), 'integrity');
  assert.equal(error.phase, 'failed');
  assert.equal((await h.archive.receipts()).length, 0, '不得产生回执');
  await assert.rejects(stat(join(h.stateDirectory, 'intakes', error.intakeId)), /ENOENT/,
    '失败残留应被清除');
});

test('AAD 指向别的位置时认证失败，而不是摘要失败', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'aad'), exportId: 'export-aad', version: 1,
    segments: [{ keyId: h.keyA.id, plaintext: 'x\n' },
      { keyId: h.keyA.id, plaintext: 'y\n', encryptAad: { exportId: 'export-aad', version: 1, position: 0 } }],
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  const error = await h.service.accept({ manifestPath: created.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(error.code, ERROR_CODES.AUTH_FAILED);
  assert.equal(error.position, 1);
  assert.equal((await h.archive.receipts()).length, 0);
});

test('清单块顺序被调换时按 position 重新排序后接纳', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'order'), exportId: 'export-order', version: 1,
    segments: segments(3, h.keyB.id, 'line'),
    keys: new Map([[h.keyB.id, h.keyB.key]]), privateKey: h.identity.privateKey,
    shuffleManifestOrder: true
  });
  const result = await h.service.accept({ manifestPath: created.manifestPath });
  assert.equal((await h.archive.read(result.receipt.sha256)).toString(), 'line,0\nline,1\nline,2\n');
});

test('暂停后继续只处理剩余块，恢复不会重复接纳', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'pause'), exportId: 'export-pause', version: 3,
    segments: segments(4, h.keyB.id),
    keys: new Map([[h.keyB.id, h.keyB.key]]), privateKey: h.identity.privateKey
  });
  const paused = await h.service.accept({ manifestPath: created.manifestPath, maxBlocks: 2 });
  assert.equal(paused.status, 'paused');
  assert.deepEqual(paused.authenticatedPositions, [0, 1]);
  assert.equal(paused.nextPosition, 2);
  const journal = await h.service.store.readJournal(paused.intakeId);
  assert.deepEqual(journal.chunks.map(chunk => chunk.position), [0, 1]);

  const resumed = await h.service.accept({ manifestPath: created.manifestPath });
  assert.equal(resumed.status, 'published');
  assert.equal(resumed.resumedFrom, paused.intakeId);
  assert.equal((await h.archive.read(resumed.receipt.sha256)).toString(), 'row,0\nrow,1\nrow,2\nrow,3\n');
  // 再次调用是幂等的：返回同一回执，不新增记录。
  const again = await h.service.accept({ manifestPath: created.manifestPath });
  assert.equal(again.status, 'published');
  assert.equal(again.receipt.id, resumed.receipt.id);
  assert.equal((await h.archive.receipts()).length, 1);
});

test('不同版本/不同导出的记录不能被拼成一份', async (t) => {
  const h = await harness(t);
  const first = await createSyntheticExport({
    directory: join(h.root, 'v1'), exportId: 'export-same', version: 1,
    segments: segments(3, h.keyA.id, 'v1'),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  const paused = await h.service.accept({ manifestPath: first.manifestPath, maxBlocks: 1 });
  assert.equal(paused.status, 'paused');

  const second = await createSyntheticExport({
    directory: join(h.root, 'v2'), exportId: 'export-same', version: 2,
    segments: segments(3, h.keyA.id, 'v2'),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  await assert.rejects(
    h.service.accept({ manifestPath: second.manifestPath, resumeIntakeId: paused.intakeId }),
    (error) => {
      assert.equal(error.code, ERROR_CODES.RESUME_MISMATCH);
      assert.equal(classifyError(error.code), 'state');
      return true;
    });
  // 另一份导出也不能借用该记录。
  await assert.rejects(
    h.service.accept({ manifestPath: second.manifestPath, resumeIntakeId: paused.intakeId }),
    (error) => error.code === ERROR_CODES.RESUME_MISMATCH);
  // 原记录与暂存仍在，可用于继续 v1。
  const v1Again = await h.service.accept({ manifestPath: first.manifestPath, resumeIntakeId: paused.intakeId });
  assert.equal(v1Again.status, 'published');
  assert.equal((await h.archive.read(v1Again.receipt.sha256)).toString(), 'v1,0\nv1,1\nv1,2\n');
});

test('整体明文摘要不符时每块都已认证也拒绝接纳', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'cleartext'), exportId: 'export-clear', version: 1,
    segments: segments(2, h.keyA.id),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  const envelope = JSON.parse(await readFile(created.manifestPath, 'utf8'));
  const payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
  payload.cleartextSha256 = digest(Buffer.from('别的内容'));
  await writeSignedManifest(created.directory, payload, h.identity.privateKey);
  const error = await h.service.accept({ manifestPath: created.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(error.code, ERROR_CODES.CLEARTEXT_DIGEST);
  assert.equal((await h.archive.receipts()).length, 0);
});

test('缺块、摘要失败与认证失败使用不同的错误码', async (t) => {
  const h = await harness(t);
  const missing = await createSyntheticExport({
    directory: join(h.root, 'missing'), exportId: 'export-missing', version: 1,
    segments: segments(3, h.keyA.id),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  await rm(join(missing.directory, 'chunk-2.bin'));
  const error = await h.service.accept({ manifestPath: missing.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(error.code, ERROR_CODES.BLOCK_MISSING);
  assert.equal(error.position, 2);

  const integrity = await createSyntheticExport({
    directory: join(h.root, 'integrity'), exportId: 'export-integrity', version: 1,
    segments: segments(2, h.keyA.id),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  const path = join(integrity.directory, 'chunk-0.bin');
  await writeFile(path, flipByte(await readFile(path), 1));
  const mismatch = await h.service.accept({ manifestPath: integrity.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(mismatch.code, ERROR_CODES.CIPHERTEXT_DIGEST);
  assert.notEqual(mismatch.code, error.code);
});

test('保留策略清理已终结记录，未完成的接纳不受影响', async (t) => {
  const h = await harness(t);
  const done = await createSyntheticExport({
    directory: join(h.root, 'done'), exportId: 'export-done', version: 1,
    segments: segments(2, h.keyA.id), keys: new Map([[h.keyA.id, h.keyA.key]]),
    privateKey: h.identity.privateKey
  });
  const published = await h.service.accept({ manifestPath: done.manifestPath });
  const pending = await createSyntheticExport({
    directory: join(h.root, 'pending'), exportId: 'export-pending', version: 1,
    segments: segments(3, h.keyA.id), keys: new Map([[h.keyA.id, h.keyA.key]]),
    privateKey: h.identity.privateKey
  });
  const paused = await h.service.accept({ manifestPath: pending.manifestPath, maxBlocks: 1 });
  const future = new Date(Date.now() + 31 * 24 * 60 * 60 * 1000);
  const removed = await h.service.store.prune({ retentionDays: 30, now: future });
  assert.deepEqual(removed, [published.intakeId]);
  await assert.rejects(stat(join(h.stateDirectory, 'journal', `${published.intakeId}.json`)), /ENOENT/);
  // 进行中的记录仍在。
  assert.equal((await h.service.store.readJournal(paused.intakeId)).phase, 'staging');
});

test('提交阶段崩溃后继续：回执已落盘则直接完成，不重复登记', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'commit'), exportId: 'export-commit', version: 1,
    segments: segments(2, h.keyB.id),
    keys: new Map([[h.keyB.id, h.keyB.key]]), privateKey: h.identity.privateKey
  });
  // 模拟“对象与回执已写入，但记录还停在 committing”的中断现场。
  const opened = await h.service.inspect(created.manifestPath);
  const staged = await h.service.accept({ manifestPath: created.manifestPath, maxBlocks: 1 });
  assert.equal(staged.status, 'paused');
  const journal = await h.service.store.readJournal(staged.intakeId);
  const receipt = await h.archive.accept(created.cleartext, {
    source: 'sealed-export', exportId: 'export-commit', version: 1,
    manifestDigest: opened.manifestDigest, intakeId: staged.intakeId
  });
  await h.service.store.writeJournal({ ...journal, phase: 'committing', receiptId: receipt.id });

  const recovered = await h.service.accept({ manifestPath: created.manifestPath, resumeIntakeId: staged.intakeId });
  assert.equal(recovered.status, 'published');
  assert.equal(recovered.receipt.id, receipt.id);
  assert.equal((await h.archive.receipts()).length, 1);
  assert.equal((await h.archive.read(recovered.receipt.sha256)).toString(), 'row,0\nrow,1\n');
});

test('显式继续已失败的接纳会从该版本重新认证，不沿用旧块', async (t) => {
  const h = await harness(t);
  const created = await createSyntheticExport({
    directory: join(h.root, 'retry'), exportId: 'export-retry', version: 1,
    segments: segments(3, h.keyA.id),
    keys: new Map([[h.keyA.id, h.keyA.key]]), privateKey: h.identity.privateKey
  });
  const damagePath = join(created.directory, 'chunk-1.bin');
  const original = await readFile(damagePath);
  await writeFile(damagePath, flipByte(original, 0));
  const failed = await h.service.accept({ manifestPath: created.manifestPath }).then(
    () => assert.fail('应当拒绝'), (caught) => caught);
  assert.equal(failed.code, ERROR_CODES.CIPHERTEXT_DIGEST);
  // 修复来源后，用同一记录重试应重新走完整个版本。
  await writeFile(damagePath, original);
  const recovered = await h.service.accept({
    manifestPath: created.manifestPath, resumeIntakeId: failed.intakeId
  });
  assert.equal(recovered.status, 'published');
  assert.equal((await h.archive.read(recovered.receipt.sha256)).toString(), 'row,0\nrow,1\nrow,2\n');
});
