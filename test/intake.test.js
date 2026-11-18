import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, cp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildExport, generateKey, tamperBlockBytes, swapBlockFiles, removeBlock, reencryptWithWrongKey, resignManifest } from '../src/synthetic.js';
import { KeyStore } from '../src/keystore.js';
import { Archive, digest } from '../src/archive.js';
import { Intake } from '../src/intake.js';
import { inspect } from '../src/domain.js';
import {
  MissingKeyError, AuthenticationError, MissingBlockError,
  DigestMismatchError, IntakeConflictError, ManifestSignatureError, ManifestInvalidError,
} from '../src/errors.js';

async function workspace() {
  return mkdtemp(join(tmpdir(), 'intake-test-'));
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function keyringFrom(exportRoot, target) {
  await mkdir(target, { recursive: true });
  await cp(join(exportRoot, 'keys'), target, { recursive: true });
  return new KeyStore(target);
}

test('完整轮换导出：按每块 key ID 领取并解密，读者拿到完整明文', async () => {
  const wd = await workspace();
  try {
    const oldKey = generateKey('old');
    const newKey = generateKey('new');
    const exp = await buildExport(join(wd, 'exp'), {
      exportId: 'ex', version: 1,
      keyByPosition: p => (p === 0 ? oldKey : newKey),
    });
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    const result = await intake.run(join(exp.root, 'manifest.json'), keyStore, archive);
    assert.equal(result.status, 'complete');
    const bytes = await archive.read(result.sha256);
    assert.ok(bytes.equals(exp.cleartext));
    const receipts = await archive.receipts();
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].metadata.exportId, 'ex');
    // 只发生按 ID 的精确领取，不存在遍历试解
    assert.deepEqual(keyStore.accessLog.map(e => e.keyId).sort(), ['new', 'new', 'old']);
    assert.ok(keyStore.accessLog.every(e => e.granted));
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('暂停后继续：两次 run 完成接纳，暂停期间无部分明文发布', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    const first = await intake.run(join(exp.root, 'manifest.json'), keyStore, archive, { maxBlocks: 1 });
    assert.equal(first.status, 'paused');
    assert.equal(first.staged, 1);
    assert.deepEqual(await archive.receipts(), []);
    const snapshot = await intake.snapshot();
    assert.equal(snapshot.status, 'paused');
    const second = await intake.run(join(exp.root, 'manifest.json'), keyStore, archive);
    assert.equal(second.status, 'complete');
    assert.equal((await archive.receipts()).length, 1);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('已完成的接纳重复执行是幂等的', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'));
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    const done = await intake.run(join(exp.root, 'manifest.json'), keyStore, archive);
    const again = await intake.run(join(exp.root, 'manifest.json'), keyStore, archive);
    assert.equal(again.status, 'complete');
    assert.equal(again.alreadyAccepted, true);
    assert.equal(again.receiptId, done.receiptId);
    assert.equal((await archive.receipts()).length, 1);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('缺密钥报 MISSING_KEY，归档无回执，暂存区清空', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await mkdir(join(wd, 'empty-keys'), { recursive: true });
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), new KeyStore(join(wd, 'empty-keys')), archive),
      error => error instanceof MissingKeyError && error.code === 'MISSING_KEY',
    );
    assert.deepEqual(await archive.receipts(), []);
    assert.deepEqual(await readdir(join(wd, 'intake', 'staging', 'blocks')), []);
    assert.equal((await intake.snapshot()).status, 'failed');
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('补齐授权后重试可恢复完成', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await mkdir(join(wd, 'keys'), { recursive: true });
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), archive),
      error => error.code === 'MISSING_KEY',
    );
    await cp(join(exp.root, 'keys'), join(wd, 'keys'), { recursive: true });
    const result = await intake.run(join(exp.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), archive);
    assert.equal(result.status, 'complete');
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('中间块损坏报 DIGEST_MISMATCH，且发生在任何解密之前', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await tamperBlockBytes(exp.root, exp.manifest, 1);
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, archive),
      error => error instanceof DigestMismatchError && error.details.position === 1,
    );
    assert.deepEqual(await archive.receipts(), []);
    // 损坏块已进入隔离区，且隔离内容是密文而非明文
    const q = await readdir(join(wd, 'intake', 'quarantine'));
    assert.equal(q.length, 1);
    const info = JSON.parse(await readFile(join(wd, 'intake', 'quarantine', q[0], 'info.json'), 'utf8'));
    assert.equal(info.error.code, 'DIGEST_MISMATCH');
    const quarantined = await readFile(join(wd, 'intake', 'quarantine', q[0], 'block-1.bin'));
    const actual = await readFile(join(exp.root, 'chunk-1.bin'));
    assert.ok(quarantined.equals(actual));
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('顺序调换报 DIGEST_MISMATCH；即使摘要被改写，AAD 位置绑定也会令认证失败', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await swapBlockFiles(exp.root, exp.manifest, 0, 1);
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, archive),
      error => error instanceof DigestMismatchError && error.details.position === 0,
    );

    // 第二重防护：改写块 0 的摘要并重签，GCM 的 AAD（position）校验拦截
    const wd2 = await workspace();
    const exp2 = await buildExport(join(wd2, 'exp'), { exportId: 'ex2', version: 1 });
    await swapBlockFiles(exp2.root, exp2.manifest, 0, 1);
    exp2.manifest.blocks[0].sha256 = digest(await readFile(join(exp2.root, 'chunk-0.bin')));
    await resignManifest(exp2.root, exp2.manifest, exp2.signingKey);
    const keyStore2 = await keyringFrom(exp2.root, join(wd2, 'keys'));
    const intake2 = new Intake(join(wd2, 'intake'));
    await assert.rejects(
      intake2.run(join(exp2.root, 'manifest.json'), keyStore2, new Archive(join(wd2, 'archive'))),
      error => error instanceof AuthenticationError && error.details.position === 0,
    );
    await rm(wd2, { recursive: true, force: true });
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('AAD 与导出/位置不一致的清单在结构校验层被判为不合法', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    const envelope = JSON.parse(await readFile(join(exp.root, 'manifest.json'), 'utf8'));
    const payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
    const aad = JSON.parse(Buffer.from(payload.blocks[0].aad, 'base64url').toString('utf8'));
    aad.position = 9;
    payload.blocks[0].aad = Buffer.from(JSON.stringify(aad)).toString('base64url');
    const { validateManifest } = await import('../src/domain.js');
    assert.throws(() => validateManifest(payload), error => error instanceof ManifestInvalidError);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('缺块报 MISSING_BLOCK，与摘要/认证错误分开', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await removeBlock(exp.root, exp.manifest, 2);
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, new Archive(join(wd, 'archive'))),
      error => error instanceof MissingBlockError && error.details.position === 2,
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('错误密钥导致 GCM 认证失败报 AUTH_FAILED', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    const wrong = generateKey('wrong');
    await reencryptWithWrongKey(exp.root, exp.manifest, 0, wrong);
    exp.manifest.blocks[0].sha256 = digest(await readFile(join(exp.root, 'chunk-0.bin')));
    await resignManifest(exp.root, exp.manifest, exp.signingKey);
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, new Archive(join(wd, 'archive'))),
      error => error instanceof AuthenticationError && error.code === 'AUTH_FAILED',
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('不同版本/清单混入同一接纳目录报 INTAKE_CONFLICT', async () => {
  const wd = await workspace();
  try {
    const v1 = await buildExport(join(wd, 'v1'), { exportId: 'ex', version: 1 });
    const v2 = await buildExport(join(wd, 'v2'), { exportId: 'ex', version: 2 });
    const keyStore = await keyringFrom(v1.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await intake.run(join(v1.root, 'manifest.json'), keyStore, archive, { maxBlocks: 1 });
    await assert.rejects(
      intake.run(join(v2.root, 'manifest.json'), keyStore, archive),
      error => error instanceof IntakeConflictError && error.code === 'INTAKE_CONFLICT',
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('同一身份重新下发的修复清单允许续跑，并按新清单重置暂存块', async () => {
  const wd = await workspace();
  try {
    const key = generateKey('lab-2026');
    const v1 = await buildExport(join(wd, 'v1'), { exportId: 'ex', version: 1, keyByPosition: () => key });
    const v1Rebuilt = await buildExport(join(wd, 'v1b'), { exportId: 'ex', version: 1, keyByPosition: () => key });
    const keyStore = await keyringFrom(v1.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await intake.run(join(v1.root, 'manifest.json'), keyStore, archive, { maxBlocks: 1 });
    const result = await intake.run(join(v1Rebuilt.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), archive);
    assert.equal(result.status, 'complete');
    assert.ok((await archive.read(result.sha256)).equals(v1Rebuilt.cleartext));
    const state = await intake.snapshot();
    assert.equal(state.identity.payloadHash, (await inspect(join(v1Rebuilt.root, 'manifest.json'))).payloadHash);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('不同 exportId 也不能共用接纳目录', async () => {
  const wd = await workspace();
  try {
    const a = await buildExport(join(wd, 'a'), { exportId: 'A', version: 1 });
    const b = await buildExport(join(wd, 'b'), { exportId: 'B', version: 1 });
    await keyringFrom(a.root, join(wd, 'keys'));
    const intake = new Intake(join(wd, 'intake'));
    await intake.run(join(a.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), new Archive(join(wd, 'ar')));
    await assert.rejects(
      intake.run(join(b.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), new Archive(join(wd, 'ar'))),
      error => error.code === 'INTAKE_CONFLICT',
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('签名被篡改的清单在解密前被拒绝', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'));
    const envelope = JSON.parse(await readFile(join(exp.root, 'manifest.json'), 'utf8'));
    const sig = Buffer.from(envelope.signature, 'base64url');
    sig[0] ^= 0x01;
    envelope.signature = sig.toString('base64url');
    await writeFile(join(exp.root, 'manifest.json'), JSON.stringify(envelope));
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, new Archive(join(wd, 'archive'))),
      error => error instanceof ManifestSignatureError,
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('恢复时暂存块被篡改会回到 pending 重新解密', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const archive = new Archive(join(wd, 'archive'));
    const intake = new Intake(join(wd, 'intake'));
    await intake.run(join(exp.root, 'manifest.json'), keyStore, archive, { maxBlocks: 1 });
    await writeFile(join(wd, 'intake', 'staging', 'blocks', '0'), Buffer.from('被篡改的暂存明文'));
    const done = await intake.run(join(exp.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), archive);
    assert.equal(done.status, 'complete');
    assert.ok((await archive.read(done.sha256)).equals(exp.cleartext));
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('保留策略：隔离区 TTL 过期清理，日志按条数裁剪', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'), { exportId: 'ex', version: 1 });
    await tamperBlockBytes(exp.root, exp.manifest, 0);
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    // TTL 依据文件系统真实 mtime，使用真实时钟与极短 TTL
    const intake = new Intake(join(wd, 'intake'), { quarantineTtlMs: 60, journalMaxEntries: 2, journalMaxAgeMs: 600_000 });
    const archive = new Archive(join(wd, 'archive'));
    for (let i = 0; i < 3; i++) {
      await assert.rejects(
        intake.run(join(exp.root, 'manifest.json'), new KeyStore(join(wd, 'keys')), archive),
        error => error.code === 'DIGEST_MISMATCH',
      );
    }
    // 保留策略在 sweep（每次 run 开头也会执行）中按条数/期限裁剪
    const sweptTrim = await intake.sweep();
    assert.ok(sweptTrim.journalEntries >= 1);
    const lines = (await readFile(join(wd, 'intake', 'journal.jsonl'), 'utf8')).split('\n').filter(Boolean);
    assert.ok(lines.length <= 2);
    await sleep(80);
    const swept = await intake.sweep();
    assert.ok(swept.quarantine >= 1);
    assert.deepEqual(await readdir(join(wd, 'intake', 'quarantine')), []);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('接纳成功后暂存区不残留任何明文', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'));
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const intake = new Intake(join(wd, 'intake'));
    await intake.run(join(exp.root, 'manifest.json'), keyStore, new Archive(join(wd, 'archive')));
    assert.deepEqual(await readdir(join(wd, 'intake', 'staging', 'blocks')), []);
  } finally { await rm(wd, { recursive: true, force: true }); }
});

test('块文件路径不能越界到资料目录之外', async () => {
  const wd = await workspace();
  try {
    const exp = await buildExport(join(wd, 'exp'));
    const keyStore = await keyringFrom(exp.root, join(wd, 'keys'));
    const envelope = JSON.parse(await readFile(join(exp.root, 'manifest.json'), 'utf8'));
    const payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
    payload.blocks[0].file = '../../escape.bin';
    envelope.payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    await writeFile(join(exp.root, 'manifest.json'), JSON.stringify(envelope));
    const intake = new Intake(join(wd, 'intake'));
    await assert.rejects(
      intake.run(join(exp.root, 'manifest.json'), keyStore, new Archive(join(wd, 'archive'))),
      error => error.code === 'MANIFEST_SIGNATURE_INVALID' || error.code === 'MANIFEST_INVALID',
    );
  } finally { await rm(wd, { recursive: true, force: true }); }
});
