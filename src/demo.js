// 端到端演示：全部使用合成密钥与合成资料，不接触任何真实客户资料。
// 每个场景都展示运维可见的分类错误码，以及读者只能看到完整接纳资料。
import { mkdtemp, rm, mkdir, cp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
import { buildExport, generateKey, tamperBlockBytes, swapBlockFiles, removeBlock, resignManifest, reencryptWithWrongKey } from './synthetic.js';
import { KeyStore } from './keystore.js';
import { Archive } from './archive.js';
import { Intake } from './intake.js';
import { IntakeError } from './errors.js';
import { digest } from './archive.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));

function section(title) {
  console.log(`\n=== ${title} ===`);
}

async function expectIntakeError(fn, expectedCode) {
  try {
    await fn();
    assert.fail('应当抛出接纳错误');
  } catch (error) {
    assert.ok(error instanceof IntakeError, `期望 IntakeError，实际 ${error.constructor.name}`);
    assert.equal(error.code, expectedCode);
    console.log(`  -> 运维可见错误: ${JSON.stringify(error.toJSON())}`);
    return error;
  }
}

async function countFiles(dir) {
  try {
    const { readdir } = await import('node:fs/promises');
    return (await readdir(dir, { recursive: true })).length;
  } catch { return 0; }
}

export async function runDemo() {
  const workdir = await mkdtemp(join(tmpdir(), 'sealed-demo-'));
  try {
    console.log(`演示工作目录（退出时清理）: ${workdir}`);

    // ---------------------------------------------------------------- 1
    section('场景 1：新旧 key ID 共存的密钥轮换 + 暂停后继续（完整接纳）');
    const oldKey = generateKey('lab-2026');
    const newKey = generateKey('lab-2027');
    const exp1 = await buildExport(join(workdir, 'export-rotation'), {
      exportId: 'export-A', version: 1,
      keyByPosition: position => (position === 0 ? oldKey : newKey), // 块 0 用旧钥匙，其余用新钥匙
    });
    console.log(`  合成导出 ${exp1.manifest.exportId} v${exp1.manifest.version}，各块 key ID:`,
      exp1.manifest.blocks.map(b => `${b.position}:${b.keyId}`).join(' '));

    const keyring1 = join(workdir, 'keyring-1');
    await mkdir(keyring1, { recursive: true });
    await cp(join(exp1.root, 'keys'), keyring1, { recursive: true });
    const keyStore1 = new KeyStore(keyring1);
    console.log(`  受控目录中的授权 key ID: ${(await keyStore1.listKeyIds()).join(', ')}（只能按 ID 精确领取）`);

    const archive1 = new Archive(join(workdir, 'archive-1'));
    const intake1 = new Intake(join(workdir, 'intake-1'));

    const step1 = await intake1.run(join(exp1.root, 'manifest.json'), keyStore1, archive1, { maxBlocks: 2 });
    console.log(`  第一次推进（限 2 块）: ${JSON.stringify(step1)}`);
    assert.equal(step1.status, 'paused');
    assert.equal(step1.staged, 2);
    // 暂停期间读者侧没有任何可读取的资料对象
    assert.deepEqual(await archive1.receipts(), []);

    const step2 = await intake1.run(join(exp1.root, 'manifest.json'), keyStore1, archive1);
    console.log(`  继续推进: ${JSON.stringify(step2)}`);
    assert.equal(step2.status, 'complete');
    const readable = await archive1.read(step2.sha256);
    assert.ok(readable.equals(exp1.cleartext));
    console.log(`  读者可见的完整资料（${readable.length} 字节）:\n${readable.toString().split('\n').map(l => l && `    ${l}`).filter(Boolean).join('\n')}`);
    // 成功后暂存区无明文残留
    assert.equal(await countFiles(join(workdir, 'intake-1', 'staging', 'blocks')), 0);
    // 续跑已完成的导出是幂等的
    const again = await intake1.run(join(exp1.root, 'manifest.json'), keyStore1, archive1);
    assert.equal(again.alreadyAccepted, true);
    console.log('  -> 已完成的接纳重复执行返回 alreadyAccepted，不重复解密入库');

    // ---------------------------------------------------------------- 2
    section('场景 2：缺密钥 —— 缺授权与文件损坏必须分开报告');
    const exp2 = await buildExport(join(workdir, 'export-missing-key'), { exportId: 'export-B', version: 1 });
    const keyring2 = join(workdir, 'keyring-2');
    await mkdir(keyring2, { recursive: true }); // 故意空目录：没有任何授权
    const keyStore2 = new KeyStore(keyring2);
    const intake2 = new Intake(join(workdir, 'intake-2'));
    const archive2 = new Archive(join(workdir, 'archive-2'));
    await expectIntakeError(
      () => intake2.run(join(exp2.root, 'manifest.json'), keyStore2, archive2),
      'MISSING_KEY',
    );
    assert.deepEqual(await archive2.receipts(), []);
    console.log('  -> 归档中没有发布任何部分明文');

    section('场景 2b：补齐授权后重试，同一份导出可恢复完成（不会误报文件损坏）');
    await cp(join(exp2.root, 'keys'), keyring2, { recursive: true });
    const resumed = await intake2.run(join(exp2.root, 'manifest.json'), new KeyStore(keyring2), archive2);
    assert.equal(resumed.status, 'complete');
    console.log(`  -> 重试结果: ${JSON.stringify(resumed)}`);

    // ---------------------------------------------------------------- 3
    section('场景 3：认证失败 —— 钥匙不匹配时 GCM 标签校验拦截，不产出明文');
    const exp3 = await buildExport(join(workdir, 'export-auth'), { exportId: 'export-C', version: 1 });
    const wrongKey = generateKey('lab-wrong');
    await reencryptWithWrongKey(exp3.root, exp3.manifest, 1, wrongKey);
    // 重签清单：签名仍然有效，问题被精确隔离到块认证层
    exp3.manifest.blocks[1].sha256 = digest(await readFile(join(exp3.root, exp3.manifest.blocks[1].file)));
    await resignManifest(exp3.root, exp3.manifest, exp3.signingKey);
    const keyring3 = join(workdir, 'keyring-3');
    await mkdir(keyring3, { recursive: true });
    await cp(join(exp3.root, 'keys'), keyring3, { recursive: true });
    const intake3 = new Intake(join(workdir, 'intake-3'));
    const archive3 = new Archive(join(workdir, 'archive-3'));
    await expectIntakeError(
      () => intake3.run(join(exp3.root, 'manifest.json'), new KeyStore(keyring3), archive3),
      'AUTH_FAILED',
    );
    assert.deepEqual(await archive3.receipts(), []);

    // ---------------------------------------------------------------- 4
    section('场景 4：中间块损坏 —— 签名有效但密文摘要对不上（与缺密钥区分）');
    const exp4 = await buildExport(join(workdir, 'export-corrupt'), { exportId: 'export-D', version: 1 });
    await tamperBlockBytes(exp4.root, exp4.manifest, 1); // 仅改字节，清单仍登记原摘要
    const keyring4 = join(workdir, 'keyring-4');
    await mkdir(keyring4, { recursive: true });
    await cp(join(exp4.root, 'keys'), keyring4, { recursive: true });
    const intake4 = new Intake(join(workdir, 'intake-4'));
    const archive4 = new Archive(join(workdir, 'archive-4'));
    await expectIntakeError(
      () => intake4.run(join(exp4.root, 'manifest.json'), new KeyStore(keyring4), archive4),
      'DIGEST_MISMATCH',
    );
    assert.deepEqual(await archive4.receipts(), []);

    section('场景 4b：修复后重试 —— 以同一 exportId/版本重新下发完好导出，接纳继续推进');
    // 运维收到合作实验室重新下发的完好导出：身份（exportId/version）不变，
    // 清单重新签名、块重新加密；同一接纳目录凭身份绑定接受它，而不是把两份混在一起。
    const exp4Key = JSON.parse(await readFile(
      join(exp4.root, 'keys', exp4.manifest.blocks[0].keyId + '.json'), 'utf8'));
    await rm(exp4.root, { recursive: true, force: true });
    const rebuilt4 = await buildExport(exp4.root, {
      exportId: 'export-D', version: 1, keyByPosition: () => exp4Key,
    });
    const fixed = await intake4.run(join(rebuilt4.root, 'manifest.json'), new KeyStore(keyring4), archive4);
    assert.equal(fixed.status, 'complete');
    console.log(`  -> 修复后重试: ${JSON.stringify(fixed)}`);

    // ---------------------------------------------------------------- 5
    section('场景 5：顺序调换 —— AAD 绑定位置 + 块摘要双重拦截');
    const exp5 = await buildExport(join(workdir, 'export-swap'), { exportId: 'export-E', version: 1 });
    await swapBlockFiles(exp5.root, exp5.manifest, 0, 1);
    const keyring5 = join(workdir, 'keyring-5');
    await mkdir(keyring5, { recursive: true });
    await cp(join(exp5.root, 'keys'), keyring5, { recursive: true });
    const intake5 = new Intake(join(workdir, 'intake-5'));
    const archive5 = new Archive(join(workdir, 'archive-5'));
    await expectIntakeError(
      () => intake5.run(join(exp5.root, 'manifest.json'), new KeyStore(keyring5), archive5),
      'DIGEST_MISMATCH',
    );
    console.log('  -> 调换后块位置 0 的密文摘要与清单登记不符；即使摘要被改写，AAD 中的 position 也会令 GCM 认证失败');

    // ---------------------------------------------------------------- 6
    section('场景 6：缺块 —— 明确报告缺失位置，与摘要失败分开');
    const exp6 = await buildExport(join(workdir, 'export-missing-block'), { exportId: 'export-F', version: 1 });
    await removeBlock(exp6.root, exp6.manifest, 2);
    const keyring6 = join(workdir, 'keyring-6');
    await mkdir(keyring6, { recursive: true });
    await cp(join(exp6.root, 'keys'), keyring6, { recursive: true });
    const intake6 = new Intake(join(workdir, 'intake-6'));
    const archive6 = new Archive(join(workdir, 'archive-6'));
    await expectIntakeError(
      () => intake6.run(join(exp6.root, 'manifest.json'), new KeyStore(keyring6), archive6),
      'MISSING_BLOCK',
    );

    // ---------------------------------------------------------------- 7
    section('场景 7：重试不混版本 —— 不同 exportId/版本/清单摘要被拒绝');
    const exp7 = await buildExport(join(workdir, 'export-v1'), { exportId: 'export-G', version: 1 });
    const exp7b = await buildExport(join(workdir, 'export-v2'), { exportId: 'export-G', version: 2 });
    const keyring7 = join(workdir, 'keyring-7');
    await mkdir(keyring7, { recursive: true });
    await cp(join(exp7.root, 'keys'), keyring7, { recursive: true });
    const intake7 = new Intake(join(workdir, 'intake-7'));
    const archive7 = new Archive(join(workdir, 'archive-7'));
    const p1 = await intake7.run(join(exp7.root, 'manifest.json'), new KeyStore(keyring7), archive7, { maxBlocks: 1 });
    assert.equal(p1.status, 'paused');
    await expectIntakeError(
      () => intake7.run(join(exp7b.root, 'manifest.json'), new KeyStore(keyring7), archive7),
      'INTAKE_CONFLICT',
    );
    console.log('  -> 同一接纳目录拒绝接收 v2；不同版本必须使用独立接纳目录，块不能拼成一份');

    // ---------------------------------------------------------------- 8
    section('场景 8：保留策略 —— 失败残留隔离（不含明文）与日志按期清理');
    const exp8 = await buildExport(join(workdir, 'export-retention'), { exportId: 'export-H', version: 1 });
    // 先制造一次损坏块，得到含密文残料的隔离条目
    await tamperBlockBytes(exp8.root, exp8.manifest, 0);
    const keyring8 = join(workdir, 'keyring-8');
    await mkdir(keyring8, { recursive: true });
    await cp(join(exp8.root, 'keys'), keyring8, { recursive: true });
    const retention = { quarantineTtlMs: 80, journalMaxEntries: 3, journalMaxAgeMs: 60_000 };
    const intake8 = new Intake(join(workdir, 'intake-8'), retention);
    const archive8 = new Archive(join(workdir, 'archive-8'));
    await expectIntakeError(
      () => intake8.run(join(exp8.root, 'manifest.json'), new KeyStore(keyring8), archive8),
      'DIGEST_MISMATCH',
    );
    // 再制造缺块失败（移除已损坏的块 0；缺块没有残料，不产生新的隔离目录）
    await removeBlock(exp8.root, exp8.manifest, 0);
    const qBefore = (await import('node:fs/promises')).readdir(join(workdir, 'intake-8', 'quarantine'));
    console.log(`  -> 隔离区条目（只含密文残料与错误信息，无明文）: ${(await qBefore).join(', ')}`);
    assert.equal(await countFiles(join(workdir, 'intake-8', 'staging', 'blocks')), 0);

    // 制造多条日志后触发条数裁剪（裁剪在 sweep 中执行，每次 run 开头也会 sweep）
    for (let i = 0; i < 4; i++) {
      await expectIntakeError(
        () => intake8.run(join(exp8.root, 'manifest.json'), new KeyStore(keyring8), archive8),
        'MISSING_BLOCK',
      );
    }
    await intake8.sweep();
    const journalLines = (await readFile(join(workdir, 'intake-8', 'journal.jsonl'), 'utf8'))
      .split('\n').filter(Boolean);
    assert.ok(journalLines.length <= retention.journalMaxEntries, '日志应按 journalMaxEntries 裁剪');
    console.log(`  -> sweep 裁剪后保留 ${journalLines.length} 条（上限 ${retention.journalMaxEntries}），条目示例: ${journalLines.at(-1)}`);

    // TTL 过期后 sweep 清理隔离区
    await sleep(100);
    const sweepResult = await intake8.sweep();
    console.log(`  -> TTL 到期后 sweep 清理结果: ${JSON.stringify(sweepResult)}`);
    assert.ok(sweepResult.quarantine >= 1);

    // ---------------------------------------------------------------- 9
    section('场景 9：清单来源验证在前 —— 篡改签名的清单在解密前即被拒绝');
    const exp9 = await buildExport(join(workdir, 'export-badsig'), { exportId: 'export-I', version: 1 });
    const envelope9 = JSON.parse(await readFile(join(exp9.root, 'manifest.json'), 'utf8'));
    const sig = Buffer.from(envelope9.signature, 'base64url');
    sig[0] ^= 0x01;
    envelope9.signature = sig.toString('base64url');
    await import('node:fs/promises').then(fs => fs.writeFile(join(exp9.root, 'manifest.json'), JSON.stringify(envelope9)));
    const keyring9 = join(workdir, 'keyring-9');
    await mkdir(keyring9, { recursive: true });
    await cp(join(exp9.root, 'keys'), keyring9, { recursive: true });
    const intake9 = new Intake(join(workdir, 'intake-9'));
    const archive9 = new Archive(join(workdir, 'archive-9'));
    await expectIntakeError(
      () => intake9.run(join(exp9.root, 'manifest.json'), new KeyStore(keyring9), archive9),
      'MANIFEST_SIGNATURE_INVALID',
    );

    section('汇总：四类故障彼此分开，且从不发布未经认证的部分明文');
    console.log('  MISSING_KEY / AUTH_FAILED / MISSING_BLOCK / DIGEST_MISMATCH / INTAKE_CONFLICT / MANIFEST_SIGNATURE_INVALID');
    console.log(`  全部演示归档的回执数量（只有完整接纳才产生）: ${
      (await Promise.all([archive1, archive2, archive3, archive4, archive5, archive6, archive7, archive8, archive9]
        .map(a => a.receipts().then(r => r.length)))).reduce((a, b) => a + b, 0)
    } 份；演示工作目录将被清理: ${workdir}`);
    return { workdir };
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
}

// 允许直接执行：node src/demo.js
if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo().catch(error => { console.error(error); process.exitCode = 1; });
}
