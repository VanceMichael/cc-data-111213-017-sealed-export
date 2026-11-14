import { cp, mkdir, mkdtemp, readFile, rm, writeFile, rename, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Archive } from './archive.js';
import { Intake, KeyDirectory } from './intake.js';

// 演示全部使用 fixtures/ 下的合成钥匙与合成资料，在临时目录中运行，退出时清理。
// 每个场景独立的接纳根目录与归档，读者视角只统计完整接纳的回执。
export async function runDemo() {
  const work = await mkdtemp(join(tmpdir(), 'intake-demo-'));
  const report = {};
  try {
    const keysDirectory = join(work, 'controlled-keys');
    await mkdir(keysDirectory, { recursive: true });
    await copyFile('fixtures/keys/lab-2026.json', join(keysDirectory, 'lab-2026.json'));
    await copyFile('fixtures/keys/lab-2026-r2.json', join(keysDirectory, 'lab-2026-r2.json'));

    const makeIntake = (name, keysDir = keysDirectory) => {
      const root = join(work, name, 'intake');
      const archive = new Archive(join(work, name, 'archive'));
      return { intake: new Intake({ root, archive, keys: new KeyDirectory(keysDir) }), archive };
    };
    const failureOf = error => ({ code: error.code, category: error.category, message: error.message });
    const readerViewOf = async archive => (await archive.receipts())
      .map(receipt => ({ exportId: receipt.metadata.exportId, version: receipt.metadata.version, sha256: receipt.sha256 }));
    const opsViewOf = async intake => (await intake.status()).sessions
      .map(session => ({ exportId: session.exportId, version: session.version, status: session.status,
        progress: `${session.verifiedBlocks}/${session.totalBlocks}`,
        stuckOn: session.lastFailure ? { code: session.lastFailure.code, category: session.lastFailure.category } : null }));

    // 场景一：基线接纳 + 轮换期间新旧 key ID 共存
    {
      const { intake, archive } = makeIntake('s1-rotation');
      const v1 = await intake.run('fixtures/manifest.json');
      const v2 = await intake.run('fixtures/rotation/manifest.json');
      report.rotation = {
        v1: { receipt: v1.receipt.id, keyIds: v1.receipt.metadata.keyIds },
        v2: { receipt: v2.receipt.id, keyIds: v2.receipt.metadata.keyIds },
        verifiedBytes: (await archive.read(v2.receipt.sha256)).length,
        readerView: await readerViewOf(archive),
      };
    }

    // 场景二：未领取到钥匙是授权问题，不再误报为文件损坏
    {
      const { intake, archive } = makeIntake('s2-missing-key');
      try {
        await intake.run('fixtures/missing-key/manifest.json');
      } catch (error) {
        report.missingKey = { failure: failureOf(error) };
      }
      report.missingKey.readerView = await readerViewOf(archive);
      report.missingKey.opsView = await opsViewOf(intake);
    }

    // 场景三：中间块损坏被识别为完整性问题，修复后从断点继续
    {
      const { intake, archive } = makeIntake('s3-corrupted');
      const chunks = join(work, 's3-chunks');
      await cp('fixtures/rotation', chunks, { recursive: true });
      const damaged = join(chunks, 'chunk-1.bin');
      const bytes = await readFile(damaged);
      bytes[0] ^= 0xff;
      await writeFile(damaged, bytes);
      try {
        await intake.run(join(chunks, 'manifest.json'));
      } catch (error) {
        report.corruptedBlock = { failure: failureOf(error), opsView: await opsViewOf(intake) };
      }
      await copyFile('fixtures/rotation/chunk-1.bin', damaged); // 运维补回正确块
      const retried = await makeIntake('s3-corrupted').intake.run(join(chunks, 'manifest.json'));
      report.corruptedBlock.afterRepair = { status: retried.session.status, resumed: retried.resumed };
      report.corruptedBlock.readerView = await readerViewOf(archive);
    }

    // 场景四：块顺序调换在逐块摘要核对时暴露
    {
      const { intake, archive } = makeIntake('s4-swapped');
      const chunks = join(work, 's4-chunks');
      await mkdir(chunks, { recursive: true });
      for (const name of ['manifest.json', 'signing-public.txt', 'chunk-0.bin', 'chunk-1.bin', 'chunk-2.bin']) {
        await copyFile(join('fixtures', name), join(chunks, name));
      }
      await rename(join(chunks, 'chunk-0.bin'), join(chunks, 'chunk.tmp'));
      await rename(join(chunks, 'chunk-2.bin'), join(chunks, 'chunk-0.bin'));
      await rename(join(chunks, 'chunk.tmp'), join(chunks, 'chunk-2.bin'));
      try {
        await intake.run(join(chunks, 'manifest.json'));
      } catch (error) {
        report.swappedOrder = { failure: failureOf(error), opsView: await opsViewOf(intake) };
      }
      report.swappedOrder.readerView = await readerViewOf(archive);
    }

    // 场景五：轮换窗口内新钥匙尚未下发，暂停；钥匙到位后继续，不重头拼凑
    {
      const partialKeys = join(work, 'partial-keys');
      await mkdir(partialKeys, { recursive: true });
      await copyFile('fixtures/keys/lab-2026.json', join(partialKeys, 'lab-2026.json')); // 只有旧钥匙
      const first = makeIntake('s5-paused', partialKeys);
      try {
        await first.intake.run('fixtures/rotation/manifest.json');
      } catch (error) {
        report.pauseResume = { interrupted: failureOf(error), opsView: await opsViewOf(first.intake) };
      }
      await copyFile('fixtures/keys/lab-2026-r2.json', join(partialKeys, 'lab-2026-r2.json')); // 新钥匙下发
      const second = makeIntake('s5-paused', partialKeys);
      const done = await second.intake.run('fixtures/rotation/manifest.json');
      report.pauseResume.completed = { status: done.session.status, resumed: done.resumed, receipt: done.receipt.id };
      report.pauseResume.readerView = await readerViewOf(second.archive);
    }

    // 场景六：保留策略清理失败残留与日志，已接纳回执保留
    {
      const failed = makeIntake('s4-swapped').intake;
      report.retention = {
        pruned: await failed.prune({ olderThanMs: 0 }),
        opsViewAfterPrune: await opsViewOf(failed),
      };
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }
  return report;
}
