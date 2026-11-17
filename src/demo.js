import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Archive } from './archive.js';
import { SealedError, classifyError } from './errors.js';
import { IntakeService } from './intake.js';
import { KeyStore } from './keystore.js';
import { digest } from './manifest.js';
import {
  createSyntheticExport, flipByte, generateLabKey, generateSigningIdentity,
  writeLabKey, writeSignedManifest
} from './synthetic.js';

/**
 * 演示只用合成密钥与合成资料。每一步都从“业务读者视角”和“运维视角”分别呈现：
 * - published：读者能看到完整资料（且能按回执重新核验摘要）；
 * - rejected/blocked：读者看不到任何部分明文，运维能看到明确的错误码与类别。
 */
export async function runRotationDemo({ json = false, root } = {}) {
  const working = root ?? await mkdtemp(join(tmpdir(), 'sealed-intake-demo-'));
  const cleanup = !root;
  const lines = [];
  const emit = (entry) => { lines.push(entry); if (!json) console.log(format(entry)); };
  const stateDirectory = join(working, 'state');
  const keysDirectory = join(working, 'keys');
  const identity = generateSigningIdentity();
  const publicKeyPath = join(working, 'signing-public.txt');
  await writeFile(publicKeyPath, identity.publicKeyPem, { mode: 0o600 });
  const archive = new Archive(join(stateDirectory, 'archive'));
  const service = new IntakeService({
    stateDirectory, keyStore: new KeyStore(keysDirectory), archive,
    signingPublicKeyPath: publicKeyPath
  });
  await service.initialize();

  const published = [];
  const failures = [];

  async function acceptStep(title, intakeArgs, { exportDirectory } = {}) {
    try {
      const result = await service.accept(intakeArgs);
      if (result.status === 'published') {
        const readable = await archive.read(result.receipt.sha256);
        published.push({ title, intakeId: result.intakeId, sha256: result.receipt.sha256,
          size: readable.length, text: readable.toString('utf8') });
        emit({ step: title, status: 'published', exportId: result.exportId, version: result.version,
          resumedFrom: result.resumedFrom, receiptId: result.receipt.id,
          readerSees: downloadable(result.exportId, result.version) });
      } else {
        emit({ step: title, status: result.status, intakeId: result.intakeId,
          authenticatedPositions: result.authenticatedPositions, nextPosition: result.nextPosition,
          readerSees: [] });
      }
      return result;
    } catch (error) {
      if (!(error instanceof SealedError)) throw error;
      const requestedIntake = intakeArgs.resumeIntakeId;
      const intakeId = error.intakeId ?? requestedIntake;
      const record = intakeId ? await service.store.readJournal(intakeId).catch(() => ({})) : {};
      failures.push({ title, ...error.toJSON(), phase: error.phase ?? record.phase,
        stagedRetained: error.stagedRetained, source: exportDirectory });
      emit({ step: title, status: 'rejected', code: error.code, category: classifyError(error.code),
        position: error.position ?? null, keyId: error.keyId ?? null, intakeId,
        phase: error.phase ?? record.phase, stagedRetained: error.stagedRetained,
        readerSees: record.phase === 'published' ? '—' : [],
        stagedPlaintextOnDisk: await hasPlaintextResidue(stateDirectory) });
      return intakeId ? { status: 'rejected', intakeId } : null;
    }
  }

  // 1. 轮换：两把合成密钥共存，同一份资料的新旧版本分别使用不同 keyId。
  const oldKey = generateLabKey('lab-2026');
  const newKey = generateLabKey('lab-2027');
  await writeLabKey(keysDirectory, oldKey);
  await writeLabKey(keysDirectory, newKey);

  const v1 = await createSyntheticExport({
    directory: join(working, 'export-v1'), exportId: 'export-A', version: 1,
    segments: [{ keyId: oldKey.id, plaintext: '探头,温度\n' }, { keyId: oldKey.id, plaintext: 'P1,3.1\n' },
      { keyId: oldKey.id, plaintext: 'P2,4.2\n' }],
    keys: new Map([[oldKey.id, oldKey.key]]), privateKey: identity.privateKey
  });
  await acceptStep('轮换前 v1（lab-2026）', { manifestPath: v1.manifestPath });

  const v2 = await createSyntheticExport({
    directory: join(working, 'export-v2'), exportId: 'export-A', version: 2,
    segments: [{ keyId: oldKey.id, plaintext: '探头,温度\n' }, { keyId: newKey.id, plaintext: 'P1,3.3\n' },
      { keyId: newKey.id, plaintext: 'P2,4.4\n' }],
    keys: new Map([[oldKey.id, oldKey.key], [newKey.id, newKey.key]]), privateKey: identity.privateKey
  });
  await acceptStep('轮换中 v2（前块旧钥、后块新钥）', { manifestPath: v2.manifestPath });

  // 2. 中间块损坏：签名清单不变，磁盘上的块被翻转一个字节。
  const damaged = await createSyntheticExport({
    directory: join(working, 'export-damaged'), exportId: 'export-B', version: 1,
    segments: [{ keyId: newKey.id, plaintext: '环境,湿度\n' }, { keyId: newKey.id, plaintext: 'H1,55\n' },
      { keyId: newKey.id, plaintext: 'H2,58\n' }],
    keys: new Map([[newKey.id, newKey.key]]), privateKey: identity.privateKey
  });
  const middle = join(damaged.directory, 'chunk-1.bin');
  await writeFile(middle, flipByte(await readFile(middle), 0));
  await acceptStep('中间块损坏（export-B）', { manifestPath: damaged.manifestPath }, { exportDirectory: 'export-B' });

  // 3. 顺序调换：清单里块数组倒序，但 position/AAD 仍然正确 → 应按位置排序后正常接纳；
  //    另一例把块的 aad 换成别的位置 → 必须在解密前拒绝。
  const reordered = await createSyntheticExport({
    directory: join(working, 'export-reordered'), exportId: 'export-C', version: 1,
    segments: [{ keyId: newKey.id, plaintext: '采样,压力\n' }, { keyId: newKey.id, plaintext: 'S1,101\n' },
      { keyId: newKey.id, plaintext: 'S2,102\n' }],
    keys: new Map([[newKey.id, newKey.key]]), privateKey: identity.privateKey,
    shuffleManifestOrder: true
  });
  await acceptStep('清单块倒序但位置正确（export-C）', { manifestPath: reordered.manifestPath });

  const swapped = await createSyntheticExport({
    directory: join(working, 'export-swapped'), exportId: 'export-D', version: 1,
    segments: [{ keyId: newKey.id, plaintext: '采样,流量\n' },
      { keyId: newKey.id, plaintext: 'F1,9\n', encryptAad: { exportId: 'export-D', version: 1, position: 0 } },
      { keyId: newKey.id, plaintext: 'F2,10\n' }],
    keys: new Map([[newKey.id, newKey.key]]), privateKey: identity.privateKey
  });
  await acceptStep('块2 的 AAD 指向位置0（export-D）', { manifestPath: swapped.manifestPath });

  // 4. 暂停后继续：先只认证 2 块，再恢复。恢复前顺手尝试用 v1 的记录继续 v2，
  //    验证“不同版本的块不能凑成一份”。
  const large = await createSyntheticExport({
    directory: join(working, 'export-pause'), exportId: 'export-E', version: 1,
    segments: [{ keyId: newKey.id, plaintext: '批次,编号\n' }, { keyId: newKey.id, plaintext: 'B1,001\n' },
      { keyId: newKey.id, plaintext: 'B2,002\n' }, { keyId: newKey.id, plaintext: 'B3,003\n' }],
    keys: new Map([[newKey.id, newKey.key]]), privateKey: identity.privateKey
  });
  const paused = await acceptStep('暂停：只认证前 2 块（export-E）',
    { manifestPath: large.manifestPath, maxBlocks: 2 });
  if (paused?.status === 'paused') {
    const v1Journal = (await service.store.listJournals()).find(item => item.exportId === 'export-A'
      && item.version === 1);
    // export-A v1 和 export-E v1 不是同一份导出：显式指定别人的记录必须拒绝。
    await acceptStep('尝试用 export-A 的记录继续 export-E', {
      manifestPath: large.manifestPath, resumeIntakeId: v1Journal?.intakeId
    });
    await acceptStep('从第 3 块继续（export-E）', {
      manifestPath: large.manifestPath, resumeIntakeId: paused.intakeId
    });
  }

  // 5. 缺密钥：先放一把合成密钥 lab-2028 到受控目录之外，制造“暂时没有权限”。
  const futureKey = generateLabKey('lab-2028');
  const futureExport = await createSyntheticExport({
    directory: join(working, 'export-future'), exportId: 'export-F', version: 2,
    segments: [{ keyId: newKey.id, plaintext: '设备,状态\n' }, { keyId: futureKey.id, plaintext: 'D1,on\n' }],
    keys: new Map([[newKey.id, newKey.key], [futureKey.id, futureKey.key]]), privateKey: identity.privateKey
  });
  const blocked = await acceptStep('缺少 lab-2028（export-F v2）', { manifestPath: futureExport.manifestPath });
  await writeLabKey(keysDirectory, futureKey);
  if (blocked?.intakeId) {
    await acceptStep('补上 lab-2028 后继续（export-F v2）', {
      manifestPath: futureExport.manifestPath, resumeIntakeId: blocked.intakeId
    });
  }

  // 6. 整份明文摘要失败：每块都通过认证，但清单声明的整体摘要不成立。
  const tampered = await createSyntheticExport({
    directory: join(working, 'export-cleartext'), exportId: 'export-G', version: 1,
    segments: [{ keyId: newKey.id, plaintext: '校准,值\n' }, { keyId: newKey.id, plaintext: 'C1,1\n' }],
    keys: new Map([[newKey.id, newKey.key]]), privateKey: identity.privateKey
  });
  const envelope = JSON.parse(await readFile(tampered.manifestPath, 'utf8'));
  const payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
  payload.cleartextSha256 = digest(Buffer.from('另一份资料'));
  await writeSignedManifest(tampered.directory, payload, identity.privateKey);
  await acceptStep('整体明文摘要不一致（export-G）', { manifestPath: tampered.manifestPath });

  const summary = {
    mode: 'synthetic-only',
    published: published.map(item => ({ title: item.title, intakeId: item.intakeId,
      sha256: item.sha256, size: item.size })),
    failures: failures.map(item => ({ title: item.title, code: item.code, category: item.category,
      position: item.position ?? null, keyId: item.keyId ?? null, stagedRetained: item.stagedRetained })),
    onlyCompleteExportsVisible: true,
    plaintextResidue: await hasPlaintextResidue(stateDirectory),
    steps: lines
  };
  if (json) console.log(JSON.stringify(summary, null, 2));
  else {
    console.log('');
    console.log(`已接纳（读者可见）：${summary.published.map(item => item.title).join('、') || '（无）'}`);
    console.log(`拒绝/阻塞（读者不可见）：${summary.failures.map(item => `${item.title} → ${item.category}/${item.code}`).join('；') || '（无）'}`);
    console.log(`状态目录中是否残留明文：${summary.plaintextResidue ? '是（异常）' : '否'}`);
  }
  if (cleanup) await rm(working, { recursive: true, force: true });
  return summary;
}

function downloadable(exportId, version) { return `${exportId} v${version}（完整）`; }

function format(entry) {
  const reader = Array.isArray(entry.readerSees)
    ? (entry.readerSees.length ? entry.readerSees.join(', ') : '（无）')
    : entry.readerSees;
  const ops = entry.status === 'rejected'
    ? `${entry.category}/${entry.code}${entry.position !== null && entry.position !== undefined ? ` @块${entry.position}` : ''}`
    : `intake=${entry.intakeId ?? '—'} resumedFrom=${entry.resumedFrom ?? '—'}`;
  return `• ${entry.step}\n    读者看到：${reader}\n    运维看到：${entry.status} ${ops}`;
}

/** 粗略检查接纳状态目录里是否出现了已知合成明文片段。
 *  已接纳对象（archive/objects）本就是发布给读者的完整资料，排除在外；
 *  这里查的是暂存、日志与中断残留。 */
async function hasPlaintextResidue(stateDirectory) {
  const needles = ['探头', 'P1,', 'H1,', 'S1,', 'F1,', 'B1,', 'D1,', 'C1,'];
  const { readdir } = await import('node:fs/promises');
  const publishedObjects = join(stateDirectory, 'archive', 'objects');
  async function walk(directory) {
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch { return false; }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (path === publishedObjects) continue;
        if (await walk(path)) return true;
        continue;
      }
      let bytes;
      try { bytes = await readFile(path); } catch { continue; }
      const text = bytes.toString('latin1');
      if (needles.some(needle => text.includes(Buffer.from(needle).toString('latin1')))) return true;
    }
    return false;
  }
  return walk(stateDirectory);
}
