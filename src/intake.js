import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, readdir, rm, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Archive } from './archive.js';
import { ERROR_CODES, SealedError, classifyError } from './errors.js';
import { writeAtomic } from './fsutil.js';
import { digest, loadSignedManifest, resolveBlockPath } from './manifest.js';
import { decryptBlock, wipe } from './sealed.js';

const JOURNAL_VERSION = 1;
const DEFAULT_RETENTION_DAYS = 30;

async function readIfExists(path) {
  try { return await readFile(path); }
  catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
}

async function findFiles(directory, predicate, found = []) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error?.code === 'ENOENT') return found; throw error; }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await findFiles(path, predicate, found);
    else if (predicate(entry.name)) found.push(path);
  }
  return found;
}

/**
 * 接纳状态目录。暂存只在“已通过 GCM 认证”的块上产生，并且以本地状态密钥加密后落盘，
 * 因此暂停、崩溃或失败都不会在磁盘上留下明文。暂存密文的附加认证数据包含
 * intakeId/exportId/version/manifestDigest/position，不同版本之间无法互换暂存块。
 */
export class IntakeStore {
  constructor(directory) {
    this.directory = resolve(directory);
    this.journals = join(this.directory, 'journal');
    this.intakes = join(this.directory, 'intakes');
    this.logs = join(this.directory, 'logs');
    this.stateKeyPath = join(this.directory, '.state-key');
    this.stateKey = null;
  }

  async initialize() {
    for (const path of [this.directory, this.journals, this.intakes, this.logs]) {
      await mkdir(path, { recursive: true, mode: 0o700 });
    }
    if (!this.stateKey) this.stateKey = await this.loadStateKey();
  }

  async loadStateKey() {
    const existing = await readIfExists(this.stateKeyPath);
    if (existing) {
      const key = Buffer.from(existing.toString('utf8').trim(), 'base64url');
      if (key.length !== 32) throw new SealedError(ERROR_CODES.JOURNAL_CORRUPT, '本地状态密钥长度不正确');
      return key;
    }
    const created = randomBytes(32);
    try {
      await writeAtomic(this.stateKeyPath, created.toString('base64url'), 0o600);
      return created;
    } catch (error) {
      // 另一个进程可能已抢先创建；以磁盘上的为准。
      const raced = await readIfExists(this.stateKeyPath);
      if (raced) return Buffer.from(raced.toString('utf8').trim(), 'base64url');
      throw error;
    }
  }

  intakeDirectory(intakeId) { return join(this.intakes, intakeId); }
  stagingPath(intakeId, position) {
    return join(this.intakeDirectory(intakeId), 'blocks', `${position}.json`);
  }
  journalPath(intakeId) { return join(this.journals, `${intakeId}.json`); }
  logPath(intakeId) { return join(this.logs, `${intakeId}.jsonl`); }

  assertIntakeId(intakeId) {
    if (typeof intakeId !== 'string' || !/^[A-Za-z0-9-]{8,64}$/.test(intakeId)) {
      throw new SealedError(ERROR_CODES.JOURNAL_CORRUPT, '接纳标识格式不正确');
    }
    return intakeId;
  }

  stagingAad(intakeId, journal, position) {
    return Buffer.from(JSON.stringify({
      intakeId, exportId: journal.exportId, version: journal.version,
      manifestDigest: journal.manifestDigest, position
    }));
  }

  async writeStaged(intakeId, journal, position, plaintext) {
    await this.initialize();
    const directory = join(this.intakeDirectory(intakeId), 'blocks');
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.stateKey, iv);
    const aad = this.stagingAad(intakeId, journal, position);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const frame = {
      v: 1, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
      ciphertext: ciphertext.toString('base64url'), sha256: digest(ciphertext)
    };
    await writeAtomic(this.stagingPath(intakeId, position), JSON.stringify(frame), 0o600);
    return frame.sha256;
  }

  /** 读取暂存块；任何损坏都视为该块未暂存，可重新解密而不是接纳坏数据。 */
  async readStaged(intakeId, journal, position) {
    const bytes = await readIfExists(this.stagingPath(intakeId, position));
    if (!bytes) return null;
    let frame;
    try { frame = JSON.parse(bytes.toString('utf8')); }
    catch { return null; }
    if (frame?.v !== 1 || typeof frame.iv !== 'string' || typeof frame.tag !== 'string'
      || typeof frame.ciphertext !== 'string') return null;
    const ciphertext = Buffer.from(frame.ciphertext, 'base64url');
    if (digest(ciphertext) !== frame.sha256) return null;
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.stateKey,
        Buffer.from(frame.iv, 'base64url'));
      decipher.setAAD(this.stagingAad(intakeId, journal, position));
      decipher.setAuthTag(Buffer.from(frame.tag, 'base64url'));
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      return null;
    }
  }

  async discardStaged(intakeId) {
    await rm(this.intakeDirectory(intakeId), { recursive: true, force: true });
  }

  async writeJournal(journal) {
    await this.initialize();
    const record = { ...journal, journalVersion: JOURNAL_VERSION,
      updatedAt: new Date().toISOString() };
    await writeAtomic(this.journalPath(journal.intakeId), JSON.stringify(record, null, 2), 0o600);
    return record;
  }

  async readJournal(intakeId) {
    this.assertIntakeId(intakeId);
    const bytes = await readIfExists(this.journalPath(intakeId));
    if (!bytes) throw new SealedError(ERROR_CODES.JOURNAL_CORRUPT, `找不到接纳记录 ${intakeId}`);
    try { return JSON.parse(bytes.toString('utf8')); }
    catch (error) {
      throw new SealedError(ERROR_CODES.JOURNAL_CORRUPT, `接纳记录 ${intakeId} 无法解析`, { detail: error.message });
    }
  }

  async listJournals() {
    await this.initialize();
    const names = (await readdir(this.journals)).filter(name => name.endsWith('.json')).sort();
    const records = [];
    for (const name of names) {
      try { records.push(JSON.parse(await readFile(join(this.journals, name), 'utf8'))); }
      catch { /* 损坏记录不参与自动继续，保留给运维排查 */ }
    }
    return records;
  }

  async log(intakeId, event) {
    await this.initialize();
    const line = JSON.stringify({ at: new Date().toISOString(), intakeId, ...event });
    const handle = await open(this.logPath(intakeId), 'a', 0o600);
    try { await handle.write(line + '\n'); await handle.sync(); }
    finally { await handle.close(); }
  }

  async readLog(intakeId) {
    const bytes = await readIfExists(this.logPath(this.assertIntakeId(intakeId)));
    if (!bytes) return [];
    return bytes.toString('utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  }

  /**
   * 保留策略：终结记录（已接纳/已失败/已阻塞）超过保留天数后，删除暂存、日志与记录。
   * 未终结且仍在进行中的记录不动，避免误删正在恢复的接纳。
   */
  async prune({ retentionDays = DEFAULT_RETENTION_DAYS, now = new Date() } = {}) {
    await this.initialize();
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;
    const removed = [];
    for (const journal of await this.listJournals()) {
      if (!['published', 'failed', 'blocked'].includes(journal.phase)) continue;
      const stamp = Date.parse(journal.updatedAt);
      if (!Number.isFinite(stamp) || stamp > cutoff) continue;
      await this.discardStaged(journal.intakeId);
      await rm(this.journalPath(journal.intakeId), { force: true });
      await rm(this.logPath(journal.intakeId), { force: true });
      removed.push(journal.intakeId);
    }
    // 原子写入中断留下的同目录临时文件同样受保留策略约束，避免永久残留。
    for (const path of await findFiles(this.directory, name => name.endsWith('.tmp'))) {
      const info = await stat(path);
      if (info.mtime.getTime() <= cutoff) await rm(path, { force: true });
    }
    return removed;
  }
}

/**
 * 接纳边界：
 * 1. 先验签清单，再校验结构与每块 AAD 归属；
 * 2. 逐块核对密文摘要（无钥）→ 按声明的 keyId 取密钥 → GCM 认证；
 * 3. 认证通过的块加密暂存，可暂停/恢复；任何一块失败都不会对外发布；
 * 4. 全部块认证且整体明文摘要匹配后，才一次性写入对象与回执。
 */
export class IntakeService {
  constructor({ stateDirectory, keyStore, archive, signingPublicKeyPath, retentionDays } = {}) {
    this.store = new IntakeStore(stateDirectory);
    this.keyStore = keyStore;
    this.archive = archive ?? new Archive(join(resolve(stateDirectory), 'archive'));
    this.signingPublicKeyPath = signingPublicKeyPath;
    this.retentionDays = retentionDays ?? DEFAULT_RETENTION_DAYS;
  }

  async initialize() {
    await this.store.initialize();
    await this.archive.initialize();
  }

  /** 仅解码清单，不取钥、不解密。用于运维确认“拿到的是哪一版”。 */
  async inspect(manifestPath, { publicKeyPath } = {}) {
    const opened = await loadSignedManifest(manifestPath, {
      publicKeyPath: publicKeyPath ?? this.signingPublicKeyPath
    });
    return {
      signed: true, exportId: opened.manifest.exportId, version: opened.manifest.version,
      blockCount: opened.manifest.blocks.length, manifestDigest: opened.manifestDigest,
      keyIds: [...new Set(opened.manifest.blocks.map(block => block.keyId))],
      blocks: opened.manifest.blocks.map(block => ({ position: block.position, file: block.file,
        keyId: block.keyId, alg: block.alg, sha256: block.sha256 }))
    };
  }

  /**
   * 按“导出 + 版本 + 清单载荷摘要”精确匹配既有接纳记录。
   * 同一份已签名清单的重试应幂等返回既有回执，而不是重复登记；
   * 清单摘要不同（哪怕导出标识、版本号相同）一律视为另一次接纳。
   */
  async findExisting(opened) {
    const candidates = (await this.store.listJournals()).filter(journal =>
      journal.exportId === opened.manifest.exportId
      && journal.version === opened.manifest.version
      && journal.manifestDigest === opened.manifestDigest
      && ['staging', 'committing', 'blocked', 'published'].includes(journal.phase));
    candidates.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
    return candidates[0] ?? null;
  }

  /**
   * @param {object} options
   * @param {string} options.manifestPath 已签名清单路径
   * @param {string} [options.publicKeyPath] 验签公钥路径
   * @param {string} [options.resumeIntakeId] 显式恢复某次接纳
   * @param {number} [options.maxBlocks] 本次最多新解密多少块；达到即暂停（用于演示/分批）
   */
  async accept({ manifestPath, publicKeyPath, resumeIntakeId, maxBlocks = Infinity }) {
    await this.initialize();
    const opened = await loadSignedManifest(manifestPath, {
      publicKeyPath: publicKeyPath ?? this.signingPublicKeyPath
    });
    const { manifest } = opened;

    let journal = null;
    let resumedFrom = null;
    if (resumeIntakeId) {
      journal = await this.store.readJournal(resumeIntakeId);
      this.assertResumeCompatible(journal, opened);
      if (!['staging', 'committing', 'blocked', 'failed'].includes(journal.phase)) {
        if (journal.phase === 'published') return this.publishedResult(journal, { resumedFrom: 'published' });
        throw new SealedError(ERROR_CODES.RESUME_MISMATCH,
          `接纳 ${resumeIntakeId} 已处于 ${journal.phase} 状态，不能继续`, { ...this.context(manifest) });
      }
      resumedFrom = resumeIntakeId;
    } else {
      journal = await this.findExisting(opened);
      if (journal) {
        resumedFrom = journal.intakeId;
        if (journal.phase === 'published') return this.publishedResult(journal, { resumedFrom });
      }
    }

    if (!journal) {
      journal = {
        intakeId: randomUUID(),
        exportId: manifest.exportId,
        version: manifest.version,
        manifestDigest: opened.manifestDigest,
        cleartextSha256: manifest.cleartextSha256,
        keyIds: [...new Set(manifest.blocks.map(block => block.keyId))].sort(),
        blockDigests: manifest.blocks.map(block => ({ position: block.position, sha256: block.sha256 })),
        chunks: [],
        phase: 'staging',
        createdAt: new Date().toISOString()
      };
      journal = await this.store.writeJournal(journal);
      await this.store.log(journal.intakeId, { event: 'intake-created',
        exportId: manifest.exportId, version: manifest.version,
        manifestDigest: opened.manifestDigest, blockCount: manifest.blocks.length });
    } else {
      journal = await this.store.writeJournal({ ...journal, chunks: journal.chunks ?? [] });
      await this.store.log(journal.intakeId, { event: 'intake-resumed', phase: journal.phase,
        staged: journal.chunks.length, manifestDigest: journal.manifestDigest });
    }

    // committing 阶段恢复：回执可能已落盘，先确认是否其实已完成接纳。
    // 注意必须在把阶段归正为 staging 之前判断。
    if (journal.phase === 'committing' && journal.receiptId) {
      const existing = await this.archive.receipt(journal.receiptId);
      if (existing) {
        return this.finalizePublished(journal, existing, { resumedFrom });
      }
    }
    // 无论是继续 staging 还是提交一半后重来，后续都从 staging 阶段重新走。
    if (journal.phase !== 'staging') {
      journal = await this.store.writeJournal({ ...journal, phase: 'staging' });
    }

    const staged = new Map(journal.chunks.map(chunk => [chunk.position, chunk]));
    const acknowledged = new Map();
    let newlyAuthenticated = 0;
    let lastPosition = null;

    try {
      for (const block of manifest.blocks) {
        const context = { ...this.context(manifest), position: block.position, keyId: block.keyId };
        lastPosition = block.position;

        // 已暂存的块必须能从本地状态密钥解出，并且摘要仍与清单一致，否则重新解密。
        const previous = staged.get(block.position);
        if (previous) {
          const plaintext = await this.store.readStaged(journal.intakeId, journal, block.position);
          if (plaintext && digest(plaintext) === previous.plaintextSha256) {
            acknowledged.set(block.position, { plaintext, sha256: previous.plaintextSha256,
              stagedSha256: previous.stagedSha256, reused: true });
            continue;
          }
          await this.store.log(journal.intakeId, { event: 'staged-block-discarded',
            position: block.position, reason: 'unreadable-or-digest-mismatch' });
        }

        if (newlyAuthenticated >= maxBlocks) {
          await this.store.log(journal.intakeId, { event: 'intake-paused',
            nextPosition: block.position, authenticated: acknowledged.size });
          // 释放本批已读取的暂存明文引用；它们已加密落盘。
          for (const entry of acknowledged.values()) wipe(entry.plaintext);
          return {
            status: 'paused', intakeId: journal.intakeId,
            exportId: manifest.exportId, version: manifest.version,
            resumedFrom, authenticatedPositions: [...acknowledged.keys()].sort((a, b) => a - b),
            nextPosition: block.position
          };
        }

        const ciphertext = await this.readBlockCiphertext(opened, block, context);
        const key = await this.keyStore.get(block.keyId, context);
        let plaintext;
        try {
          plaintext = decryptBlock(block, ciphertext, key, context);
        } finally { wipe(ciphertext); }

        const plaintextSha256 = digest(plaintext);
        // 只覆盖当前位置的暂存文件；其它位置的已认证暂存继续保留，避免因单块重算清空整次接纳。
        const stagedSha256 = await this.store.writeStaged(journal.intakeId, journal, block.position, plaintext);
        const chunk = { position: block.position, keyId: block.keyId,
          plaintextSha256, stagedSha256, authenticatedAt: new Date().toISOString() };
        acknowledged.set(block.position, { ...chunk, plaintext });
        journal = await this.store.writeJournal({
          ...journal, chunks: [...staged.values()].filter(item => item.position !== block.position)
            .concat(chunk).sort((a, b) => a.position - b.position)
        });
        staged.set(block.position, chunk);
        newlyAuthenticated += 1;
        await this.store.log(journal.intakeId, { event: 'block-authenticated',
          position: block.position, keyId: block.keyId, plaintextSha256 });
        // 明文仍在内存中，由后续整体摘要校验使用；暂存副本已加密。
      }

      // 所有块都已认证，才能组装整体明文并核对清单摘要。
      const cleartext = Buffer.concat(manifest.blocks.map(block => acknowledged.get(block.position).plaintext));
      try {
        const cleartextSha256 = digest(cleartext);
        if (cleartextSha256 !== manifest.cleartextSha256) {
          throw new SealedError(ERROR_CODES.CLEARTEXT_DIGEST,
            '组装后的明文摘要与清单不一致，拒绝接纳', this.context(manifest));
        }
        return await this.publish(journal, cleartext, cleartextSha256, { resumedFrom });
      } finally {
        wipe(cleartext);
        for (const entry of acknowledged.values()) wipe(entry.plaintext);
      }
    } catch (error) {
      if (!(error instanceof SealedError)) throw error;
      return this.fail(journal, error, { lastPosition, resumedFrom });
    }
  }

  assertResumeCompatible(journal, opened) {
    const context = this.context(opened.manifest);
    if (journal.exportId !== opened.manifest.exportId || journal.version !== opened.manifest.version
      || journal.manifestDigest !== opened.manifestDigest) {
      throw new SealedError(ERROR_CODES.RESUME_MISMATCH,
        `接纳 ${journal.intakeId} 属于导出 ${journal.exportId} v${journal.version}，`
        + `与当前清单 ${opened.manifest.exportId} v${opened.manifest.version} 不同，拒绝拼接不同版本`,
        { ...context, detail: `记录 ${journal.manifestDigest}，当前 ${opened.manifestDigest}` });
    }
    const recorded = new Map((journal.blockDigests ?? []).map(item => [item.position, item.sha256]));
    const current = new Map(opened.manifest.blocks.map(block => [block.position, block.sha256]));
    if (recorded.size !== current.size
      || [...current].some(([position, sha]) => recorded.get(position) !== sha)) {
      throw new SealedError(ERROR_CODES.RESUME_MISMATCH,
        '清单块摘要与接纳记录不一致，拒绝继续', context);
    }
  }

  context(manifest) { return { exportId: manifest.exportId, version: manifest.version }; }

  async readBlockCiphertext(opened, block, context) {
    const path = resolveBlockPath(opened.directory, block.file);
    let bytes;
    try { bytes = await readFile(path); }
    catch (error) {
      if (error?.code === 'ENOENT') {
        throw new SealedError(ERROR_CODES.BLOCK_MISSING, `缺少块文件 ${block.file}`, context);
      }
      throw error;
    }
    return bytes;
  }

  async publish(journal, cleartext, cleartextSha256, { resumedFrom }) {
    const receiptId = journal.receiptId ?? randomUUID();
    journal = await this.store.writeJournal({ ...journal, phase: 'committing', receiptId });
    const receipt = await this.archive.accept(cleartext, {
      source: 'sealed-export', exportId: journal.exportId, version: journal.version,
      manifestDigest: journal.manifestDigest, intakeId: journal.intakeId,
      blockDigests: journal.blockDigests,
      keyIds: [...new Set(journal.chunks.map(chunk => chunk.keyId))].sort()
    }, { id: receiptId });
    return this.finalizePublished(journal, receipt, { resumedFrom });
  }

  async finalizePublished(journal, receipt, { resumedFrom } = {}) {
    const published = await this.store.writeJournal({
      ...journal, phase: 'published', receiptId: receipt.id, receiptSha256: receipt.sha256,
      publishedAt: receipt.observedAt, chunks: journal.chunks ?? []
    });
    await this.store.discardStaged(journal.intakeId);
    await this.store.log(journal.intakeId, { event: 'intake-published',
      receiptId: receipt.id, sha256: receipt.sha256, size: receipt.size });
    return {
      status: 'published', intakeId: journal.intakeId, resumedFrom,
      exportId: published.exportId, version: published.version,
      manifestDigest: published.manifestDigest, cleartextSha256: journal.cleartextSha256,
      blockCount: journal.blockDigests.length, receipt
    };
  }

  publishedResult(journal, { resumedFrom } = {}) {
    return {
      status: 'published', intakeId: journal.intakeId, resumedFrom,
      exportId: journal.exportId, version: journal.version,
      manifestDigest: journal.manifestDigest, cleartextSha256: journal.cleartextSha256,
      blockCount: journal.blockDigests?.length ?? 0,
      receipt: { id: journal.receiptId, sha256: journal.receiptSha256 }
    };
  }

  /**
   * 缺密钥属于授权问题：保留已认证的加密暂存，补上密钥后可以继续。
   * 完整性/状态问题属于资料问题：清除暂存，避免失败残留，且绝不接纳部分明文。
   */
  async fail(journal, error, { lastPosition, resumedFrom }) {
    const category = classifyError(error.code);
    const phase = category === 'authorization' ? 'blocked' : 'failed';
    const failure = { code: error.code, category, position: error.position ?? lastPosition,
      keyId: error.keyId, detail: error.detail };
    const record = await this.store.writeJournal({
      ...journal, phase, failure,
      chunks: journal.chunks ?? []
    });
    if (phase === 'failed') await this.store.discardStaged(journal.intakeId);
    await this.store.log(journal.intakeId, { event: 'intake-failed', ...failure,
      retainedStaged: phase === 'blocked' });
    const wrapped = new SealedError(error.code, error.message, {
      exportId: journal.exportId, version: journal.version,
      position: error.position ?? lastPosition, keyId: error.keyId
    });
    wrapped.intakeId = journal.intakeId;
    wrapped.phase = record.phase;
    wrapped.resumedFrom = resumedFrom ?? null;
    wrapped.stagedRetained = phase === 'blocked';
    throw wrapped;
  }
}
