import { mkdir, open, readFile, writeFile, rename, rm, readdir, stat } from 'node:fs/promises';
import { resolve, join, basename, isAbsolute, sep } from 'node:path';
import { createHash, randomUUID, createDecipheriv } from 'node:crypto';
import { inspect } from './domain.js';
import { digest } from './archive.js';
import {
  IntakeError, MissingBlockError, DigestMismatchError,
  AuthenticationError, IntakeConflictError, IntakeStateError,
} from './errors.js';

// 保留策略默认值：失败残留与日志都有明确的留存期限，到期由 sweep 清理。
export const DEFAULT_RETENTION = Object.freeze({
  quarantineTtlMs: 24 * 60 * 60 * 1000,   // 失败隔离区保留 24 小时
  journalMaxEntries: 500,                  // 审计日志最多 500 条
  journalMaxAgeMs: 7 * 24 * 60 * 60 * 1000, // 审计日志最多 7 天
});

export class Intake {
  constructor(directory, retention = {}, clock = () => new Date()) {
    this.directory = resolve(directory);
    this.retention = { ...DEFAULT_RETENTION, ...retention };
    this.clock = clock;
  }

  get #statePath() { return join(this.directory, 'state.json'); }
  get #journalPath() { return join(this.directory, 'journal.jsonl'); }
  get #stagingDir() { return join(this.directory, 'staging', 'blocks'); }
  get #quarantineDir() { return join(this.directory, 'quarantine'); }

  async #ensureLayout() {
    await mkdir(this.#stagingDir, { recursive: true, mode: 0o700 });
    await mkdir(this.#quarantineDir, { recursive: true, mode: 0o700 });
  }

  async #writeAtomic(path, bytes, mode = 0o600) {
    const temporary = `${path}.${randomUUID()}.tmp`;
    const handle = await open(temporary, 'wx', mode);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { await handle.close(); }
    try { await rename(temporary, path); }
    finally { await rm(temporary, { force: true }); }
  }

  async #readState() {
    try {
      const state = JSON.parse(await readFile(this.#statePath, 'utf8'));
      if (!state || !state.identity || typeof state.blocks !== 'object') {
        throw new IntakeStateError({ reason: '状态文件字段不完整' });
      }
      return state;
    } catch (error) {
      if (error instanceof IntakeError) throw error;
      if (error.code === 'ENOENT') return null;
      throw new IntakeStateError({ reason: '状态文件无法解析' }, error);
    }
  }

  async #writeState(state) {
    await this.#writeAtomic(this.#statePath, Buffer.from(JSON.stringify(state, null, 2)));
  }

  async #journal(event) {
    const entry = { at: this.clock().toISOString(), ...event };
    await this.#ensureLayout();
    const handle = await open(this.#journalPath, 'a', 0o600);
    try { await handle.writeFile(`${JSON.stringify(entry)}\n`); }
    finally { await handle.close(); }
  }

  #trimJournal(entries) {
    const cutoff = this.clock().getTime() - this.retention.journalMaxAgeMs;
    const fresh = entries.filter(e => {
      const t = Date.parse(e.at);
      return Number.isFinite(t) && t >= cutoff;
    });
    return fresh.slice(-this.retention.journalMaxEntries);
  }

  // 保留策略执行：清理过期隔离残留，并按条数/期限裁剪审计日志。
  async sweep() {
    await this.#ensureLayout();
    const removed = { quarantine: 0, journalEntries: 0 };
    const now = this.clock().getTime();
    for (const name of await readdir(this.#quarantineDir)) {
      const path = join(this.#quarantineDir, name);
      try {
        const info = await stat(path);
        if (now - info.mtimeMs >= this.retention.quarantineTtlMs) {
          await rm(path, { recursive: true, force: true });
          removed.quarantine += 1;
        }
      } catch { /* 已被并发清理则忽略 */ }
    }
    let entries = [];
    try {
      const raw = await readFile(this.#journalPath, 'utf8');
      entries = raw.split('\n').filter(Boolean).map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const kept = this.#trimJournal(entries);
    removed.journalEntries = entries.length - kept.length;
    if (removed.journalEntries > 0) {
      await this.#writeAtomic(this.#journalPath, Buffer.from(kept.map(e => JSON.stringify(e)).join('\n') + (kept.length ? '\n' : '')));
    }
    return removed;
  }

  async snapshot() {
    const state = await this.#readState();
    if (!state) return { status: 'empty' };
    return { ...state, keyStoreAccess: undefined };
  }

  #blockPath(exportRoot, block) {
    if (isAbsolute(block.file) || block.file.includes('..') || block.file.includes(sep)) {
      throw new IntakeStateError({ position: block.position, reason: '块文件路径越界' });
    }
    return resolve(join(exportRoot, basename(block.file)));
  }

  // 失败处理：把触发问题的密文残料移入隔离区（绝不隔离明文），
  // 清空暂存区中的部分明文，并在审计日志记录分类错误。
  async #handleFailure(error, state, exportRoot, block) {
    state.status = 'failed';
    state.failure = error instanceof IntakeError ? error.toJSON() : { code: 'UNKNOWN', message: String(error) };
    await this.#writeState(state);

    if (block) {
      let quarantinedBytes = null;
      try {
        quarantinedBytes = await readFile(this.#blockPath(exportRoot, block));
      } catch { /* 缺块等场景没有可隔离的字节 */ }
      if (quarantinedBytes) {
        const qdir = join(this.#quarantineDir, `${this.clock().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}`);
        await mkdir(qdir, { recursive: true, mode: 0o700 });
        await this.#writeAtomic(join(qdir, `block-${block.position}.bin`), quarantinedBytes);
        await this.#writeAtomic(join(qdir, 'info.json'), Buffer.from(JSON.stringify({
          at: this.clock().toISOString(),
          exportId: state.identity.exportId,
          version: state.identity.version,
          position: block.position,
          error: state.failure,
        }, null, 2)));
        await this.#journal({ event: 'quarantine_written', position: block.position, code: state.failure.code, quarantine: basename(qdir) });
      }
    }
    // 未经完整接纳的部分明文不允许残留在暂存区。
    await rm(this.#stagingDir, { recursive: true, force: true });
    await mkdir(this.#stagingDir, { recursive: true, mode: 0o700 });
    for (const position of Object.keys(state.blocks)) state.blocks[position].status = 'pending';
    await this.#writeState(state);
    await this.#journal({ event: 'intake_failed', code: state.failure.code, details: state.failure.details });
  }

  // 执行一次接纳推进。maxBlocks 限制本次调用处理的块数，用于“暂停后继续”。
  // 任何分类错误都会抛出 IntakeError；只有全部块通过认证并登记入库才算成功。
  async run(manifestPath, keyStore, archive, { maxBlocks = Infinity } = {}) {
    await this.#ensureLayout();
    await this.sweep();
    const exportRoot = resolve(dirnameOf(manifestPath));
    const inventory = await inspect(manifestPath); // 先验证清单来源，再做任何解密
    const { manifest, payloadHash } = inventory;

    let state = await this.#readState();
    if (state) {
      const id = state.identity;
      // 接纳边界按导出身份（exportId + 版本）绑定；同一身份重新下发的修复清单允许续跑，
      // 不同身份一律拒绝，避免把不同版本的块凑成一份。
      if (id.exportId !== manifest.exportId || id.version !== manifest.version) {
        throw new IntakeConflictError({
          bound: { exportId: id.exportId, version: id.version },
          incoming: { exportId: manifest.exportId, version: manifest.version },
        });
      }
      if (state.status === 'complete') return { status: 'complete', receiptId: state.receiptId, alreadyAccepted: true };
      // 修复清单：登记最新的清单摘要并重置暂存块，按新清单重新核验
      if (id.payloadHash !== payloadHash) {
        id.payloadHash = payloadHash;
        id.manifestPath = resolve(manifestPath);
        state.blocks = Object.fromEntries(manifest.blocks.map(b => [b.position, { status: 'pending', keyId: b.keyId, sha256: b.sha256 }]));
        await rm(this.#stagingDir, { recursive: true, force: true });
        await mkdir(this.#stagingDir, { recursive: true, mode: 0o700 });
        await this.#writeState(state);
        await this.#journal({ event: 'manifest_updated', exportId: manifest.exportId, version: manifest.version, payloadHash });
      }
    } else {
      state = {
        identity: { exportId: manifest.exportId, version: manifest.version, payloadHash, manifestPath: resolve(manifestPath) },
        status: 'in_progress',
        blocks: Object.fromEntries(manifest.blocks.map(b => [b.position, { status: 'pending', keyId: b.keyId, sha256: b.sha256 }])),
        startedAt: this.clock().toISOString(),
      };
      await this.#writeState(state);
    }
    await this.#journal({ event: 'intake_start', exportId: manifest.exportId, version: manifest.version, payloadHash });

    // 恢复时核对暂存块：摘要不符或文件缺失的块回到 pending，重做解密。
    for (const block of manifest.blocks) {
      const record = state.blocks[block.position];
      if (record.status !== 'staged') continue;
      try {
        const staged = await readFile(join(this.#stagingDir, String(block.position)));
        if (digest(staged) !== record.plaintextSha256) throw new Error('stale');
      } catch {
        record.status = 'pending';
        delete record.plaintextSha256;
        await this.#journal({ event: 'block_reset', position: block.position, reason: '暂存块缺失或摘要不符' });
      }
    }
    await this.#writeState(state);

    let budget = Number.isFinite(maxBlocks) ? maxBlocks : manifest.blocks.length;
    let paused = false;
    try {
      for (const block of manifest.blocks) {
        const record = state.blocks[block.position];
        if (record.status === 'staged') continue;
        if (budget <= 0) { paused = true; break; }
        budget -= 1;

        // 1) 块必须存在
        const path = this.#blockPath(exportRoot, block);
        let cipherBytes;
        try {
          cipherBytes = await readFile(path);
        } catch (error) {
          if (error.code === 'ENOENT') throw new MissingBlockError({ position: block.position, file: block.file, keyId: block.keyId });
          throw error;
        }

        // 2) 密文摘要必须与清单一致（调换/损坏在此拦截，且先于任何解密动作）
        if (digest(cipherBytes) !== block.sha256) {
          throw new DigestMismatchError({ position: block.position, file: block.file,
            expected: block.sha256, actual: digest(cipherBytes) });
        }

        // 3) 按 key ID 精确领取授权，绝不遍历密钥试解
        const granted = await keyStore.claim(block.keyId, { exportId: manifest.exportId, position: block.position });

        // 4) AES-256-GCM：以清单登记的 AAD 认证“属于哪份导出、哪个位置”
        let plaintext;
        try {
          const decipher = createDecipheriv('aes-256-gcm', granted.bytes, Buffer.from(block.iv, 'base64url'), { authTagLength: 16 });
          decipher.setAAD(Buffer.from(block.aad, 'base64url'));
          decipher.setAuthTag(Buffer.from(block.tag, 'base64url'));
          plaintext = Buffer.concat([decipher.update(cipherBytes), decipher.final()]);
        } catch (cause) {
          throw new AuthenticationError({ position: block.position, keyId: block.keyId, file: block.file }, cause);
        }

        await this.#writeAtomic(join(this.#stagingDir, String(block.position)), plaintext);
        record.status = 'staged';
        record.plaintextSha256 = digest(plaintext);
        record.stagedAt = this.clock().toISOString();
        await this.#writeState(state);
        await this.#journal({ event: 'block_staged', position: block.position, keyId: block.keyId });
      }

      if (paused) {
        state.status = 'paused';
        await this.#writeState(state);
        await this.#journal({ event: 'intake_paused', staged: manifest.blocks.filter(b => state.blocks[b.position].status === 'staged').length, total: manifest.blocks.length });
        return { status: 'paused', ...this.#progress(state, manifest) };
      }

      // 5) 按块顺序拼装，核对全文摘要后才允许发布
      const ordered = manifest.blocks.slice().sort((a, b) => a.position - b.position);
      const parts = await Promise.all(ordered.map(b => readFile(join(this.#stagingDir, String(b.position)))));
      const full = Buffer.concat(parts);
      if (digest(full) !== manifest.cleartextSha256) {
        throw new DigestMismatchError({ stage: 'assembly', expected: manifest.cleartextSha256, actual: digest(full) });
      }

      // 6) 登记入库：内容对象 + 来源回执，读者只能从归档读到完整资料
      const receipt = await archive.accept(full, {
        exportId: manifest.exportId,
        version: manifest.version,
        manifestPayloadHash: payloadHash,
        blocks: manifest.blocks.map(b => ({ position: b.position, keyId: b.keyId, sha256: b.sha256 })),
      });
      state.status = 'complete';
      state.receiptId = receipt.id;
      state.completedAt = this.clock().toISOString();
      await this.#writeState(state);
      await this.#journal({ event: 'intake_completed', receiptId: receipt.id, sha256: receipt.sha256, size: receipt.size });

      // 7) 接纳成功后清理临时明文
      await rm(this.#stagingDir, { recursive: true, force: true });
      await mkdir(this.#stagingDir, { recursive: true, mode: 0o700 });
      return { status: 'complete', receiptId: receipt.id, sha256: receipt.sha256, size: receipt.size, ...this.#progress(state, manifest) };
    } catch (error) {
      await this.#handleFailure(error, state, exportRoot, error.details && Number.isInteger(error.details.position)
        ? manifest.blocks.find(b => b.position === error.details.position) : undefined);
      throw error;
    }
  }

  #progress(state, manifest) {
    const staged = manifest.blocks.filter(b => state.blocks[b.position].status === 'staged').length;
    return { staged, total: manifest.blocks.length };
  }
}

function dirnameOf(p) {
  return resolve(p, '..');
}
