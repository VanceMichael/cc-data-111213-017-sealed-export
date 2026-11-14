import { appendFile, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createDecipheriv } from 'node:crypto';
import { digest, writeAtomic } from './archive.js';
import { inspect } from './domain.js';

// 失败分类：运维据此区分“授权领取问题”与“完整性问题”，不再把缺钥匙误报成文件损坏
const CODE_CATEGORY = {
  MANIFEST_SIGNATURE_INVALID: 'manifest',
  MANIFEST_INVALID: 'manifest',
  ALG_UNSUPPORTED: 'manifest',
  KEY_MISSING: 'authorization',
  KEY_RECORD_INVALID: 'authorization',
  BLOCK_MISSING: 'integrity',
  BLOCK_DIGEST_MISMATCH: 'integrity',
  AAD_MISMATCH: 'integrity',
  BLOCK_AUTH_FAILED: 'integrity',
  CLEARTEXT_DIGEST_MISMATCH: 'integrity',
  SESSION_MANIFEST_MISMATCH: 'integrity',
};

export class IntakeError extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(message, options);
    this.name = 'IntakeError';
    this.code = code;
    this.category = CODE_CATEGORY[code] ?? 'internal';
    this.details = details;
  }
}

const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const EXPORT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX64 = /^[a-f0-9]{64}$/;

// 受控钥匙目录：只按清单声明的 key ID 精确领取，绝不遍历目录逐个试解。
// 新旧 key ID 可以共存（各自一个 <keyId>.json），但用哪把钥匙完全由清单决定。
export class KeyDirectory {
  constructor(directory) {
    this.directory = resolve(directory);
    this.cache = new Map();
  }
  async load(keyId) {
    if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
      throw new IntakeError('KEY_MISSING', `key ID「${String(keyId)}」格式不合法，无法从受控目录领取`, { keyId });
    }
    if (!this.cache.has(keyId)) {
      let record;
      try {
        record = JSON.parse(await readFile(join(this.directory, `${keyId}.json`), 'utf8'));
      } catch (error) {
        if (error.code === 'ENOENT') {
          throw new IntakeError('KEY_MISSING',
            `受控目录中没有 key ID「${keyId}」的钥匙，属于授权领取问题，不是文件损坏`, { keyId });
        }
        throw error;
      }
      if (record?.id !== keyId || typeof record?.key !== 'string') {
        throw new IntakeError('KEY_RECORD_INVALID', `受控目录中 ${keyId}.json 的记录与 key ID 不一致`, { keyId });
      }
      const key = Buffer.from(record.key, 'base64url');
      if (key.length !== 32) {
        throw new IntakeError('KEY_RECORD_INVALID', `受控目录中 ${keyId}.json 的钥匙长度不是 256 位`, { keyId });
      }
      this.cache.set(keyId, key);
    }
    return this.cache.get(keyId);
  }
}

// 清单结构校验：在验签之后、逐块处理之前执行
export function validateManifest(manifest) {
  const fail = (message, details = {}) => { throw new IntakeError('MANIFEST_INVALID', message, details); };
  if (!manifest || typeof manifest !== 'object') fail('清单内容不是对象');
  const { exportId, version, blocks, cleartextSha256 } = manifest;
  if (typeof exportId !== 'string' || !EXPORT_ID_PATTERN.test(exportId)) {
    fail('exportId 缺失或含有不允许的字符', { exportId });
  }
  if (!Number.isInteger(version) || version < 1) fail('version 必须是正整数', { version });
  if (typeof cleartextSha256 !== 'string' || !HEX64.test(cleartextSha256)) fail('cleartextSha256 格式不正确');
  if (!Array.isArray(blocks) || blocks.length === 0) fail('blocks 必须是非空数组');
  for (const [index, block] of blocks.entries()) {
    if (!block || typeof block !== 'object') fail(`块 ${index} 不是对象`);
    if (block.position !== index) fail(`块顺序不连续：数组第 ${index} 项声明 position ${block.position}`);
    if (typeof block.file !== 'string' || block.file.length === 0
      || block.file.includes('/') || block.file.includes('\\') || block.file.includes('..')) {
      fail(`块 ${index} 的文件名必须是导出目录内的纯文件名`, { file: block.file });
    }
    if (typeof block.keyId !== 'string' || !KEY_ID_PATTERN.test(block.keyId)) {
      fail(`块 ${index} 的 key ID 格式不正确`, { keyId: block.keyId });
    }
    if (block.alg !== 'A256GCM') {
      throw new IntakeError('ALG_UNSUPPORTED', `块 ${index} 使用不支持的算法「${block.alg}」，仅支持 A256GCM`, { position: index });
    }
    if (typeof block.iv !== 'string' || Buffer.from(block.iv, 'base64url').length !== 12) {
      fail(`块 ${index} 的 iv 必须是 12 字节`);
    }
    if (typeof block.tag !== 'string' || Buffer.from(block.tag, 'base64url').length !== 16) {
      fail(`块 ${index} 的认证标签必须是 16 字节`);
    }
    if (typeof block.sha256 !== 'string' || !HEX64.test(block.sha256)) fail(`块 ${index} 的 sha256 格式不正确`);
    if (typeof block.aad !== 'string' || block.aad.length === 0) fail(`块 ${index} 缺少附加认证数据`);
  }
}

// 接纳边界：解密与资料登记构成可恢复的会话，按 (exportId, version) 隔离。
// 暂存明文逐块落盘（0600），全部块认证通过且整体摘要相符后才写入归档；
// 读者因此只能看到完整接纳的资料，部分明文永远不会发布。
export class Intake {
  constructor({ root, archive, keys, now = () => new Date() }) {
    this.root = resolve(root);
    this.archive = archive;
    this.keys = keys;
    this.now = now;
  }

  sessionDirectory(exportId, version) {
    return join(this.root, 'sessions', exportId, `v${version}`);
  }

  async readSession(sessionPath) {
    try {
      return JSON.parse(await readFile(sessionPath, 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  async writeSession(sessionPath, session) {
    session.updatedAt = this.now().toISOString();
    await writeAtomic(sessionPath, JSON.stringify(session, null, 2));
  }

  async journal(entry) {
    await mkdir(this.root, { recursive: true });
    // 日志只记录元数据（事件、位置、key ID、失败分类），绝不写入明文或钥匙材料
    const line = JSON.stringify({ at: this.now().toISOString(), ...entry });
    await appendFile(join(this.root, 'journal.log'), `${line}\n`, { mode: 0o600 });
  }

  async run(manifestPath, { chunkDirectory } = {}) {
    const source = resolve(manifestPath);
    let inspection;
    try {
      inspection = await inspect(source); // 先验证清单来源签名
    } catch (error) {
      throw new IntakeError('MANIFEST_SIGNATURE_INVALID', `清单来源验证失败：${error.message}`, {}, { cause: error });
    }
    const { manifest, manifestSha256 } = inspection;
    validateManifest(manifest);
    const { exportId, version } = manifest;
    const chunks = chunkDirectory ? resolve(chunkDirectory) : dirname(source);

    const sessionDir = this.sessionDirectory(exportId, version);
    const stagingDir = join(sessionDir, 'staging');
    await mkdir(stagingDir, { recursive: true, mode: 0o700 });
    const sessionPath = join(sessionDir, 'session.json');

    let session = await this.readSession(sessionPath);
    const resumed = session !== null;
    if (session) {
      if (session.manifestSha256 !== manifestSha256) {
        // 同一 exportId+version 出现了内容不同的清单：拒绝合并，避免把不同批次的块凑成一份
        const error = new IntakeError('SESSION_MANIFEST_MISMATCH',
          `已存在 ${exportId} v${version} 的进行中会话，但新清单内容不一致；为避免拼凑不同批次的块，已拒绝合并。请人工核对后执行 prune 再重试`,
          { exportId, version });
        await this.journal({ event: 'intake-rejected', exportId, version, code: error.code, category: error.category });
        throw error;
      }
      if (session.status === 'accepted') {
        await rm(stagingDir, { recursive: true, force: true }); // 上次若在清理前中断，这里补齐保留策略
        return { receipt: session.receipt, session, resumed, alreadyAccepted: true };
      }
      session.status = 'in-progress';
    } else {
      session = {
        exportId, version, manifestSha256,
        cleartextSha256: manifest.cleartextSha256,
        status: 'in-progress',
        blocks: manifest.blocks.map(block => ({
          position: block.position, file: block.file, keyId: block.keyId,
          sha256: block.sha256, status: 'pending', plaintextSha256: null,
        })),
        lastFailure: null,
        receipt: null,
        createdAt: this.now().toISOString(),
        updatedAt: this.now().toISOString(),
      };
    }
    await this.writeSession(sessionPath, session);
    await this.journal({ event: 'intake-started', exportId, version, resumed });

    for (const block of manifest.blocks) {
      const state = session.blocks[block.position];
      if (state.status === 'verified') {
        // 续传时先核对暂存明文仍完好，损坏则重新解密，绝不信任未核验的暂存内容
        const stagedPath = join(stagingDir, `${block.position}.bin`);
        const intact = await readFile(stagedPath)
          .then(bytes => digest(bytes) === state.plaintextSha256)
          .catch(() => false);
        if (intact) continue;
        state.status = 'pending';
        state.plaintextSha256 = null;
      }
      try {
        const plaintext = await this.decryptBlock(manifest, block, chunks);
        await writeAtomic(join(stagingDir, `${block.position}.bin`), plaintext);
        state.status = 'verified';
        state.plaintextSha256 = digest(plaintext);
        session.lastFailure = null;
        await this.writeSession(sessionPath, session);
        await this.journal({ event: 'block-verified', exportId, version, position: block.position, keyId: block.keyId });
      } catch (error) {
        const intakeError = error instanceof IntakeError ? error
          : new IntakeError('INTERNAL', error.message, {}, { cause: error });
        session.status = 'failed';
        session.lastFailure = {
          at: this.now().toISOString(),
          position: block.position,
          keyId: block.keyId,
          code: intakeError.code,
          category: intakeError.category,
          message: intakeError.message,
        };
        await this.writeSession(sessionPath, session);
        await this.journal({ event: 'block-failed', exportId, version, ...session.lastFailure });
        throw intakeError;
      }
    }

    // 全部块认证完成后才组装；整体明文摘要不符时绝不发布
    const parts = [];
    for (const block of manifest.blocks) {
      parts.push(await readFile(join(stagingDir, `${block.position}.bin`)));
    }
    const cleartext = Buffer.concat(parts);
    if (digest(cleartext) !== manifest.cleartextSha256) {
      const error = new IntakeError('CLEARTEXT_DIGEST_MISMATCH',
        `导出 ${exportId} v${version} 组装后的明文摘要与清单不符，未发布任何内容`, { exportId, version });
      session.status = 'failed';
      session.lastFailure = { at: this.now().toISOString(), position: null, keyId: null,
        code: error.code, category: error.category, message: error.message };
      await this.writeSession(sessionPath, session);
      await this.journal({ event: 'intake-failed', exportId, version, code: error.code, category: error.category });
      throw error;
    }

    const receipt = await this.archive.accept(cleartext, {
      source, exportId, version, manifestSha256,
      keyIds: [...new Set(manifest.blocks.map(block => block.keyId))],
    });
    session.status = 'accepted';
    session.receipt = { id: receipt.id, sha256: receipt.sha256 };
    session.lastFailure = null;
    await this.writeSession(sessionPath, session);
    await rm(stagingDir, { recursive: true, force: true }); // 临时明文随接纳立即清除
    await this.journal({ event: 'intake-accepted', exportId, version, receipt: receipt.id });
    return { receipt, session, resumed, alreadyAccepted: false };
  }

  async decryptBlock(manifest, block, chunkDirectory) {
    let ciphertext;
    try {
      ciphertext = await readFile(join(chunkDirectory, block.file));
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new IntakeError('BLOCK_MISSING',
          `缺少块文件 ${block.file}（位置 ${block.position}），导出 ${manifest.exportId} v${manifest.version} 不完整`,
          { position: block.position, file: block.file });
      }
      throw error;
    }
    if (digest(ciphertext) !== block.sha256) {
      throw new IntakeError('BLOCK_DIGEST_MISMATCH',
        `块 ${block.position}（${block.file}）的密文摘要与清单不符，可能已损坏或与其他块调换`,
        { position: block.position, file: block.file });
    }
    const aadBytes = Buffer.from(block.aad, 'base64url');
    let aad;
    try {
      aad = JSON.parse(aadBytes.toString('utf8'));
    } catch {
      throw new IntakeError('AAD_MISMATCH', `块 ${block.position} 的附加认证数据无法解析`, { position: block.position });
    }
    if (aad?.exportId !== manifest.exportId || aad?.version !== manifest.version || aad?.position !== block.position) {
      throw new IntakeError('AAD_MISMATCH',
        `块 ${block.position} 的附加认证数据指向 ${aad?.exportId} v${aad?.version} 位置 ${aad?.position}，不属于当前导出的该位置`,
        { position: block.position, aad });
    }
    const key = await this.keys.load(block.keyId); // 只领取清单声明的 key ID
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(block.iv, 'base64url'));
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(Buffer.from(block.tag, 'base64url'));
    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new IntakeError('BLOCK_AUTH_FAILED',
        `块 ${block.position} 用 key ID「${block.keyId}」认证失败（GCM 标签不符）；不会尝试其他钥匙`,
        { position: block.position, keyId: block.keyId });
    }
  }

  async status() {
    const sessionsRoot = join(this.root, 'sessions');
    const sessions = [];
    let exportDirs;
    try {
      exportDirs = await readdir(sessionsRoot, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return { sessions };
      throw error;
    }
    for (const exportDir of exportDirs.filter(entry => entry.isDirectory())) {
      for (const versionDir of await readdir(join(sessionsRoot, exportDir.name))) {
        const session = await this.readSession(join(sessionsRoot, exportDir.name, versionDir, 'session.json'));
        if (!session) continue;
        sessions.push({
          exportId: session.exportId,
          version: session.version,
          status: session.status,
          verifiedBlocks: session.blocks.filter(block => block.status === 'verified').length,
          totalBlocks: session.blocks.length,
          lastFailure: session.lastFailure,
          receipt: session.receipt,
          updatedAt: session.updatedAt,
        });
      }
    }
    sessions.sort((a, b) => a.exportId.localeCompare(b.exportId) || a.version - b.version);
    return { sessions };
  }

  // 保留策略：清理过期的失败残留（含暂存明文），截断日志；已接纳会话保留回执审计
  async prune({ olderThanMs = 24 * 60 * 60 * 1000 } = {}) {
    const cutoff = this.now().getTime() - olderThanMs;
    const removedSessions = [];
    const sessionsRoot = join(this.root, 'sessions');
    let exportDirs = [];
    try {
      exportDirs = await readdir(sessionsRoot, { withFileTypes: true });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    for (const exportDir of exportDirs.filter(entry => entry.isDirectory())) {
      const exportPath = join(sessionsRoot, exportDir.name);
      for (const versionDir of await readdir(exportPath)) {
        const sessionPath = join(exportPath, versionDir, 'session.json');
        const session = await this.readSession(sessionPath);
        if (session && session.status !== 'accepted' && Date.parse(session.updatedAt) <= cutoff) {
          await rm(join(exportPath, versionDir), { recursive: true, force: true });
          removedSessions.push(`${session.exportId}/v${session.version}`);
        }
      }
      if ((await readdir(exportPath)).length === 0) {
        await rm(exportPath, { recursive: true, force: true });
      }
    }
    const journalPath = join(this.root, 'journal.log');
    let journalEntriesKept = 0;
    try {
      const lines = (await readFile(journalPath, 'utf8')).split('\n').filter(Boolean);
      const kept = lines.filter(line => {
        try { return Date.parse(JSON.parse(line).at) > cutoff; } catch { return false; }
      }).slice(-1000);
      journalEntriesKept = kept.length;
      await writeAtomic(journalPath, kept.length ? `${kept.join('\n')}\n` : '');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const result = { removedSessions, journalEntriesKept };
    await this.journal({ event: 'pruned', ...result });
    return result;
  }
}
