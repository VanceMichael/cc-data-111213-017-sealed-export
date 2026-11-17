import { mkdir, open, readFile, rename, readdir, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { writeAtomic } from './fsutil.js';

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export class Archive {
  constructor(directory) { this.directory = resolve(directory); }

  async initialize() {
    await mkdir(join(this.directory, 'objects'), { recursive: true });
    await mkdir(join(this.directory, 'receipts'), { recursive: true });
  }

  /** 兼容既有调用；writeAtomic 保留同目录临时文件与 fsync。 */
  async writeAtomic(path, bytes) { return writeAtomic(path, bytes); }

  /**
   * @param {Buffer} bytes 已认证的完整资料
   * @param {object} metadata 来源与清单绑定信息
   * @param {{id?: string}} [options] 允许接纳流程预先生成回执 ID，便于崩溃后识别已提交
   */
  async accept(bytes, metadata, { id } = {}) {
    await this.initialize();
    const sha256 = digest(bytes);
    await this.writeAtomic(join(this.directory, 'objects', sha256), bytes);
    const receipt = { id: id ?? randomUUID(), sha256, size: bytes.length,
      observedAt: new Date().toISOString(), metadata };
    await this.writeAtomic(join(this.directory, 'receipts', `${receipt.id}.json`),
      JSON.stringify(receipt, null, 2));
    return receipt;
  }

  async receipts() {
    await this.initialize();
    const files = (await readdir(join(this.directory, 'receipts')))
      .filter(name => name.endsWith('.json')).sort();
    return Promise.all(files.map(name => readFile(join(this.directory, 'receipts', name), 'utf8').then(JSON.parse)));
  }

  async receipt(id) {
    if (typeof id !== 'string' || !/^[A-Za-z0-9-]{8,64}$/.test(id)) throw new Error('回执标识格式不正确');
    try { return JSON.parse(await readFile(join(this.directory, 'receipts', `${id}.json`), 'utf8')); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  }

  async read(sha256) {
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error('对象摘要格式不正确');
    const bytes = await readFile(join(this.directory, 'objects', sha256));
    if (digest(bytes) !== sha256) throw new Error('对象完整性校验失败');
    return bytes;
  }
}
