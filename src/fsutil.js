import { open, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

/** 同目录临时文件 + fsync + rename，避免读者看到半份状态。 */
export async function writeAtomic(path, bytes, mode = 0o600) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const handle = await open(temporary, 'wx', mode);
  try { await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
  try { await rename(temporary, path); }
  finally { await rm(temporary, { force: true }); }
}
