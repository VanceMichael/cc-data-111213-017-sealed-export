// 维护者重建合成资料：全部为合成数据与本地密钥，不接触真实客户资料。
// 从仓库根目录运行：npm run fixtures
import { rm } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildExport, generateKey } from '../src/synthetic.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
await rm(root, { recursive: true, force: true });

// 轮换场景：块 0 仍由旧 key ID lab-2026 加密，块 1、2 已轮换到 lab-2027；
// 两个 key ID 在受控目录中共存，接纳时按每块登记的 ID 精确领取。
const oldKey = generateKey('lab-2026');
const newKey = generateKey('lab-2027');
await buildExport(root, {
  exportId: 'export-A',
  version: 1,
  records: ['探头,温度\n', 'P1,3.1\n', 'P2,4.2\n'],
  keyByPosition: position => (position === 0 ? oldKey : newKey),
});

console.log(`合成资料已重建于 ${join(root)}（轮换：块0=lab-2026，块1-2=lab-2027）`);
