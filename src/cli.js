import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Archive } from './archive.js';
import { inspect, sample } from './domain.js';
import { KeyStore } from './keystore.js';
import { Intake } from './intake.js';
import { IntakeError } from './errors.js';
import { runDemo } from './demo.js';

const args = process.argv.slice(2);
const [command = 'help', file, directory] = args;

function flags(names) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const match = /^--([\w-]+)(?:=(.*))?$/.exec(args[i]);
    if (!match) continue;
    if (!names.has(match[1])) throw new Error(`不支持的参数 --${match[1]}`);
    if (match[2] !== undefined) {
      out[match[1]] = match[2];
    } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
      out[match[1]] = args[++i]; // 支持 --flag value 形式
    } else {
      out[match[1]] = true;
    }
  }
  return out;
}

async function run() {
  if (command === 'help') {
    console.log(JSON.stringify({
      usage: 'npm start -- <命令> [资料路径] [归档目录] [选项]',
      commands: ['inspect', 'capture', 'list', 'ingest', 'status', 'keys', 'sweep', 'demo'],
      ingestOptions: {
        '--key-dir': '本地受控密钥目录（默认 fixtures/keys）',
        '--intake-dir': '可恢复接纳状态目录（默认 .local/intake）',
        '--max-blocks': '本次最多处理的块数，用于暂停后继续（默认全部）',
      },
    }, null, 2));
  } else if (command === 'inspect') {
    if (!file) throw new Error('需要资料路径');
    console.log(JSON.stringify(await inspect(resolve(file)), null, 2));
  } else if (command === 'capture') {
    if (!file) throw new Error('需要资料路径');
    const inventory = await inspect(resolve(file));
    const receipt = await new Archive(directory || '.local/archive').accept(await readFile(file),
      { source: resolve(file), inventory });
    console.log(JSON.stringify(receipt, null, 2));
  } else if (command === 'list') {
    console.log(JSON.stringify(await new Archive(file || directory || '.local/archive').receipts(), null, 2));
  } else if (command === 'ingest') {
    if (!file) throw new Error('需要清单路径');
    const opts = flags(new Set(['key-dir', 'intake-dir', 'max-blocks']));
    const keyStore = new KeyStore(resolve(opts['key-dir'] || 'fixtures/keys'));
    const archive = new Archive(resolve(directory || '.local/archive'));
    const intake = new Intake(resolve(opts['intake-dir'] || '.local/intake'));
    const options = {};
    if (opts['max-blocks']) options.maxBlocks = Number(opts['max-blocks']);
    const result = await intake.run(resolve(file), keyStore, archive, options);
    console.log(JSON.stringify({ result, keyStoreAccess: keyStore.accessLog }, null, 2));
  } else if (command === 'status') {
    if (!file) throw new Error('需要接纳状态目录');
    console.log(JSON.stringify(await new Intake(resolve(file)).snapshot(), null, 2));
  } else if (command === 'keys') {
    if (!file) throw new Error('需要受控密钥目录');
    const keyStore = new KeyStore(resolve(file));
    console.log(JSON.stringify({ keyDirectory: keyStore.directory, keyIds: await keyStore.listKeyIds() }, null, 2));
  } else if (command === 'sweep') {
    if (!file) throw new Error('需要接纳状态目录');
    console.log(JSON.stringify(await new Intake(resolve(file)).sweep(), null, 2));
  } else if (command === 'demo') {
    await runDemo();
  } else {
    throw new Error('支持 inspect、capture、list、ingest、status、keys、sweep、demo');
  }
}

run().catch(error => {
  if (error instanceof IntakeError) {
    // 运维入口：分类错误码与安全详情输出到 stderr，退出码 1
    console.error(JSON.stringify(error.toJSON(), null, 2));
  } else {
    console.error(error.message);
  }
  process.exitCode = 1;
});
