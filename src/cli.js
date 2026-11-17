import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Archive } from './archive.js';
import { inspect, sample } from './domain.js';
import { ERROR_CODES, SealedError, classifyError } from './errors.js';
import { IntakeService } from './intake.js';
import { KeyStore } from './keystore.js';
import { runRotationDemo } from './demo.js';

const args = process.argv.slice(2);
const [command = 'help', ...rest] = args;
const positional = rest.filter(value => !value.startsWith('--'));
const flags = new Map(rest.filter(value => value.startsWith('--')).map(value => {
  const [name, ...tail] = value.slice(2).split('=');
  return [name, tail.length ? tail.join('=') : true];
}));

function option(name, fallback) {
  const value = flags.get(name);
  return value === undefined || value === true ? fallback : value;
}

function service(stateDirectory, keysDirectory) {
  return new IntakeService({
    stateDirectory,
    keyStore: new KeyStore(keysDirectory),
    archive: new Archive(join(stateDirectory, 'archive')),
    signingPublicKeyPath: option('public-key', undefined),
    retentionDays: option('retain-days', undefined) === undefined
      ? undefined : Number(option('retain-days', undefined))
  });
}

function printError(error, json) {
  const payload = error instanceof SealedError
    ? { status: 'rejected', ...error.toJSON(), intakeId: error.intakeId,
      phase: error.phase, stagedRetained: error.stagedRetained }
    : { status: 'rejected', code: ERROR_CODES.INTERNAL, category: 'internal', message: error.message };
  if (json) console.log(JSON.stringify(payload, null, 2));
  else {
    const location = [payload.exportId && `导出 ${payload.exportId}`, payload.version && `v${payload.version}`,
      payload.position !== undefined && `块 ${payload.position}`, payload.keyId && `密钥 ${payload.keyId}`]
      .filter(Boolean).join('，');
    console.error(`拒绝接纳 [${payload.category}/${payload.code}] ${payload.message}${location ? `（${location}）` : ''}`);
  }
  process.exitCode = 2;
}

async function run() {
  const json = flags.has('json');
  if (command === 'help') {
    console.log(JSON.stringify({
      usage: 'npm start -- <命令> [参数] [--选项=值]',
      commands: {
        inspect: '验签并展示清单绑定信息，不解密',
        accept: '授权领取并解密入库；可 --resume=<intakeId> 继续，--max-blocks=N 分批暂停',
        resume: '继续最近一次未完成或缺少密钥的接纳',
        intakes: '列出接纳记录与卡点',
        demo: '运行合成密钥的轮换/损坏/调序/暂停演示',
        prune: '按保留策略清理已终结的暂存、日志与记录',
        capture: '原样保存资料字节（既有行为）',
        list: '列出资料回执（既有行为）'
      },
      options: ['--state=<目录>（默认 .local/intake）', '--keys=<受控密钥目录>',
        '--public-key=<验签公钥>', '--json', '--max-blocks=N', '--resume=<intakeId>', '--retain-days=N']
    }, null, 2));
    return;
  }

  if (command === 'demo') { await runRotationDemo({ json }); return; }

  if (command === 'prune') {
    const removed = await service(option('state', '.local/intake'), option('keys', '.local/keys'))
      .store.prune({ retentionDays: Number(option('retain-days', 30)) });
    console.log(JSON.stringify({ removed }, null, 2));
    return;
  }

  const stateDirectory = option('state', '.local/intake');
  const intake = service(stateDirectory, option('keys', '.local/keys'));

  if (command === 'inspect' || command === 'capture') {
    if (!positional[0]) throw new Error('需要资料路径');
    if (command === 'capture') {
      const inventory = await inspect(resolve(positional[0]));
      const receipt = await new Archive(positional[1] ?? join(stateDirectory, 'archive'))
        .accept(await readFile(positional[0]), { source: resolve(positional[0]), inventory });
      console.log(JSON.stringify(receipt, null, 2));
      return;
    }
    console.log(JSON.stringify(await intake.inspect(resolve(positional[0])), null, 2));
    return;
  }

  if (command === 'intakes') { console.log(JSON.stringify(await intake.store.listJournals(), null, 2)); return; }

  if (command === 'list') {
    console.log(JSON.stringify(await new Archive(positional[0] ?? join(stateDirectory, 'archive')).receipts(), null, 2));
    return;
  }

  if (command === 'accept' || command === 'resume') {
    if (!positional[0]) throw new Error('需要已签名清单路径');
    try {
      const result = await intake.accept({
        manifestPath: resolve(positional[0]),
        resumeIntakeId: command === 'resume' ? option('resume', undefined) : option('resume', undefined),
        maxBlocks: option('max-blocks', undefined) === undefined ? Infinity : Number(option('max-blocks', undefined))
      });
      console.log(JSON.stringify(result, null, 2));
      return;
    } catch (error) { printError(error, json); return; }
  }

  throw new Error('支持 inspect、accept、resume、intakes、prune、capture、list、demo');
}

run().catch(error => printError(error, flags.has('json')));
