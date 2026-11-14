import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Archive } from './archive.js';
import { inspect } from './domain.js';
import { Intake, KeyDirectory } from './intake.js';
import { runDemo } from './demo.js';

const [command = 'help', ...rest] = process.argv.slice(2);
const positional = [];
const flags = {};
for (let index = 0; index < rest.length; index++) {
  if (rest[index].startsWith('--')) flags[rest[index].slice(2)] = rest[++index];
  else positional.push(rest[index]);
}
const archiveDirectory = flags.archive ?? '.local/archive';
const intakeRoot = flags.intake ?? '.local/intake';
const keysDirectory = flags.keys ?? 'fixtures/keys';

function makeIntake() {
  return new Intake({ root: intakeRoot, archive: new Archive(archiveDirectory), keys: new KeyDirectory(keysDirectory) });
}

async function run() {
  if (command === 'help') {
    console.log(JSON.stringify({ usage: 'npm start -- <命令> [参数] [--keys 目录] [--intake 目录] [--archive 目录]',
      commands: ['inspect', 'capture', 'intake', 'status', 'prune', 'list', 'demo'] }, null, 2));
  } else if (command === 'inspect') {
    if (!positional[0]) throw new Error('需要资料路径');
    console.log(JSON.stringify(await inspect(resolve(positional[0])), null, 2));
  } else if (command === 'capture') {
    if (!positional[0]) throw new Error('需要资料路径');
    const inventory = await inspect(resolve(positional[0]));
    const receipt = await new Archive(positional[1] ?? archiveDirectory).accept(await readFile(positional[0]),
      { source: resolve(positional[0]), inventory });
    console.log(JSON.stringify(receipt, null, 2));
  } else if (command === 'intake') {
    if (!positional[0]) throw new Error('需要清单路径');
    const result = await makeIntake().run(resolve(positional[0]),
      { chunkDirectory: flags.chunks ? resolve(flags.chunks) : undefined });
    console.log(JSON.stringify({ receipt: result.receipt, resumed: result.resumed,
      alreadyAccepted: result.alreadyAccepted }, null, 2));
  } else if (command === 'status') {
    console.log(JSON.stringify(await makeIntake().status(), null, 2));
  } else if (command === 'prune') {
    const olderThanMs = flags['older-than-ms'] === undefined ? undefined : Number(flags['older-than-ms']);
    console.log(JSON.stringify(await makeIntake().prune({ olderThanMs }), null, 2));
  } else if (command === 'list') {
    console.log(JSON.stringify(await new Archive(positional[0] ?? archiveDirectory).receipts(), null, 2));
  } else if (command === 'demo') {
    console.log(JSON.stringify(await runDemo(), null, 2));
  } else { throw new Error('支持 inspect、capture、intake、status、prune、list、demo'); }
}
run().catch(error => {
  const report = { message: error.message };
  if (error.code) { report.code = error.code; report.category = error.category; }
  console.error(JSON.stringify(report, null, 2));
  process.exitCode = 1;
});
