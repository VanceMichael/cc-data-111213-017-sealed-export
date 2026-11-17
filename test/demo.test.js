import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runRotationDemo } from '../src/demo.js';

test('合成演示覆盖轮换、损坏、调序、暂停继续且只发布完整资料', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'demo-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const summary = await runRotationDemo({ root, json: true });
  assert.equal(summary.mode, 'synthetic-only');
  assert.equal(summary.plaintextResidue, false);
  assert.equal(summary.onlyCompleteExportsVisible, true);

  const byTitle = (needle) => summary.failures.find(item => item.title.includes(needle));
  assert.equal(byTitle('中间块损坏').category, 'integrity');
  assert.ok(['CIPHERTEXT_DIGEST_MISMATCH', 'BLOCK_AUTH_FAILED']
    .includes(byTitle('中间块损坏').code));
  assert.equal(byTitle('AAD 指向位置0').code, 'BLOCK_AUTH_FAILED');
  assert.equal(byTitle('export-A 的记录继续 export-E').code, 'RESUME_STATE_MISMATCH');
  assert.equal(byTitle('缺少 lab-2028').category, 'authorization');
  assert.equal(byTitle('缺少 lab-2028').code, 'KEY_MISSING');
  assert.equal(byTitle('缺少 lab-2028').stagedRetained, true);
  assert.equal(byTitle('整体明文摘要不一致').code, 'CLEARTEXT_DIGEST_MISMATCH');

  const publishedTitles = summary.published.map(item => item.title);
  assert.ok(publishedTitles.some(title => title.includes('轮换前 v1')));
  assert.ok(publishedTitles.some(title => title.includes('轮换中 v2')));
  assert.ok(publishedTitles.some(title => title.includes('清单块倒序')));
  assert.ok(publishedTitles.some(title => title.includes('从第 3 块继续')));
  assert.ok(publishedTitles.some(title => title.includes('补上 lab-2028 后继续')));
});
