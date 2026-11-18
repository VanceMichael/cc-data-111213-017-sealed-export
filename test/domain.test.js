import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect, sample } from '../src/domain.js';

test('既有资料查看与本地来源符合领域约定', async () => {
  const result = await inspect(sample);
  assert.equal(result.signed, true);
  assert.equal(result.manifest.blocks.length, 3);
  // 轮换期间新旧 key ID 共存：块 0 仍为旧授权，块 1、2 为新授权
  assert.equal(result.manifest.blocks[0].keyId, 'lab-2026');
  assert.equal(result.manifest.blocks[1].keyId, 'lab-2027');
  assert.match(result.payloadHash, /^[a-f0-9]{64}$/);
});
