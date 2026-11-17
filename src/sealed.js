import { createDecipheriv } from 'node:crypto';
import { ERROR_CODES, SealedError } from './errors.js';
import { digest } from './manifest.js';

const MAX_BLOCK_BYTES = 64 * 1024 * 1024;

/** 尽力清零不再需要的明文缓冲区；这不是防取证承诺，只是缩短保留时间。 */
export function wipe(...buffers) {
  for (const buffer of buffers) {
    if (Buffer.isBuffer(buffer)) buffer.fill(0);
  }
}

/**
 * 单块解密：先把密文摘要与清单比对（无钥完整性），再用清单声明的 keyId 取密钥，
 * 最后以“导出/版本/位置”作为附加认证数据做 AES-256-GCM 认证。
 * 三种失败分别映射到 CIPHERTEXT_DIGEST / KEY_MISSING / AUTH_FAILED，绝不互相冒充。
 */
export function decryptBlock(block, ciphertext, key, context) {
  if (ciphertext.length > MAX_BLOCK_BYTES) {
    throw new SealedError(ERROR_CODES.BLOCK_TOO_LARGE, '块密文超过大小上限', context);
  }
  const actual = digest(ciphertext);
  if (actual !== block.sha256) {
    throw new SealedError(ERROR_CODES.CIPHERTEXT_DIGEST,
      '块密文摘要与清单不一致', { ...context, detail: `期望 ${block.sha256}，实际 ${actual}` });
  }
  if (!key || key.length !== 32) {
    throw new SealedError(ERROR_CODES.KEY_UNUSABLE, '解密密钥不可用', context);
  }

  let decipher;
  try {
    decipher = createDecipheriv('aes-256-gcm', key, block.iv);
    decipher.setAAD(block.aad);
    decipher.setAuthTag(block.tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    // 认证数据只在此刻被 GCM 验证；失败会抛错，不会返回任何明文。
    return plaintext;
  } catch {
    throw new SealedError(ERROR_CODES.AUTH_FAILED,
      '块认证失败：密钥、附加认证数据或密文不匹配', context);
  }
}
