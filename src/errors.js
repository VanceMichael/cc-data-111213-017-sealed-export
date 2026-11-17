/**
 * 接纳边界上的失败必须可以区分。每种失败只对应一个错误码，调用方据此判断
 * “是授权问题还是完整性问题”，不得把缺密钥、认证失败、缺块、摘要失败混成一个异常。
 */
export const ERROR_CODES = Object.freeze({
  MANIFEST_SIGNATURE: 'MANIFEST_SIGNATURE_INVALID',
  SIGNING_KEY_UNAVAILABLE: 'SIGNING_KEY_UNAVAILABLE',
  MANIFEST_SHAPE: 'MANIFEST_STRUCTURE_INVALID',
  BLOCK_REFERENCE: 'BLOCK_REFERENCE_INVALID',
  KEY_MISSING: 'KEY_MISSING',
  KEY_UNUSABLE: 'KEY_UNUSABLE',
  CIPHERTEXT_DIGEST: 'CIPHERTEXT_DIGEST_MISMATCH',
  AUTH_FAILED: 'BLOCK_AUTH_FAILED',
  BLOCK_MISSING: 'BLOCK_MISSING',
  BLOCK_TOO_LARGE: 'BLOCK_TOO_LARGE',
  CLEARTEXT_DIGEST: 'CLEARTEXT_DIGEST_MISMATCH',
  RESUME_MISMATCH: 'RESUME_STATE_MISMATCH',
  JOURNAL_CORRUPT: 'JOURNAL_CORRUPT',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  INTERNAL: 'INTERNAL_ERROR'
});

/**
 * 运维只需要先分清三类：拿不到授权、资料完整性有问题、接纳状态本身损坏。
 * 缺密钥与认证失败必须落在不同类别里，不能都报成“文件损坏”。
 */
const AUTHORIZATION_CODES = new Set([
  ERROR_CODES.KEY_MISSING,
  ERROR_CODES.KEY_UNUSABLE,
  ERROR_CODES.SIGNING_KEY_UNAVAILABLE
]);
const STATE_CODES = new Set([
  ERROR_CODES.RESUME_MISMATCH,
  ERROR_CODES.JOURNAL_CORRUPT
]);

export function classifyError(code) {
  if (AUTHORIZATION_CODES.has(code)) return 'authorization';
  if (STATE_CODES.has(code)) return 'state';
  return 'integrity';
}

export class SealedError extends Error {
  /**
   * @param {keyof ERROR_CODES} code
   * @param {string} message 面向运维的说明，不含明文
   * @param {{exportId?: string, version?: number, position?: number, keyId?: string, detail?: string}} [context]
   */
  constructor(code, message, context = {}) {
    super(message);
    this.name = 'SealedError';
    this.code = ERROR_CODES[code] ?? code;
    this.exportId = context.exportId;
    this.version = context.version;
    this.position = context.position;
    this.keyId = context.keyId;
    this.detail = context.detail;
  }

  toJSON() {
    const out = { code: this.code, category: classifyError(this.code), message: this.message };
    for (const field of ['exportId', 'version', 'position', 'keyId', 'detail']) {
      if (this[field] !== undefined) out[field] = this[field];
    }
    return out;
  }
}
