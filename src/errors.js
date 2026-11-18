// 接纳流程的分类错误。details 只允许放入安全字段（标识、摘要、位置等），
// 任何情况下都不得携带密钥材料或明文片段。
export class IntakeError extends Error {
  constructor(code, message, details = {}, cause) {
    super(message);
    this.name = 'IntakeError';
    this.code = code;
    this.details = details;
    if (cause) this.cause = cause;
  }
  toJSON() {
    return { code: this.code, message: this.message, details: this.details };
  }
}

// 清单来源：签名无效（无法证明来自合作实验室）
export class ManifestSignatureError extends IntakeError {
  constructor(details = {}, cause) {
    super('MANIFEST_SIGNATURE_INVALID', '导出清单签名验证失败，来源不可信', details, cause);
  }
}

// 清单本身结构不合法（算法未知、AAD 与导出/位置不一致等）
export class ManifestInvalidError extends IntakeError {
  constructor(details = {}, cause) {
    super('MANIFEST_INVALID', '导出清单结构或附加认证数据不合法', details, cause);
  }
}

// 授权：受控密钥目录中没有清单指定的 key ID
export class MissingKeyError extends IntakeError {
  constructor(details = {}, cause) {
    const keyId = typeof details === 'string' ? details : details.keyId;
    super('MISSING_KEY', `缺少密钥授权：${keyId}`, typeof details === 'string' ? { keyId } : details, cause);
  }
}

// 完整性：清单登记的块文件在资料目录中不存在
export class MissingBlockError extends IntakeError {
  constructor(details = {}, cause) {
    super('MISSING_BLOCK', '缺少加密块文件，导出不完整', details, cause);
  }
}

// 完整性：密文摘要或拼装后全文摘要与清单不一致
export class DigestMismatchError extends IntakeError {
  constructor(details = {}, cause) {
    super('DIGEST_MISMATCH', '摘要校验失败，资料可能被篡改或调换', details, cause);
  }
}

// 认证：AES-256-GCM 认证标签校验失败（密钥不匹配或密文/AAD 被改）
export class AuthenticationError extends IntakeError {
  constructor(details = {}, cause) {
    super('AUTH_FAILED', '块认证失败，密钥与加密内容不匹配', details, cause);
  }
}

// 恢复边界：同一接纳目录被用于另一份导出（不同 exportId/版本/清单摘要）
export class IntakeConflictError extends IntakeError {
  constructor(details = {}, cause) {
    super('INTAKE_CONFLICT', '接纳目录已绑定另一份导出，禁止混合不同版本的块', details, cause);
  }
}

// 恢复边界：本地接纳状态损坏
export class IntakeStateError extends IntakeError {
  constructor(details = {}, cause) {
    super('INTAKE_STATE', '接纳状态损坏，需要运维介入', details, cause);
  }
}
