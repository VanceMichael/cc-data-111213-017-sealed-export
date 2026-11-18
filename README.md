# 授权加密导出资料的轮换密钥接收

sealed-export 用于合作资料的本地查看、来源保存与**授权解密入库**。当前版本支持人工触发的整份资料查看、字节级归档，以及基于本地受控密钥目录的分块加密包（AES-256-GCM）接纳：先验证清单来源，再按每块登记的 key ID 精确领取密钥、用附加认证数据（AAD）核对块归属，全部块通过认证并核对摘要后才登记入库。全部样例使用合成数据与合成密钥，不接触任何真实客户资料。

## 运行环境

使用 Node.js 22，零第三方依赖。依赖已锁定；首次准备执行 `npm ci --ignore-scripts`，正式运行无需下载资料或软件。

```bash
npm run check
npm test
npm run demo
```

`npm run demo` 在临时目录中用合成密钥演示完整接纳与全部故障分类，退出时清理临时内容，正常应在九十秒内结束。

## 资料操作

```bash
# 既有：查看已签名清单、保存来源字节、列出回执
npm start -- inspect fixtures/manifest.json
npm start -- capture fixtures/manifest.json .local/archive
npm start -- list .local/archive

# 新增：受控密钥目录中的授权 key ID（只列标识，不返回密钥材料）
npm start -- keys fixtures/keys

# 新增：授权领取 + 解密入库；--max-blocks 用于暂停后继续
npm start -- ingest fixtures/manifest.json .local/archive \
  --key-dir fixtures/keys --intake-dir .local/intake --max-blocks 2
npm start -- ingest fixtures/manifest.json .local/archive \
  --key-dir fixtures/keys --intake-dir .local/intake
npm start -- status .local/intake   # 查看接纳进度与失败分类
npm start -- sweep .local/intake    # 执行保留策略，清理过期隔离残留与日志
```

`capture` 只表示来源字节已保存；`ingest` 才是经过来源验证、授权领取与逐块认证的资料接纳。读者只能从归档中读到**完整接纳**的资料，任何失败都不会发布部分明文。

## 接纳安全模型

1. **来源验证在前**：清单是 Ed25519 签名信封，签名通过后才解析结构；结构校验还会核对每个块的 AAD 确实绑定到该 `exportId`、`version` 和 `position`。
2. **按 key ID 精确领取**：密钥来自本地受控目录（每个文件一份 `{ id, alg, key }` 授权）。引擎只按清单登记的 key ID 读取对应授权文件，**不提供、也不存在遍历全部密钥试解**的路径；每次领取都有只含 key ID 与命中结果的审计记录。
3. **逐块认证**：AES-256-GCM 以清单登记的 AAD 解密，证明该块属于这份导出的这个位置；顺序调换会先被块摘要拦截，即使摘要被改写，AAD 中的位置绑定也会令 GCM 认证失败。
4. **全文核对后发布**：按块顺序拼装，核对 `cleartextSha256` 后才写入内容对象与回执，成功即清空暂存明文。

故障分类彼此独立，运维看到的是授权或完整性问题，而不是笼统的“文件损坏”：

| 错误码 | 含义 |
| --- | --- |
| `MANIFEST_SIGNATURE_INVALID` | 清单签名无效，来源不可信，解密前即拒绝 |
| `MANIFEST_INVALID` | 清单结构/AAD 绑定不合法 |
| `MISSING_KEY` | 受控目录缺少清单指定的 key ID（授权问题，不是损坏） |
| `AUTH_FAILED` | GCM 认证标签失败，密钥与加密内容不匹配 |
| `MISSING_BLOCK` | 清单登记的块文件缺失 |
| `DIGEST_MISMATCH` | 块密文或拼装全文的摘要与清单不一致（损坏/调换） |
| `INTAKE_CONFLICT` | 接纳目录已绑定另一份导出，禁止混合不同版本 |
| `INTAKE_STATE` | 本地接纳状态损坏，需要运维介入 |

## 可恢复的接纳边界与保留策略

每个接纳目录保存独立的原子状态（`state.json`）、暂存区（`staging/`）、隔离区（`quarantine/`）与审计日志（`journal.jsonl`）：

- **暂停后继续**：`--max-blocks` 限制单次处理块数；续跑时重新核对暂存块摘要，被篡改的暂存块自动回到待处理并重新解密。
- **不混版本**：接纳目录按 `exportId + version` 绑定；不同身份的清单直接报 `INTAKE_CONFLICT`。同一身份重新下发的修复清单允许续跑，并重置暂存块按新清单重新核验。
- **失败不留明文**：任何失败都会清空暂存区、把触发问题的**密文残料**（绝不明文）与分类错误信息移入隔离区；缺块等无残料场景不建隔离目录。
- **保留策略**：隔离区默认 24 小时 TTL，审计日志默认最多 500 条且只留 7 天；每次接纳开头与手动 `sweep` 都会执行清理，可在构造 `Intake` 时覆盖。

## 演示场景（npm run demo）

全部在临时目录中用合成数据完成，退出即清理：

1. 新旧 key ID 共存的密钥轮换 + 暂停后继续，读者只看到完整接纳的资料；
2. 缺密钥报 `MISSING_KEY`，补齐授权后同一份导出恢复完成；
3. 错误钥匙重加密报 `AUTH_FAILED`，不产出明文；
4. 中间块损坏报 `DIGEST_MISMATCH`，重新下发完好导出后续跑完成；
5. 块顺序调换被块摘要与 AAD 位置绑定双重拦截；
6. 缺块报 `MISSING_BLOCK`；
7. 不同版本混入同一接纳目录报 `INTAKE_CONFLICT`；
8. 隔离区 TTL 与日志条数保留策略；
9. 篡改清单签名在任何解密动作之前被拒绝。

## 目录约定

- `src/domain.js`：清单来源验证、结构与 AAD 绑定校验。
- `src/keystore.js`：本地受控密钥目录，按 key ID 精确领取与领取审计。
- `src/intake.js`：可恢复的解密入库引擎、暂存/隔离/日志与保留策略。
- `src/archive.js`：内容对象、来源回执与完整性检查。
- `src/errors.js`：分类错误码（详情字段不含密钥材料或明文）。
- `src/synthetic.js`：合成导出包构建器与故障场景构造（仅测试/演示使用）。
- `src/demo.js`：端到端演示编排。
- `scripts/create-fixtures.js`：维护者重建合成资料（含轮换：块 0 用 `lab-2026`，块 1、2 用 `lab-2027`）。
- `fixtures/`：本地合成资料、签名公钥与受控密钥目录。
- `test/`：行为验证，使用独立临时目录。

## Linux 环境

`Dockerfile` 使用 Node.js 22 镜像。可执行 `docker build -t sealed-export:local .` 后运行 `docker run --rm --network none sealed-export:local npm test`。测试与演示只使用本地临时目录，不需要网络或第二个容器。构建阶段准备依赖，运行时不安装依赖。
