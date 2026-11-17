# 授权加密导出资料的轮换密钥接收

sealed-export 用于合作资料的本地查看和来源保存。当前版本支持人工触发的整份资料查看与字节级归档，资料对象按内容摘要保存，每次领取保留单独回执。自动组织领域资料的能力与人工查看入口分别演进。

本版本新增**分块加密包的授权领取与解密入库**：先验证签名清单来源，再按每块声明的 keyId 从本地受控目录领取密钥，用 AES-256-GCM 逐块认证，全部块通过后才登记为一份完整资料。

## 运行环境

使用 Node.js 22。依赖已锁定；首次准备执行 `npm ci --ignore-scripts`，正式运行无需下载资料或软件。全部样例使用合成数据与本机来源，不连接生产系统。

```bash
npm run check
npm test
npm run demo
```

`npm run demo` 只用临时目录内的合成密钥与合成资料，演示轮换、中间块损坏、顺序调换、暂停后继续与缺钥恢复，退出时清理临时内容。正常演示应在九十秒内结束。

## 资料操作

```bash
# 只看清单绑定信息（验签，不解密）
npm start -- inspect fixtures/manifest.json --public-key=fixtures/signing-public.txt

# 授权领取 + 解密入库；--max-blocks=N 可在认证 N 块后暂停
npm start -- accept fixtures/manifest.json \
  --keys=.local/keys --state=.local/intake --public-key=fixtures/signing-public.txt

# 继续最近一次同版本未完成/缺钥阻塞的接纳
npm start -- resume fixtures/manifest.json --keys=.local/keys --state=.local/intake \
  --public-key=fixtures/signing-public.txt

# 运维视图：每份接纳的阶段、卡点与错误码
npm start -- intakes --state=.local/intake

# 按保留策略清理已终结接纳的暂存、日志与记录
npm start -- prune --state=.local/intake --retain-days=30
```

`capture` 只表示来源字节已保存，不声称领域流程已自动完成；`accept` 才是完整的接纳边界：验签 → 结构/AAD 归属校验 → 逐块摘要与 GCM 认证 → 整体明文摘要 → 写入对象与回执。已有查看功能只展示现有资料，不替代业务接纳判断。`scripts/create-fixtures.js` 用于维护者重建合成资料；运行与测试直接读取已提交的资料。

## 受控密钥目录

密钥按 keyId 存放为 `<keyId>.json`：`{ "id": "<keyId>", "key": "<base64url 32 字节>" }`，目录权限应为 `0700`，文件 `0600`。新旧 keyId 可以共存；解密只取清单中该块声明的 keyId，**不会遍历目录试解**。keyId 必须匹配 `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`，防止被清单字段用作路径。

## 错误分类

失败会被分开报告，业务方不会再看到笼统的“文件损坏”：

| 类别 | 错误码 | 含义 | 暂存处理 |
| --- | --- | --- | --- |
| authorization | `KEY_MISSING` | 受控目录没有该 keyId，补钥后继续 | 保留（密文暂存） |
| authorization | `KEY_UNUSABLE` | 密钥文件损坏、长度或标识不符 | 失败（清理） |
| authorization | `SIGNING_KEY_UNAVAILABLE` | 缺少验签公钥 | 未开始 |
| integrity | `MANIFEST_SIGNATURE_INVALID` | 清单签名无效，不信任任何字段 | 未开始 |
| integrity | `BLOCK_AUTH_FAILED` | GCM 认证失败：密钥/AAD/密文不匹配 | 失败（清理） |
| integrity | `CIPHERTEXT_DIGEST_MISMATCH` | 块密文与清单摘要不符 | 失败（清理） |
| integrity | `BLOCK_MISSING` | 缺块 | 失败（清理） |
| integrity | `CLEARTEXT_DIGEST_MISMATCH` | 每块已认证，但整体明文摘要不符 | 失败（清理） |
| state | `RESUME_STATE_MISMATCH` | 重试的版本/摘要与记录不符 | 不动原记录 |

`accept` 失败时进程退出码为 2，并输出结构化 JSON（加 `--json` 时始终输出）。

## 接纳边界与恢复

- 接纳记录按 `exportId + version + 清单载荷摘要` 绑定；相同的已签名清单重试是幂等的，不会重复登记为两份资料。
- 显式指定其它版本的接纳记录继续会被 `RESUME_STATE_MISMATCH` 拒绝，不同版本的块不会被拼成一份。
- 只有通过 GCM 认证的块才会暂存，且暂存内容用状态目录内的本地状态密钥二次加密；暂停、崩溃和缺钥阻塞都不会留下明文。
- AAD 绑定 `exportId/version/position`：清单里块的数组顺序无关紧要，但块若实际来自另一份导出或另一位置，会在解密时认证失败。
- 只有全部块认证且整体明文摘要匹配，才写入内容对象与回执；**失败绝不发布部分明文**。
- 保留策略：`prune` 删除超过保留天数的已终结记录（published/failed/blocked）及其暂存与日志；进行中的接纳不受影响。

## 目录约定

- `src/domain.js`：现有领域读取和查看接口。
- `src/manifest.js`：签名清单验签、结构校验与 AAD 归属校验。
- `src/keystore.js`：受控密钥目录，按 keyId 领取。
- `src/sealed.js`：AES-256-GCM 块解密与错误区分。
- `src/intake.js`：可恢复的接纳边界、加密暂存、版本绑定与保留策略。
- `src/synthetic.js`：仅演示/测试用的合成密钥与资料生成器。
- `src/archive.js`：内容对象、来源回执与完整性检查。
- `fixtures/`：本地资料与领域配置。
- `test/`：已有行为的运行验证，使用独立临时目录。

## Linux 环境

`Dockerfile` 使用 Node.js 22 镜像；浏览器项目使用包含 Chromium 的运行镜像。可执行 `docker build -t sealed-export:local .` 后运行 `docker run --rm --network none sealed-export:local npm test`。测试中的 HTTP、MQTT 和门户都仅绑定回环地址；不需要第二个容器。构建阶段准备依赖，运行时不安装依赖。
