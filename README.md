# 授权加密导出资料的轮换密钥接收

sealed-export 用于合作资料的本地查看和来源保存。合作实验室把导出资料做成分块加密包（AES-256-GCM），本工具在本地完成授权领取、解密与登记：先验证清单签名来源，再按清单声明的 key ID 从本地受控目录精确领取钥匙，逐块核对摘要与附加认证数据（AAD）后解密，全部块认证通过且整体明文摘要相符时才写入归档。自动组织领域资料的能力与人工查看入口分别演进。

## 运行环境

使用 Node.js 22。依赖已锁定；首次准备执行 `npm ci --ignore-scripts`，正式运行无需下载资料或软件。全部样例使用合成数据与本机来源，不连接生产系统，不接触真实客户资料。

```bash
npm run check
npm test
npm run demo
```

`npm run demo` 在临时目录用合成钥匙演示完整接纳边界：轮换期间新旧 key ID 共存、未领取到钥匙、中间块损坏后修复续传、块顺序调换、轮换窗口内暂停后继续，以及保留策略清理。退出时清理临时内容，正常演示应在九十秒内结束。

## 资料操作

```bash
npm start -- inspect fixtures/manifest.json
npm start -- intake fixtures/rotation/manifest.json            # 解密并登记入库
npm start -- intake <清单路径> --keys 受控目录 --intake .local/intake --archive .local/archive
npm start -- status                                            # 运维视角：会话进度与卡点分类
npm start -- prune --older-than-ms 86400000                    # 保留策略：清理过期失败残留与日志
npm start -- list .local/archive                               # 读者视角：只有完整接纳的资料
npm start -- capture fixtures/manifest.json .local/archive     # 既有：仅保存来源字节
```

`intake` 只表示资料已通过完整接纳边界并登记；已有查看功能只展示现有资料，不替代业务接纳判断。`scripts/create-fixtures.js` 用于维护者重建合成资料；运行与测试直接读取已提交的资料。

## 接纳边界

- 清单先验签（来源验证），再做结构校验；每块用清单中的 AAD 核对它属于哪份导出、哪个位置，GCM 解密把密文与该 AAD 密码学绑定。
- 钥匙只按清单声明的 key ID 从受控目录精确领取；新旧 key ID 可共存，但绝不遍历所有钥匙试解直到碰巧成功。
- 会话按 `(exportId, version)` 隔离，暂存明文逐块原子落盘（目录 0700、文件 0600），中断后重试从断点继续，不重复解密已认证的块；同一版本号出现内容不同的清单会被拒绝合并，避免把不同批次的块凑成一份。
- 全部块认证通过且整体明文摘要相符后才写归档；未经认证的部分明文绝不发布，读者只能看到完整接纳的资料。

## 失败分类

缺密钥、认证失败、缺块与摘要失败分开报告，运维据此判断卡在哪一种问题上，不再把“没有权限”误报成“文件损坏”：

| code | category | 含义 |
| --- | --- | --- |
| `KEY_MISSING` / `KEY_RECORD_INVALID` | `authorization` | 受控目录中没有该 key ID 的钥匙（授权领取问题） |
| `BLOCK_MISSING` | `integrity` | 缺块：块文件不存在 |
| `BLOCK_DIGEST_MISMATCH` | `integrity` | 块密文摘要与清单不符（损坏或顺序调换） |
| `AAD_MISMATCH` | `integrity` | 附加认证数据不指向当前导出与位置 |
| `BLOCK_AUTH_FAILED` | `integrity` | GCM 认证标签不符（不会尝试其他钥匙） |
| `CLEARTEXT_DIGEST_MISMATCH` | `integrity` | 组装后整体明文摘要与清单不符，未发布 |
| `SESSION_MANIFEST_MISMATCH` | `integrity` | 同版本号出现内容不同的清单，拒绝合并 |
| `MANIFEST_SIGNATURE_INVALID` / `MANIFEST_INVALID` / `ALG_UNSUPPORTED` | `manifest` | 清单来源或结构问题 |

## 保留策略

- 临时明文：接纳成功立即清除；失败时保留在会话暂存区供断点续传，由 `prune` 按 TTL 清理。
- 失败残留：非接纳状态的会话（含暂存明文）超过 TTL 后由 `prune` 删除；已接纳会话保留回执审计。
- 日志：`journal.log` 只记录事件元数据（位置、key ID、失败分类），不含明文与钥匙材料；`prune` 按 TTL 截断并封顶 1000 条。

## 目录约定

- `src/domain.js`：现有领域读取和查看接口（清单验签）。
- `src/archive.js`：内容对象、来源回执与完整性检查。
- `src/intake.js`：授权领取、逐块解密、可恢复接纳会话、状态与保留策略。
- `src/demo.js`：合成数据场景演示。
- `fixtures/`：本地合成资料与受控钥匙目录（`keys/`），`rotation/` 为混合 key ID 的轮换导出，`missing-key/` 引用未发放的 key ID。
- `test/`：已有行为的运行验证，使用独立临时目录。

## Linux 环境

`Dockerfile` 使用 Node.js 22 镜像；浏览器项目使用包含 Chromium 的运行镜像。可执行 `docker build -t sealed-export:local .` 后运行 `docker run --rm --network none sealed-export:local npm test`。测试中的 HTTP、MQTT 和门户都仅绑定回环地址；不需要第二个容器。构建阶段准备依赖，运行时不安装依赖。
