# 给接手 AI 的完整提示词 / AI takeover prompt

你接手 AgentKeychain Managed Cloud v0.7 的未完成开发，而不是重新安装密码管理器。

先读仓库 `AGENTS.md` 和 `docs/AI_HANDOFF.md`，然后对照实际源码、Git diff 与测试证据。交接说明准备于 2026-11-21；其中云端操作发生在 2026-11-06–07，不是当前实时状态。不要照抄历史“已完成”结论。

## 取得完整工作代码

仓库公开地址：`https://github.com/linsipeng/agentkeychain`。

完整 WIP 源码与交接文档已放在 `handoff/managed-cloud-ai-20261121` 分支，直接克隆并切换到该分支即可，无需 ZIP 或打补丁。实现基线是 `37d9eb9387d2bee60c4531266cf42d13cccde3ca`；分支上的修复快照尚未独立审查，也不是正式发布。

- 在原 Mac 接手：使用 `/Users/mac/Projects/agentkeychain-managed-cloud-v07`，先检查 `feat/managed-cloud-v0.7` 的现有未提交更改；它已包含修复，不要重复打补丁、不 reset/stash/clean 他人代码。
- 在新环境接手：直接检出 `handoff/managed-cloud-ai-20261121`，先比较其相对实现基线的 diff，再开始隔离验收；不需要另取压缩包。
- 不复制真实 Vault、Keychain、导出的 D1、Cookie、生成的部署配置或任何私钥。新环境先做隔离的 synthetic 验收。

## 目标

把 Managed Cloud 的注册、登录、首设备、第二设备、安全同步、审批与独立恢复做成能真正使用的闭环。先修复首设备批准后的可信 roster/witness/信任包激活及重试问题，再完成其他验收。普通用户不能承担 Wrangler、服务器部署或反复确认的调试工作。

Sam 已被反复要求登录/Touch ID，明确拒绝继续配合。你必须自己查源码、复现、修复和完成隔离测试，不再让他重复点同样的按钮。不能伪造/绕过 Passkey 或 OS 生物识别；无法跨越身份边界时准确记录阻塞，不声称成功。

## 首要任务

1. 固定当前 Git/部署/本地状态的脱敏证据，确认有没有其他活动进程；不要恢复历史进程 ID 或配对短语。
2. 完整审查未提交的双 Origin、Web Step-up 和 `GENESIS_AUTH` 变更。当前 genesis binding 指向 API Trust 的完整 RecoveryAuthority；`Pick<>` 不是权限隔离，必须评估专用 RPC 入口和独立信任证据，不能为了通过测试削弱 Custodian。
3. 为“浏览器批准后 roster 发布失败→重启→请求/grant 过期”的真实故障写回归。保持原设备身份、VDK、可信锚和幂等数据，不再自动替换 pending 导致幽灵设备。禁止靠反复清库修复。
4. 查明真实浏览器/profile、Session/CSRF/bootstrap 与 401 原因；先前“Safari 有登录态”只是无证据推断，不得继承为事实。不要输出 Cookie 或抓取 Passkey assertion。
5. 改善错误：503/401/取消/请求过期不能全部显示为“request changed”。测试 UI 和编译客户端、真实 Worker bundle，而不是仅 mock 成功。
6. 补全服务图与所有 synthetic fixtures，然后运行 `AI_HANDOFF.md` 中列出的完整验证。独立安全复审通过后才可称修复已验证。历史测试计数不能当当前通过。
7. 文档与中英文用户指南同步，分清本地验证、staging 已部署、真实验收、正式发布。

## 禁止与审批

- 不接触真实凭证值，不读生产 Vault 作测试，不执行 init/setup 覆盖现有 Vault。
- 测试必须强制隔离 HOME、AGENTKEYCHAIN_HOME、OS secure-store stub；绝不触达真实 `security -U`。
- 不生成/记录业务 token、私钥、主密码、Cookie 或 KEK 明文。
- 删除/恢复/迁移/轮换/扩大 scope/委派令牌/合并/Release/第三方账号变更另需批准。之前批准的一次 staging 清理已执行完，不可继续沿用。
- 本次提示词是开发交接，不是新的部署或破坏性清理授权。先完成本地修复和独立验收。
- 不修改或放宽签名 origin、公钥归属、tombstone/replay/rollback/最后设备保护来“跑通”。

## 输出方式

先自己做，不把步骤交还给 Sam。正常进展只用简短中文说结果、影响、还差什么。最终交付必须有真实代码 diff、可复现测试与未完成清单；不把“代码改了”“测试过了”“上线了”“真实用户流程成功”混为一谈。遇到身份边界停止自动操作，但继续所有不依赖它的开发与验证。

---

## English summary for the receiving agent

Read `docs/AI_HANDOFF.md` first. This is unfinished Managed Cloud development, not a request to install/reset the user's vault. The `handoff/managed-cloud-ai-20261121` branch contains the full WIP source snapshot and documents; check it out directly without a ZIP or patch. These repairs remain unreviewed, not release-ready. On the original Mac preserve the existing dirty worktree and do not reapply changes. Finish isolated reproduction, review trust boundaries and enrollment expiry/resume, then run full compiled/bundle acceptance. Treat the Safari-session attribution as unproven. Do not ask Sam to repeat authentication attempts, bypass Passkey, use production credentials in tests, or treat past cleanup permission as continuing authorization. Deployment, destructive changes, merge and release require separate approval.
