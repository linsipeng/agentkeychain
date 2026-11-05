# Concept

## One-line headline
AgentKeychain Cloud：让普通用户放心让 AI Agent 使用凭证，但 Agent 看不到、带不走长期秘密。

## Thesis
AgentKeychain 从面向技术用户的本地 CLI/BYO Cloudflare 工具，升级为只提供一种产品形态的托管云服务。首发服务已经使用 AI Agent、但担心凭证泄露和越权的个人与小团队。用户不需要理解 Cloudflare、scope 字符串、设备密钥或同步命令；本地 AgentKeychain 负责加密、解密和凭证交付，云端负责账号、同步、设备、版本、恢复、风险审批与审计。

## Desired outcome
用户登录 AgentKeychain 账号后，凭证在多台设备间自动同步；普通读取可按最小权限自动执行，发布、付款、删除和改权限必须确认；AI Agent 可以完成任务，但长期凭证不进入聊天、Prompt、日志或云端明文。

## Known constraints
- 只做 AgentKeychain 官方托管云模式，不再提供 BYO Cloudflare、自托管或让用户部署 Worker/D1 的产品入口。
- 平台账号验证可以触发恢复流程；恢复必须使用受控密钥托管/重包裹设计并全程审计，不能让单一应用服务静默解密用户 Vault。
- 冲突采用服务器最后接收版本为当前版本，但必须保留历史版本以便恢复。
- 本地 Vault 和云端都不得记录明文 master password、secret value、私钥或长期 KEK。
- 现有 v0.6.2 Vault、CLI、MCP、scope、审计链和 Secure Capture 必须兼容，不得破坏现有本地数据。

## Non-goals
- 不做普通消费者网站密码自动填充。
- 不做企业级 SSO、SCIM、复杂组织层级、计费或公开注册。
- 不做 BYO Cloud、自托管、Wrangler 安装或用户复制 Worker URL/Token。
- 本阶段不部署生产云、不迁移现有用户 Vault、不发布 Release。

## Success evidence
- 自动同步协议支持服务端单调序列、删除传播、历史版本和幂等重试。
- 每台设备拥有独立身份并可单独吊销，不共享一个长期 Sync Token。
- 风险审批契约能区分自动读取与必须确认的高风险动作。
- 旧 v0.3 同步入口被兼容迁移或明确弃用，普通用户路径不再出现 Cloudflare/Wrangler。
- 新旧测试、lint、typecheck、build 全部通过，并有真实本地多设备同步模拟验收。
