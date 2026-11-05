# AgentKeychain Managed Cloud Web Specification

## Product promise

**Your Agents can use saved credentials without receiving the long-lived secret.**

浏览器是账号控制面，不接收 Vault Data Key，不解密或显示凭证值，不因为登录就成为受信设备。

## Navigation

Desktop:

- Home / 首页
- Requests / 请求
- Devices / 设备
- Activity / 活动
- Account / 账号
- Help / 帮助
- Sign out / 退出登录

Mobile bottom navigation:

- Home
- Requests
- Devices
- More

More 默认收起，包含 Activity、Account、Help、Sign out；关闭后恢复焦点。

## Routes

Public:

- `/sign-in`
- `/join/:invite`
- `/verify-email`
- `/create-passkey`
- `/recovery`
- `/recovery/:caseId`
- `/unsupported-browser`

Signed in:

- `/app`
- `/app/requests`
- `/app/requests/:requestId`
- `/app/devices`
- `/app/devices/add`
- `/app/devices/:deviceId`
- `/app/status`
- `/app/activity`
- `/app/activity/:eventId`
- `/app/history/:itemRef`
- `/app/account`
- `/app/help`

## Plain-language vocabulary

- Vault → Saved credentials / 已保存的凭证
- Device identity → Device / 设备
- Enrollment → Add a device / 添加设备
- Revocation → Remove device / 移除设备
- Sync → Updates / 更新
- Approval → Request / 请求
- Approve → Allow once / 允许一次
- Deny → Don’t allow / 不允许
- Audit → Activity / 活动
- Restore → Make this version current / 将此版本设为当前版本
- Internal scope/nonce/digest/sequence/ciphertext/key package/Worker/D1/bearer token must never appear in ordinary UI.

## Core screens

### Sign in

- Primary action: Sign in with passkey / 使用通行密钥登录
- No password fallback.
- Generic unknown-account/credential failure.
- Links: use another device, recovery, invitation.

### Join invitation

- Read-only masked invited email.
- Verify email, then create Passkey.
- Expired/used/wrong invitation states.
- No public registration.

### Home

Sections:

1. Protection/update status.
2. Requests needing attention.
3. Devices needing attention.
4. Recent activity.
5. First-device onboarding when no device exists.

“Everything is up to date” may appear only when every active device acknowledged the latest accepted change within the freshness window.

### Requests

- Needs your attention / Recent tabs.
- Card shows action, Agent, device, time, expiry and risk explanation.
- No bulk selection or batch approval.
- Detail shows exactly what will happen, who requested it, originating device, safe credential reference, expiry and reason for confirmation.
- Sticky actions: Don’t allow / Allow once.
- Allow once requires Passkey step-up.
- Missing target/amount/destination/action details disables Allow once.
- Changed/tampered request requires re-review and cannot reuse prior approval.

### Devices

- Active, needs attention, removed sections.
- Add device flow: short code, matching three-word phrase, Passkey confirmation, existing-device confirmation.
- First device follows explicit initialization path.
- Remove device requires Passkey; read back removed state; explain local files are not remotely erased.

### Update status

Plain states only:

- Everything is up to date
- Updating
- Waiting for a device
- Not recently checked
- Updates temporarily paused
- Device removed
- Status unavailable

Never show sequence, queue length, retry counter or key epoch.

### Earlier versions

- Contextual page only; no cloud plaintext credential catalog.
- If no safe label exists, show Saved credential.
- Timeline: current, updated, deleted, restored.
- Restore requires Passkey approval and an enrolled device to sign actual operation.
- Browser never manufactures restore operation.

### Activity

- Filters: All, Credential use, Requests, Devices, Account and recovery, Problems.
- Details: what happened, actor, device, time, result and related request/device.
- Explicit verification state. Verification failure produces persistent warning on Home, Requests and Activity.
- No global integer IDs, keys, signatures, envelope data or secret values.

### Account and recovery

- Passkeys, notifications, recovery status and signed-in sessions.
- Recovery shows exact stages: verifying account, cooling-off period, waiting for existing device, preparing new device, completed/cancelled/expired.
- Cancellation no longer available after activation starts.
- Completion requires re-login and device review.

## Interaction requirements

- All async states: loading, empty, retryable error, terminal error and stale data.
- Mutations use CSRF/session API and invalidate authoritative queries.
- User-visible process reflects real persisted backend state; no fake progress timers.
- Destructive or high-risk actions require a confirm surface with exact consequences.
- One H1 per page.
- Help explanations use compact accessible popovers; important risk remains visible.
- Copy/open actions for pairing and invitation links preserve complete URL.

## Accessibility and responsive gate

- WCAG AA color contrast.
- Keyboard-only sign-in, request denial/approval, device removal, activity and sign-out.
- Focus trap/restore for dialogs and mobile More sheet.
- Minimum 44px touch targets.
- No horizontal overflow at 375px.
- Desktop content fills available area without narrow floating tables.
- Reduced-motion support.
- Primary pages pass axe with zero serious/critical findings.

## Security release blockers

- Browser response or DOM contains credential value, VDK, private key or wrapped share.
- Browser can restore without enrolled device signature.
- Approval can be reused or approved after content changes.
- Device removal is shown successful without server readback.
- Recovery completion can be shown before target proof and backend completed state.
- Activity verification failure is hidden.
- Ordinary users see infrastructure or protocol terminology.
- Public signup/billing/self-hosting appears.
- Cross-account requests/devices/activity/recovery are visible.
- Real browser tests reach production accounts, Vault or Keychain.

## Acceptance tests

- Invitation → email verification → Passkey → Home.
- Passkey sign-in/cancel/unknown/replayed challenge.
- Add/remove device, phrase mismatch, expired pairing, no-device recovery route.
- Request allow/deny/expiry/changed/tampered/no-batch.
- Update status truthful freshness states.
- History preserves concurrent versions, delete remains current, approved restore waits for device.
- Activity list/detail/filter and verification failure banner.
- Fast-path and delayed recovery, cancellation, replay and session revocation.
- Cross-account isolation.
- English/Chinese UI terminology scan.
- Desktop, 375px mobile, keyboard and axe.
