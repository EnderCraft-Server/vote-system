# 安全设计

第一原则是安全。这份文档按"攻击面 → 我们怎么挡 → 怎么验证"组织，
最后列出**已知的边界**——哪些事这套系统做不到，避免给人虚假的安全感。

## 信任边界

```text
公网用户
  │  ①  不可信输入：URL、表单、Cookie、UA、X-Forwarded-For
  ▼
PHP 前台（无数据库权限，无会话）
  │  ②  受签名保护的 RPC：只监听 127.0.0.1
  ▼
Go 后台（唯一有数据库权限的进程）
  │  ③  参数化 SQL
  ▼
MySQL
```

- ① 与 ② 之间是**密钥边界**：密钥不同就一个字节的业务数据都过不去。
- ② 与 ③ 之间是**接口边界**：后台只暴露固定的方法表，没有通用查询通道。
- 管理员浏览器走**独立端口**，与前台没有任何共享 Cookie / 模板 / 会话。

## 逐项防护

### 1. 前台 → 后台的传输

| 攻击 | 防护 | 在哪 |
| --- | --- | --- |
| 伪造请求 | 每帧 HMAC-SHA256（覆盖整帧，含时间戳、nonce、方法名、body） | `protocol.DecodeRequest` / `app/Rpc/Client.php` |
| 重放 | 时间戳 ±60s + nonce 300s 去重，命中即断开 | `rpc.Server` + `protocol.NonceCache` |
| 响应被篡改 | 响应同样签名，且校验 request_id 回显；验签失败前台直接报错 | 两侧 |
| 密钥爆破 | 密钥至少 32 字节；`production` 下含 `CHANGE_ME` 或过短直接拒绝启动 | `config.Validate` |
| 超大帧 DoS | 单帧 1 MiB、body 256 KiB、连接数上限、空闲超时 | `protocol` / `rpc.Server` |

### 2. 投票本身

| 攻击 | 防护 | 在哪 |
| --- | --- | --- |
| 一 IP 多票 | `votes(poll_id, ip)` 唯一键；并发下第二个事务拿 1062 → `already_voted` | 迁移 0001 / `vote.Submit` |
| 验证码被复用 | 验证码与 IP 绑定、一次性原子消费（`UPDATE … WHERE consumed_at IS NULL`）、3 次尝试后作废 | `vote.verifyCaptcha` |
| 机器批量破验证码 | 图片之外再叠一层工作量证明（无视觉语义，OCR/多模态无用），同一 IP 申请越多难度越高 | vote.Submit + internal/pow |
| 验证码答案泄露 | 库里只有 `sha256(id‖答案‖rpc_secret)`，PNG 只在进程内存 | `vote.CreateCaptcha` |
| 刷提交 | 每 IP 每分钟 3 次投票、每分钟 10 次验证码申请（令牌桶） | `vote.allow` |
| 题目/选项越权 | 答案必须对得上"该投票的题目 + 该题的选项"，多选题还校验最少/最多与去重 | `vote.validateAnswers` |
| 关闭后的票 | `IsOpenAt` 同时校验 status 与时间窗；写入前再判一次 | `vote.Submit` |
| 定向禁投 | `ip_rules` 支持 block/allow（CIDR），默认动作可设为 deny（白名单制） | `vote.ipAllowed` |

### 3. 管理端

| 攻击 | 防护 | 在哪 |
| --- | --- | --- |
| 后台暴露在公网 | 默认只监听 `127.0.0.1`；`admin_allowed_cidrs` 之外一律 403 | `admin.chain` |
| 弱口令 | bcrypt（cost 12）+ 登录失败锁定 + 每 IP 20 次/10 分钟 | `admin.handleLogin` |
| 账号枚举 | 用户不存在与密码错误返回同一句话 | 同上 |
| 会话劫持 | 32 字节随机 token，Cookie 只存 token，库里存 sha256；HttpOnly + Secure + SameSite=Strict；30 分钟空闲 + 8 小时绝对过期 | `admin.currentSession` |
| CSRF | 每个 POST 校验 `HMAC(rpc_secret, "csrf\|" + sha256(token))`；登录页用 IP+日期派生的匿名令牌 | `admin.csrfToken` |
| XSS | 全部走 `html/template` 自动转义；CSP `script-src 'self'`，无内联脚本 | `admin` 模板 |
| 改题毁数据 | 有票的投票题目只读，服务端再比对一次差异 | `admin.handlePollSave` |
| 审计缺失 | 登录/登出、投票增删改、状态切换、IP 规则、管理员增删、改密全部写 `audit_logs` | `admin.audit` |

### 4. 前台

| 攻击 | 防护 | 在哪 |
| --- | --- | --- |
| CSRF | 无状态令牌 `HMAC(secret, ts\|IP\|用途)`，30 分钟过期，常数时间比较 | `App\\Csrf` |
| 伪造来源 IP | 只有连接地址命中 `trusted_proxies` 才采信转发头，且取第一个值并重新校验格式 | `App\\ClientIp` |
| XSS | 输出统一 `e()`；CSP 无 `unsafe-inline`；结果条宽度用预生成类名而非内联样式 | `public/index.php` / `app.css` |
| 点击劫持 | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | 同上 |
| 信息泄露 | production 关闭 `display_errors`，致命错误换成一句话；后台 `message` 只进日志 | `Bootstrap` / `RpcException` |
| 路径穿越 | 路由是固定模式（`/p/{slug}` 只接受 `[A-Za-z0-9_.-]`），没有文件路径来自用户输入 | `Router` |
| 结果泄露 | 公开结果不含简答原文；`show_results` 由管理端控制，服务端判定 | `vote.Results` |

### 5. 数据

- 所有 SQL 都是占位符，没有字符串拼接（`store/mysql` 全量检查过）。
- 字符集统一 `utf8mb4`；IP 存 16 字节 `VARBINARY` 便于唯一索引与网段匹配。
- 日志里不写密钥、令牌、验证码答案；只写 slug / IP / 回执。
- 备份：只要 `vote_system` 库；恢复时注意 `schema_migrations` 一并恢复。

## 本轮自查发现并已修复的问题

| # | 问题 | 影响 | 修复 |
| --- | --- | --- | --- |
| 1 | `captchas` 表缺 `answer_hash` 列 | MySQL 下验证码永远校验失败（功能不可用） | 0002 迁移 + 集成测试 |
| 2 | 管理端 `auth` 用同一个 context key 存 session 和 admin | 模板拿不到管理员、审计 actor 变成 anonymous | 只存 admin，会话从 cookie 反推 |
| 3 | `/static/` 挂载少 `StripPrefix` | 后台 CSS/JS 404 | 修正挂载 |
| 4 | 验证码 5~6 位在 320x100 下不可读 | 用户被挡在门外（可用性→安全性反噬） | 换 base64Captcha + 降到 4 位，见 #7 |
| 5 | `mb_strlen` 硬依赖 | 未装 mbstring 的环境 500 | 换成 `text_len()` 兜底 |
| 6 | 元信息色 `#75787E` 对比度 4.03:1 | 低于 WCAG AA | 调成 `#686B71`（4.9:1） |
| 7 | 重复提交提示"已结束" | 误导用户 | 409 + "已投过票" |

## 已知边界（做不到的事）

1. **一 IP 一票 ≠ 一人一票**。同一个 NAT / 公司网络 / 校园网只能投一票；反之换 IP 就能再投。
   这是需求"每个 IP 只能投票一次"的固有限制。需要更强身份约束时，得引入手机号/学号等真实身份，
   那会破坏匿名性，不在本系统范围内。
   注意：`limits.one_vote_per_ip: false` 会**关闭**这条限制（唯一键退化为每票随机 ip_key），
   只为压测/演示准备，生产必须为 `true`。
2. **验证码是"抬高成本"，不是"杜绝机器"**。这一版是两层：
   - 图片验证码（4~6 位）：只负责"有人在看"，OCR/多模态模型能解；
   - 工作量证明（base_bits=18，按 IP 逐级升到 max_bits=24）：没有可识别的语义，**只能靠算力换答案**。
     18 bit ≈ 26 万次 SHA-256（浏览器 0.3~1 秒），24 bit ≈ 1600 万次（数十秒 CPU）。
     批量脚本想投 1000 票，第 N 票的成本会随申请次数线性抬升；正常用户只解一次，几乎无感。
   如果你的对手有 GPU 农场，自建方案挡不住——那需要托管式验证码（Turnstile/hCaptcha）或真实身份。
3. **单实例设计**。验证码 PNG 缓存在进程内存，多实例部署需要会话粘滞或改成共享存储。
4. **没有二次验证**。管理员账号被盗 = 全部权限；建议在 nginx 层再叠一层 HTTP Basic 或 VPN。
5. **审计只记录不阻止**。没有"双人复核"，误删投票无法回滚（只能靠数据库备份）。
6. **RPC 只保护到"密钥持有者"**。PHP 主机被拿下的情况下，攻击者可以伪造任意投票请求——
   这是"前后台共享密钥"架构的固有代价；缓解手段是让 PHP 与 Go 跑在同一台机器的回环地址上。

## 部署时必须做的 5 件事

1. 两份配置里的密钥都换成随机值（`openssl rand -hex 32`），权限 600，仅服务账号可读。
2. RPC 只监听 `127.0.0.1`；管理端口用防火墙或 nginx 白名单，不要直接对公网。
3. 全站 HTTPS；`admin_cookie_secure: true` 保持不变。
4. MySQL 用独立账号，只授权 `vote_system` 库，不要用 root。
5. 备份 `vote_system`，并定期检查 `storage/logs/app.log` 与 `voted` 的 journal。


## 危险操作的二次授权（OAuth2）

原来的 TOTP 已替换成"外部身份授权"，流程：

```text
POST /super/danger/delete-ip     （已登录 + CSRF + 勾选确认）
   → 服务端建一次性 pending{发起人, 动作, 目标, 5 分钟过期}
   → 302 到 provider 的 /authorize?state=<pending id>
   → 用户在 provider 登录/授权
   → GET /oauth/callback?code=..&state=..
        ├ 校验 state 存在且未过期（取出即删，防重放）
        ├ code 换 token（client_secret 只在服务端）
        ├ 读 userinfo，取 oauth.subject_field 作为身份标识
        ├ 必须等于该管理员绑定的 oauth_subject，否则拒绝并记 oauth_subject_mismatch
        └ 执行删除 + 写审计
```

- **每个账号只能绑一次**：绑定页 `/account/oauth` 跳一次授权即绑定；之后不可自助换绑，只能在后台控制台
  `unbind oauth <用户名>`（systemd 下用 `voted -unbind-oauth <用户名>`），两者都写审计。
- **callback 不依赖会话 Cookie**：从 provider 跳回来是跨站请求，SameSite=Strict 的会话本来就不会带上；
  身份完全由"服务端 pending 里的发起人 + provider 返回的 subject"决定。
- **pending 一次性 + 5 分钟过期**，state 是随机的 24 字节，猜不到也复用不了。
- 可选 `oauth.allowed_email_domains` 限定只能是公司域邮箱。
- 没启用 OAuth2（`oauth.enabled: false`）时，危险操作直接不可用——不会退化成"输密码就能删"。

## 近期修复（代码审计回填）

- **只读题目仍然提交**：管理端"已有票"时改用 `readOnly`，`<select>`/`checkbox` 用同名 hidden 顶替。
  以前用 `disabled`，控件不随表单提交，服务端解析出 0 道题 → "至少要有一道题目"，标题也存不了。
- **CSP 下的内联脚本**：删除确认从 `onsubmit` 改成 `data-confirm` + 事件委托；条形图宽度从内联 `style` 改成
  预生成 `pct-N` 类。CSP 保持 `script-src 'self'; style-src 'self'`，没有放宽。
- **X-Forwarded-For 取右不取左**：只信任 `trusted_proxies` 内的地址，并从右往左跳过它们，
  取第一个不可信地址。追加型反代（`$proxy_add_x_forwarded_for`）下，取第一个等于让客户端自己填。
- **CSRF 密钥**：弱密钥/未配置不再退化成可复算常量，改为"本进程随机 + 明确告警"，重启即失效。
- **改密吊销会话**：`POST /account/password` 与控制台 `reset password` 会删除该管理员的其它会话。
- **过期数据清理**：进程内每 10 分钟清理 `captchas`（1 小时前过期）与过期 `admin_sessions`。
- **时区固定**：新增 `server.timezone`（默认 `Asia/Shanghai`），启动时设置 `time.Local`，
  避免管理端填的时间按 UTC 解析、按上海时区落库导致整体偏移 8 小时。
- **管理端暴露校验**：production 下 `admin_listen` 监听全部地址且 `admin_allowed_cidrs` 为空时拒绝启动。
