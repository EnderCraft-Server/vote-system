# 架构

## 三个进程，两条信任边界

```text
          公网
           │  HTTPS
           ▼
 ┌──────────────────────┐        ┌────────────────────────┐
 │ PHP 前台 (php-fpm)    │  TCP   │ Go 后台 voted           │        ┌─────────┐
 │ public/ 为唯一根目录  │ ─────▶ │  · RPC  127.0.0.1:7788  │ ─────▶ │  MySQL  │
 │ 不直连数据库          │  HMAC  │  · 管理 127.0.0.1:7789  │  SQL   │ 8.0/5.7 │
 └──────────────────────┘        └────────────────────────┘        └─────────┘
           ▲                                  ▲
           │        内网 / VPN / IP 白名单      │
      （公众）                          管理员浏览器
```

三条硬规则：

1. **前台不碰数据库**。所有读写都经过 Go 后台的 RPC 方法，方法表是白名单，没有通用 SQL 通道。
2. **RPC 只监听回环地址**，每帧都有 HMAC-SHA256 签名，密钥不符直接断开并记日志，不返回任何业务数据。
3. **管理界面是独立进程/端口**，与前台没有任何共享会话、Cookie 或模板；只通过 MySQL 交换数据。

## 为什么 PHP 与 Go 之间用 TCP 而不是 HTTP

- 需求指定用 TCP socket；同时它把请求格式收敛成一个可签名的二进制帧，避免 HTTP 头、编码、代理带来的歧义。
- 帧自带时间戳与随机 nonce，重放窗口在服务端关闭；HTTP + Cookie 方案做不到这么干净。
- 只需要一个共享密钥。没有 JWT、没有 cookie 传递、没有 OAuth 流程需要维护。

## 投票请求的数据流

### 打开投票页

```text
浏览器 GET /p/{slug}
  └─ PHP 计算访客 IP（按 trusted_proxies 配置）
  └─ RPC poll.get {slug, ip}
        └─ Go: 读 polls/questions/options；查 votes(poll_id, ip) 是否已投
        └─ 返回投票内容 + has_voted
  └─ RPC captcha.create {ip}      → {id}
  └─ 渲染表单：<img src="/captcha/{id}.png"> + CSRF 签名令牌
```

### 提交投票

```text
浏览器 POST /p/{slug}/submit
  └─ PHP: 校验 CSRF（HMAC，无 cookie）
  └─ RPC vote.submit {slug, ip, ua, captcha:{id,answer}, answers:[...]}
        └─ Go 依次校验：
             1 帧签名/时间戳/nonce（协议层）
             2 IP 规则（ip_rules 的 allow/block）
             3 限流（每 IP 每分钟提交数）
             4 投票状态、时间窗口
             5 验证码：存在、未过期、未消费、IP 一致、答案正确、尝试次数 < 上限
             6 答案结构：题目属于该投票，选项属于该题，必填/最少/最多，排序含全部选项且不重复
             7 事务写 votes(唯一键 poll_id+ip) + vote_answers
  └─ 成功 303 到结果页；失败按错误码渲染一句人话（不暴露内部异常）
```

**验证码与投票的绑定**：验证码在 `captcha.create` 时记录 IP 与过期时间；提交时必须带同一个
id，且消费是原子的（`UPDATE ... WHERE consumed_at IS NULL`），因此「解一次、反复提交」不成立。

### 管理后台

```text
管理员浏览器 ──▶ Go 管理界面 (127.0.0.1:7789, IP 白名单)
  登录：用户名 + 密码（bcrypt）→ 失败计数/锁定 → 会话令牌（随机 32 字节）
  浏览器只拿到 httpOnly+Secure+SameSite=Strict 的 cookie；库里只存 sha256(token)
  所有写操作：POST + CSRF 令牌；每个动作写 audit_logs
```

## 代码分层

| 目录 | 职责 | 不许做的事 |
| --- | --- | --- |
| `backend/internal/protocol` | 帧编解码、HMAC、重放窗口 | 不知道业务字段 |
| `backend/internal/store` | 存储接口 + MySQL / 内存实现 | 不含业务规则 |
| `backend/internal/vote` | 业务规则、校验、事务编排 | 不拼 SQL 字符串 |
| `backend/internal/rpc` | TCP 服务、方法分发 | 不信任任何入参 |
| `backend/internal/admin` | 管理界面（模板 + handler） | 不复用前台模板 |
| `frontend/app/Rpc` | 帧编码、签名、超时、错误映射 | 不做业务判断 |
| `frontend/app/Http` | 路由、输入解析、CSRF、响应头 | 不输出未转义数据 |

## 失败时的行为

- 后台不可用：前台显示「服务暂时不可用，请稍后再试」，HTTP 503，不让异常信息出页面。
- 签名/协议错误：后台记录告警并断开连接；前台只看到一次失败，不重试（避免放大）。
- 数据库不可用：后台启动失败或方法返回 `internal` 错误；管理界面显示故障页。
- 投票写入冲突（同一 IP 并发提交）：唯一键冲突直接映射成 `already_voted`，不产生半条记录（事务回滚）。

## 明确不做

- 不做账号体系（公众端匿名投票，一人一 IP）。
- 不做多租户、不做 WebSocket 实时刷新。
- 不做问卷逻辑跳转、条件题；题型只有单选 / 多选 / 简答 / 排序。
