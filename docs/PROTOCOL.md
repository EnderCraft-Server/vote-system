# 前台 ↔ 后台 RPC 协议（v1）

传输：TCP，长连接，请求-响应严格串行。所有多字节整数为**大端**。

## 帧结构

外层是 4 字节长度前缀（不含自身），随后是 payload。

### 请求 payload

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | magic | `56 4F 54 45`（`VOTE`） |
| 4 | 1 | version | `0x01` |
| 5 | 1 | flags | 保留，必须 `0x00` |
| 6 | 2 | reserved | 必须全 0 |
| 8 | 8 | timestamp | Unix 秒（uint64） |
| 16 | 16 | request_id | 随机 16 字节，响应原样回显 |
| 32 | 16 | nonce | 随机 16 字节，服务端去重 |
| 48 | 1 | method_len | 方法名长度（1..63） |
| 49 | N | method | ASCII，如 `vote.submit` |
| 49+N | 4 | body_len | JSON 长度（0..262144） |
| 53+N | M | body | UTF-8 JSON 对象 |
| 53+N+M | 32 | mac | HMAC-SHA256(secret, payload[0 .. 53+N+M)) |

### 响应 payload

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | magic | `56 4F 54 52`（`VOTR`） |
| 4 | 1 | version | `0x01` |
| 5 | 1 | status | 0 = 成功，1 = 失败 |
| 6 | 2 | reserved | 全 0 |
| 8 | 8 | timestamp | Unix 秒 |
| 16 | 16 | request_id | 回显请求中的值 |
| 32 | 4 | body_len | JSON 长度 |
| 36 | M | body | UTF-8 JSON；失败时是 `{"code":..,"message":..}` |
| 36+M | 32 | mac | HMAC-SHA256(secret, payload[0 .. 36+M)) |

整帧上限 1 MiB；body 上限 256 KiB。超限立即断开，不回复。

## 签名算法

```text
mac = HMAC_SHA256(key = rpc_secret 的 UTF-8 字节, data = payload 去掉末尾 32 字节 mac 的全部字节)
```

- 比较用常数时间比较（Go: `hmac.Equal`；PHP: `hash_equals`）。
- 响应也签名，前台必须验证；签错的响应按「后台异常」处理，不渲染数据。
- rpc_secret 长度少于 32 字节时后台拒绝启动。

## 服务端校验顺序（任一失败即断开/拒绝）

1. 长度前缀合法、magic 正确、version 已知、reserved 为 0。
2. |now - timestamp| ≤ `rpc_clock_skew`（默认 60s）。
3. nonce 未在 `rpc_nonce_ttl`（默认 300s）内出现过。
4. mac 校验通过。
5. method 在方法表内；body 是合法 JSON 且字段类型正确。

第 1–4 步失败按**协议违例**处理：写日志（含来源 IP、方法名如可读、原因码），关闭连接，不返回业务错误。
第 5 步失败返回 `invalid_argument` / `unknown_method`。

## 方法表

| 方法 | 请求体 | 响应体 |
| --- | --- | --- |
| `ping` | @@BT@{}` | `{"pong":true,"time":<unix>}` |
| `captcha.create` | `{"ip":"1.2.3.4"}` | `{"id":"..","ttl":300}` |
| `captcha.image` | `{"id":".."}` | `{"png":"<base64>","width":240,"height":80}` |
| `poll.list` | @@BT@{}` | `{"polls":[{"slug","title","summary","status","vote_count","question_count","ends_at"}]}` |
| `poll.get` | `{"slug":"ab12cd34ef56","ip":"1.2.3.4"}` | `{"poll":{...},"questions":[...],"has_voted":false,"can_vote":true,"results_visible":false}` |
| `vote.submit` | 见下 | `{"receipt":"K7F2...","vote_id":12}` |
| `poll.results` | `{"slug":"..","ip":".."}` | `{"poll":{...},"total_votes":3,"questions":[{"..","options":[{"label","count","percent"}]}]}` |

`vote.submit` 请求体：

```json
{
  "slug": "ab12cd34ef56",
  "ip": "1.2.3.4",
  "ua": "Mozilla/5.0 …",
  "captcha": {"id": "Vt3x…", "answer": "482915"},
  "answers": [
    {"question_id": 3, "choices": [11]},
    {"question_id": 4, "choices": [21, 22]},
    {"question_id": 5, "text": "希望增加夜间巡逻"},
    {"question_id": 6, "ranking": [31, 33, 32]}
  ]
}
```

## 错误码

| code | 含义 | 前台文案（中文） |
| --- | --- | --- |
| `unknown_method` | 方法不存在 | 服务暂时不可用，请稍后再试 |
| `invalid_argument` | 参数缺失/类型错误 | 提交内容有误，请检查后重试 |
| `poll_not_found` | slug 不存在 | 投票不存在或已被删除 |
| `poll_closed` | 未开始/已结束/已关闭 | 该投票已结束 |
| `already_voted` | 该 IP 已投票 | 你所在的网络已经投过票了 |
| `captcha_invalid` | 验证码错误（含尝试过多） | 验证码不正确，请重新输入 |
| `captcha_expired` | 验证码过期/不存在 | 验证码已过期，请刷新页面 |
| `ip_blocked` | IP 命中拦截规则 | 当前网络无法参与本次投票 |
| `rate_limited` | 触发限流 | 操作太频繁，请稍后再试 |
| `internal` | 内部错误 | 服务暂时不可用，请稍后再试 |

`message` 字段只给运维看，前台**不**直接展示（开发模式下才会显示在页面底部）。
