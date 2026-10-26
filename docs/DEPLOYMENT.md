# 部署与运维

## 0. 环境要求

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| MySQL | 8.0（5.7 可用） | 需要 `JSON` 类型；字符集 utf8mb4 |
| Go | 1.22+ | 只在构建时需要；运行是一个静态二进制 |
| PHP | 8.1+ | 需要 `pdo`？不需要——前台不碰数据库；需要 `json`、`openssl`、`sockets`（或 allow_url_fopen 之外的 stream_socket） |
| nginx / apache | 任意 | 负责 HTTPS 与 rewrite |

PHP 扩展检查：

```bash
php -m | grep -E 'json|openssl|sockets'
# mbstring 可选（没有也能跑，字符计数会退回正则）
```

## 1. 建库

```sql
CREATE DATABASE vote_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vote'@'127.0.0.1' IDENTIFIED BY '换成强密码';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON vote_system.* TO 'vote'@'127.0.0.1';
FLUSH PRIVILEGES;
```

表结构由后台启动时自动迁移（`internal/migrations/*.sql` → `schema_migrations`）。
所以这个账号需要 `CREATE/ALTER`；如果你希望自己手工建表，可以先跑一遍后台再收回这些权限。

## 2. 配置

```bash
cd /srv/vote-system
cp backend/config/config.example.yaml /etc/vote-system/backend.yaml
cp frontend/config/config.example.php  /srv/vote-system/frontend/config/config.php
openssl rand -hex 32   # 生成两个密钥
```

后台 `/etc/vote-system/backend.yaml` 必须改的项：

```yaml
env: production
database:
  driver: mysql
  dsn: "vote:强密码@tcp(127.0.0.1:3306)/vote_system?charset=utf8mb4&parseTime=true&loc=Asia%2FShanghai&timeout=5s"
security:
  rpc_secret: "第一把 64 位十六进制"        # 与前台一致
  admin_cookie_secure: true
server:
  rpc_listen: "127.0.0.1:7788"
  admin_listen: "127.0.0.1:7789"
  admin_allowed_cidrs: ["127.0.0.1/32", "10.0.0.0/8"]   # 办公网段
```

前台 `frontend/config/config.php` 必须改的项：

```php
'env' => 'production',
'debug' => false,
'backend' => ['rpc_secret' => '同一把密钥'],
'security' => ['csrf_secret' => '另一把 64 位十六进制'],
```

```bash
chmod 600 /etc/vote-system/backend.yaml /srv/vote-system/frontend/config/config.php
chown vote:vote /etc/vote-system/backend.yaml
```

> 密钥不一致的表现：后台日志出现 `rpc 帧被拒绝 reason=bad_mac`，前台显示"服务暂时不可用"。
> 这是**故意**的——不匹配就意味着不可信，不返回任何业务数据。

## 3. 构建与启动后台

```bash
cd /srv/vote-system/backend
go build -trimpath -ldflags "-s -w" -o bin/voted ./cmd/voted
sudo cp ../deploy/systemd/voted.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now voted
journalctl -u voted -f
```

启动日志里应看到：

```text
level=INFO msg="RPC 已启动" addr=127.0.0.1:7788 env=production driver=mysql
level=INFO msg="管理界面已启动" addr=127.0.0.1:7789
```

## 4. 前台

nginx 样例见 `deploy/nginx/vote-system.conf.example`：站点根必须是 `frontend/public`，
`app/`、`views/`、`config/` 都在站点根之外。

Apache 用户把下面的 rewrite 放进 `public/.htaccess`（`AllowOverride All`）：

```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.php [QSA,L]
```

## 5. 建管理员

后台**不会**自动创建管理员（`demo.seed` 只在内存模式生效）。两种方式：

1. 用 SQL 插入（bcrypt 哈希需要现算）：

```bash
php -r 'echo password_hash("换成强密码", PASSWORD_BCRYPT, ["cost" => 12]), PHP_EOL;'
```

```sql
INSERT INTO admins (username, password_hash, display_name)
VALUES ('admin', '$2y$12$....', '管理员');
```

   Go 的 bcrypt 与 PHP 的 `$2y$` 前缀互相兼容。

2. 或者在开发环境先 `driver: memory, demo.seed: true` 跑一次，把 `admins` 表里的哈希拷过去。

## 6. 上线自查

```bash
# 1) 后台在听、且只在回环
ss -lntp | grep -E '7788|7789'
# 2) RPC 拒绝错误密钥（应当立刻断开、不回包）
php -r '$s=@stream_socket_client("tcp://127.0.0.1:7788", $e, $m, 2); var_dump($s);'   # 能连上
# 3) 前台首页 200、404 页正常
curl -sS -o /dev/null -w '%{http_code}\n' https://vote.example.com/
curl -sS -o /dev/null -w '%{http_code}\n' https://vote.example.com/nope     # 404
# 4) 安全响应头
curl -sSI https://vote.example.com/ | grep -Ei 'content-security-policy|strict-transport|x-frame'
# 5) 管理端从非白名单 IP 访问应 403
curl -sS -o /dev/null -w '%{http_code}\n' https://admin.vote.example.com/login
```

## 7. 升级

```bash
cd /srv/vote-system && git pull --ff-only
cd backend && go build -trimpath -ldflags "-s -w" -o bin/voted.new ./cmd/voted
sudo systemctl stop voted
mv bin/voted.new bin/voted
sudo systemctl start voted      # 启动时自动执行未应用的迁移
```

迁移是**只向前**的：新增列/表会在启动时补上，不会回滚。回滚版本前请先确认旧二进制能读新结构。

## 8. 备份与恢复

```bash
# 备份
mysqldump --single-transaction --routines --triggers vote_system | gzip > vote-$(date +%F).sql.gz
# 恢复（先停后台，避免迁移与写入竞争）
sudo systemctl stop voted
gunzip -c vote-2026-10-26.sql.gz | mysql vote_system
sudo systemctl start voted
```

## 9. 排错

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 前台"服务暂时不可用" | 后台没起 / 端口不对 / 密钥不一致 | `journalctl -u voted` 看 `bad_mac` 或连接被拒 |
| 后台启动即退出 | 配置校验失败（密钥占位符、production+memory、DSN 空） | 日志会逐条列出问题 |
| `连接 MySQL 失败` | DSN 少了 `parseTime=true` 或账号权限不足 | 补参数/授权 |
| 投票页 500 | PHP 致命错误 | `frontend/storage/logs/app.log`（开发模式才会显示在页面上） |
| 验证码总是"不正确" | 多实例部署 + 验证码图片落在另一个实例 | 改成单实例或做会话粘滞 |
| 管理端 403 | 来源 IP 不在 `admin_allowed_cidrs` | 加网段或走内网/VPN |
| 管理员被锁 | 连续 5 次密码错误 | 等 15 分钟，或 `UPDATE admins SET failed_logins=0, locked_until=NULL WHERE username='admin';` |
| 审核日志为空 | 迁移没跑完 | 看 `schema_migrations` 是否有 1、2 |

## 10. 容量参考

- 一次投票写入 = 1 行 `votes` + N 行 `vote_answers`（N = 题目数），单事务。
- 结果页实时聚合：题目数 × 选项数 的计数在 Go 里完成，票数上万仍是一次全表扫（按 `votes.poll_id` 索引）。
  投票量级继续上涨时，再加"按题缓存 + 定时刷新"。
- 验证码：每张 PNG ~2 KB，存在后台进程内存里，过期即清；单实例上限 5000 张。
