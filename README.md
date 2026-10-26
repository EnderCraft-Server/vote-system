# Vote · 投票系统

一个前后台分离、单 IP 单次投票、带验证码与后台管理的投票系统。

- **前台**：PHP 8.1+，面向公众的投票页面（中文为主，可切英文）
- **后台**：Go 1.22+，独立进程，自带管理界面
- **通讯**：前台 ↔ 后台之间走本机 TCP socket，逐帧 HMAC-SHA256 签名
- **存储**：MySQL 8.0 / 5.7（字符集 utf8mb4）

```
浏览器 ──HTTPS──▶ PHP 前台 ──TCP(127.0.0.1)+HMAC──▶ Go 后台 ──▶ MySQL
                    ▲                                   ▲
                    └────── 后台管理界面（独立端口）──────┘
```

## 目录结构

```text
.
├── backend/                    Go 后台（管理界面 + 投票内核）
│   ├── cmd/voted/              程序入口
│   ├── internal/               配置、协议、存储、业务、管理界面
│   ├── config/config.example.yaml
│   └── go.mod
├── frontend/                   PHP 前台（公众站点）
│   ├── public/                 唯一 Web 根目录
│   ├── app/                    配置、RPC 客户端、控制器、视图引擎
│   ├── views/                  页面模板
│   └── config/config.example.php
├── deploy/                     nginx / systemd 样例
└── docs/                       架构、协议、部署、设计说明
```

## 快速开始（本地，无需 MySQL）

后台内置一个仅用于本地调试的内存存储（`driver: memory`），启动即可跑通全流程；生产必须用 MySQL。

```powershell
# 1. 后台（终端 A）
cd backend
copy config\config.example.yaml config\config.yaml
# 把 env 改成 development、database.driver 改成 memory、demo.seed 改成 true，然后：
go run ./cmd/voted -config ./config/config.yaml
#   RPC  监听 127.0.0.1:7788（给 PHP 用）
#   管理 监听 127.0.0.1:7789（浏览器打开 http://127.0.0.1:7789）

# 2. 前台（终端 B）
cd frontend
copy config\config.example.php config\config.php
php -S 127.0.0.1:8080 -t public dev-router.php
#   打开 http://127.0.0.1:8080
```

两边配置里的 `security.rpc_secret` / `rpc_secret` **必须完全一致**，否则后台会直接拒绝所有请求并记日志。

## 前台一览

| 路由 | 页面 |
| --- | --- |
| `/` | 进行中的投票列表 |
| `/p/{slug}` | 投票页（单选 / 多选 / 简答 / 排序 + 验证码） |
| `/p/{slug}/submit` | 提交（POST，CSRF + 验证码 + 一 IP 一票） |
| `/p/{slug}/result` | 统计结果（按管理端设置决定是否公开） |
| `/captcha/{id}.png` | 验证码图片 |

- 前台**不连数据库**，所有数据经 TCP RPC 找后台要；页面没有任何登录态 Cookie。
- 生产环境把 `env` 设为 `production`、`debug` 设为 `false`：PHP 报错只进日志，
  页面统一显示"服务暂时不可用，请稍后再试"。开发模式才会显示细节与后台返回的 message。
- 视觉规范见 [docs/DESIGN.md](docs/DESIGN.md)（配色对比度、玻璃只用在哪一层、响应式与可访问性）。

## 生产部署

1. 建库建表：见 `backend/internal/migrations/0001_init.sql`，后台启动时会自动按版本执行迁移（也可手工执行）。
2. 后台：编译 `go build -o voted ./cmd/voted`，用 systemd 常驻（见 `deploy/systemd/voted.service`），
   RPC 只监听 `127.0.0.1`，管理端口用防火墙或 nginx 的 IP 白名单保护。
3. 前台：`public/` 作为站点根，PHP-FPM 运行，示例见 `deploy/nginx/vote-system.conf.example`。
4. 两份配置文件都要换成随机长密钥，并保证文件权限只有运行用户可读。

详细步骤见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 组件划分、信任边界、数据流 |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | TCP 帧格式、签名算法、方法表 |
| [docs/DESIGN.md](docs/DESIGN.md) | 前台视觉规范（配色、字体、玻璃层级） |
| [docs/SECURITY.md](docs/SECURITY.md) | 威胁模型与逐项防护 |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | 部署、配置、升级、排错 |

## 约定

- 任何改动先开 issue，再开只针对该 issue 的分支与 PR，自评 review 后 squash 合并。
- 中文提交信息写文件后用 `git commit -F`，避免 PowerShell 转义。
- 密钥、DSN、机器路径一律不进仓库，只提交 `*.example.*`。