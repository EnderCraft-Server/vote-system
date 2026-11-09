// voted 是 Vote 后台：RPC(给 PHP 前台) + 管理界面，共用一个进程与一个数据库连接池。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/admin"
	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/console"
	"github.com/EnderCraft-Server/vote-system/backend/internal/demo"
	"github.com/EnderCraft-Server/vote-system/backend/internal/logx"
	"github.com/EnderCraft-Server/vote-system/backend/internal/rpc"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/mysql"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

const version = "0.1.0"

func main() {
	configPath := flag.String("config", "./config/config.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "打印版本号后退出")
	unbindOAuth := flag.String("unbind-oauth", "", "解绑指定管理员的外部身份后退出（systemd 下用，控制台不可交互时）")
	flag.Parse()

	if *showVersion {
		fmt.Println("voted", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "启动失败：", err)
		os.Exit(1)
	}
	log := logx.New(cfg.Log)
	slog.SetDefault(log)

	// 固定进程时区：管理端解析开始/结束时间用的是 time.Local，
	// 而 MySQL 连接串里是 loc=Asia/Shanghai——两边不一致会整体偏移 8 小时。
	if cfg.Server.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Server.Timezone)
		if err != nil {
			log.Error("时区无效", "tz", cfg.Server.Timezone, "err", err)
			os.Exit(1)
		}
		time.Local = loc
		log.Info("已固定进程时区", "tz", cfg.Server.Timezone)
	}

	st, err := openStore(cfg, log)
	if err != nil {
		log.Error("初始化存储失败", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	if cfg.Database.Driver == "memory" && cfg.Demo.Seed {
		pwd, err := demo.Seed(context.Background(), st, cfg)
		if err != nil {
			log.Error("写入演示数据失败", "err", err)
			os.Exit(1)
		}
		if pwd != "" {
			log.Warn("已创建演示管理员，请立即登录并修改密码", "username", cfg.Demo.AdminUsername, "password", pwd)
		}
	}

	if *unbindOAuth != "" {
		admin, err := st.GetAdminByUsername(context.Background(), *unbindOAuth)
		if err != nil {
			log.Error("找不到该管理员", "username", *unbindOAuth)
			os.Exit(1)
		}
		if admin.OAuthSubject == "" {
			log.Warn("该管理员尚未绑定外部身份", "username", *unbindOAuth)
			return
		}
		if err := st.ClearAdminOAuth(context.Background(), admin.ID); err != nil {
			log.Error("解绑失败", "err", err)
			os.Exit(1)
		}
		_ = st.AddAudit(context.Background(), &store.AuditEntry{
			Actor: "console", Action: "oauth_unbind", Target: "admin:" + *unbindOAuth,
			IPText: "local", Detail: "启动参数 -unbind-oauth",
		})
		log.Warn("已解绑外部身份", "username", *unbindOAuth)
		return
	}

	if admins, err := st.ListAdmins(context.Background()); err == nil && len(admins) == 0 {
		log.Warn("数据库里还没有管理员：请在下面的控制台执行 create admin <用户名>，会打印一次性密码")
	}

	svc := vote.New(st, cfg)
	rpcServer := rpc.New(rpc.Options{
		Secret:        []byte(cfg.Security.RPCSecret),
		MaxFrameBytes: cfg.Server.MaxFrameBytes,
		ReadTimeout:   cfg.Server.ReadTimeout.Duration,
		WriteTimeout:  cfg.Server.WriteTimeout.Duration,
		IdleTimeout:   cfg.Server.IdleTimeout.Duration,
		ClockSkew:     cfg.Security.RPCClockSkew.Duration,
		NonceTTL:      cfg.Security.RPCNonceTTL.Duration,
		MaxConns:      cfg.Server.MaxConnections,
	}, svc, log.With("component", "rpc"))

	ln, err := net.Listen("tcp", cfg.Server.RPCListen)
	if err != nil {
		log.Error("监听 RPC 端口失败", "addr", cfg.Server.RPCListen, "err", err)
		os.Exit(1)
	}
	log.Info("RPC 已启动", "addr", cfg.Server.RPCListen, "env", cfg.Env, "driver", cfg.Database.Driver)

	errCh := make(chan error, 1)
	go func() { errCh <- rpcServer.Serve(ln) }()

	adminServer, err := admin.New(cfg, st, svc, log.With("component", "admin"))
	if err != nil {
		log.Error("初始化管理界面失败", "err", err)
		os.Exit(1)
	}
	adminLn, err := net.Listen("tcp", cfg.Server.AdminListen)
	if err != nil {
		log.Error("监听管理端口失败", "addr", cfg.Server.AdminListen, "err", err)
		os.Exit(1)
	}
	go func() {
		if err := adminServer.Serve(adminLn); err != nil {
			errCh <- fmt.Errorf("管理界面退出：%w", err)
		}
	}()
	log.Info("管理界面已启动", "addr", cfg.Server.AdminListen,
		"allowed_cidrs", strings.Join(cfg.Server.AdminAllowedCIDRs, ","))

	go console.New(st, log.With("component", "console"), cfg.Security.AdminBcryptCost).Run(context.Background())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 过期数据清理：每打开一次投票页就插一行 captchas，不清会无限增长。
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if n, err := st.PurgeExpiredCaptchas(ctx, now.Add(-time.Hour)); err != nil {
					log.Warn("清理过期验证码失败", "err", err)
				} else if n > 0 {
					log.Info("清理过期验证码", "rows", n)
				}
				if n, err := st.DeleteExpiredSessions(ctx, now); err != nil {
					log.Warn("清理过期会话失败", "err", err)
				} else if n > 0 {
					log.Info("清理过期会话", "rows", n)
				}
			}
		}
	}()

	if cfg.IsProduction() {
		if strings.Contains(cfg.Security.RPCSecret, "CHANGE_ME") {
			log.Error("生产环境拒绝启动：security.rpc_secret 未替换")
			os.Exit(1)
		}
	}

	select {
	case <-ctx.Done():
		log.Info("收到退出信号，开始关闭")
	case err := <-errCh:
		if err != nil {
			log.Error("RPC 服务异常退出", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := rpcServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		log.Warn("关闭 RPC 时出现异常", "err", err)
	}
	if err := adminServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		log.Warn("关闭管理界面时出现异常", "err", err)
	}
	log.Info("已退出")
}

func openStore(cfg *config.Config, log *slog.Logger) (store.Store, error) {
	switch cfg.Database.Driver {
	case "memory":
		log.Warn("使用内存存储：进程重启数据全部丢失，仅供本地调试")
		return memory.New(), nil
	case "mysql":
		st, err := mysql.Open(cfg.Database.DSN, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.ConnMaxLifetime.Duration)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			return nil, fmt.Errorf("连接 MySQL 失败（检查 DSN，注意要有 parseTime=true）：%w", err)
		}
		if err := st.Migrate(ctx); err != nil {
			return nil, err
		}
		return st, nil
	}
	return nil, fmt.Errorf("未知的数据库驱动 %q", cfg.Database.Driver)
}
