// Package console 提供后台进程的交互式控制台（stdin）。
//
// 为什么需要它：TOTP 绑定之后不允许自助解绑（防止账号被盗的人换绑自己的手机），
// 解绑只能由"能登到服务器上的人"执行 —— 也就是这条命令：
//
//	unbind totp <username>
//
// 注意：用 systemd 托管时进程的 stdin 是 /dev/null，控制台不可用；
// 这种情况下请用一次性参数：voted -unbind-totp <username>。
package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

type Console struct {
	st  store.Store
	log *slog.Logger
	in  io.Reader
	out io.Writer
}

func New(st store.Store, log *slog.Logger) *Console {
	return &Console{st: st, log: log, in: os.Stdin, out: os.Stdout}
}

// NewWith 便于测试。
func NewWith(st store.Store, log *slog.Logger, in io.Reader, out io.Writer) *Console {
	return &Console{st: st, log: log, in: in, out: out}
}

func (c *Console) printf(format string, args ...any) {
	fmt.Fprintf(c.out, format, args...)
}

// Run 读取 stdin 直到 EOF 或 quit。它不阻塞主的启动流程（由调用方放进 goroutine）。
func (c *Console) Run(ctx context.Context) {
	c.printf("\n投票后台控制台。help 查看命令，quit 退出控制台（后台继续运行）。\n> ")
	sc := bufio.NewScanner(c.in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			c.printf("> ")
			continue
		}
		if line == "quit" || line == "exit" {
			c.printf("控制台已退出，后台仍在运行。\n")
			return
		}
		if err := c.Exec(ctx, line); err != nil {
			c.printf("错误：%v\n", err)
		}
		c.printf("> ")
	}
}

// Exec 解析并执行一条命令（测试直接调用它）。
func (c *Console) Exec(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "help", "?":
		c.printf("%s\n", strings.Join([]string{
			"可用命令：",
			"  list admins                 列出管理员及 TOTP 绑定状态",
			"  unbind totp <username>      解绑某管理员的 authenticator（解绑后需重新绑定）",
			"  help                        显示本帮助",
			"  quit                        退出控制台（后台继续运行）",
		}, "\n"))
		return nil

	case "list":
		if len(fields) != 2 || fields[1] != "admins" {
			return fmt.Errorf("用法：list admins")
		}
		admins, err := c.st.ListAdmins(ctx)
		if err != nil {
			return err
		}
		c.printf("%-24s %-6s %-10s %s\n", "用户名", "状态", "TOTP", "上次登录")
		for _, a := range admins {
			state := "禁用"
			if a.Active {
				state = "启用"
			}
			totpState := "未绑定"
			if a.TOTPSecret != "" {
				totpState = "已绑定"
			}
			last := "-"
			if a.LastLoginAt != nil {
				last = a.LastLoginAt.Format("2006-01-02 15:04")
			}
			c.printf("%-24s %-6s %-10s %s\n", a.Username, state, totpState, last)
		}
		return nil

	case "unbind":
		if len(fields) != 3 || fields[1] != "totp" {
			return fmt.Errorf("用法：unbind totp <username>")
		}
		return c.unbindTOTP(ctx, fields[2])
	}
	return fmt.Errorf("未知命令 %q（输入 help 查看）", fields[0])
}

func (c *Console) unbindTOTP(ctx context.Context, username string) error {
	admin, err := c.st.GetAdminByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("找不到管理员 %q", username)
	}
	if admin.TOTPSecret == "" {
		return fmt.Errorf("管理员 %q 尚未绑定 authenticator", username)
	}
	if err := c.st.ClearAdminTOTP(ctx, admin.ID); err != nil {
		return err
	}
	if err := c.st.AddAudit(ctx, &store.AuditEntry{
		Actor: "console", Action: "totp_unbind", Target: "admin:" + username,
		IPText: "local", Detail: "后台控制台执行 unbind totp",
	}); err != nil {
		c.log.Warn("写审计失败", "action", "totp_unbind", "err", err)
	}
	c.log.Warn("已解绑 TOTP，请尽快重新绑定", "username", username)
	c.printf("已解绑 %s 的 authenticator。该账号下次需要重新绑定后才能执行危险操作。\n", username)
	return nil
}
