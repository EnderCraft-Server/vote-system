// Package console 提供后台进程的交互式控制台（stdin）。
//
// 为什么需要它：TOTP 绑定之后不允许自助解绑（防止账号被盗的人换绑自己的手机），
// 解绑只能由"能登到服务器上的人"执行 —— 也就是这条命令：
//
//	unbind oauth <username>
//
// 注意：用 systemd 托管时进程的 stdin 是 /dev/null，控制台不可用；
// 这种情况下请用一次性参数：voted -unbind-totp <username>。
package console

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

type Console struct {
	st         store.Store
	log        *slog.Logger
	in         io.Reader
	out        io.Writer
	bcryptCost int
}

func New(st store.Store, log *slog.Logger, bcryptCost int) *Console {
	return NewWith(st, log, os.Stdin, os.Stdout, bcryptCost)
}

// NewWith 便于测试。
func NewWith(st store.Store, log *slog.Logger, in io.Reader, out io.Writer, bcryptCost int) *Console {
	if bcryptCost < 10 {
		bcryptCost = 12
	}
	return &Console{st: st, log: log, in: in, out: out, bcryptCost: bcryptCost}
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
			"  create admin <username>     创建管理员并打印一次性随机密码",
			"  reset password <username>   重置某管理员的密码并打印一次性随机密码",
			"  unbind oauth <username>     解绑某管理员绑定的外部身份（解绑后需重新绑定）",
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
		c.printf("%-24s %-6s %-10s %s\n", "用户名", "状态", "外部身份", "上次登录")
		for _, a := range admins {
			state := "禁用"
			if a.Active {
				state = "启用"
			}
			oauthState := "未绑定"
			if a.OAuthSubject != "" {
				oauthState = "已绑定"
			}
			last := "-"
			if a.LastLoginAt != nil {
				last = a.LastLoginAt.Format("2006-01-02 15:04")
			}
			c.printf("%-24s %-6s %-10s %s\n", a.Username, state, oauthState, last)
		}
		return nil

	case "create":
		if len(fields) != 3 || fields[1] != "admin" {
			return fmt.Errorf("用法：create admin <username>")
		}
		return c.createAdmin(ctx, fields[2])

	case "reset":
		if len(fields) != 3 || fields[1] != "password" {
			return fmt.Errorf("用法：reset password <username>")
		}
		return c.resetPassword(ctx, fields[2])

	case "unbind":
		if len(fields) != 3 || fields[1] != "oauth" {
			return fmt.Errorf("用法：unbind oauth <username>")
		}
		return c.unbindOAuth(ctx, fields[2])
	}
	return fmt.Errorf("未知命令 %q（输入 help 查看）", fields[0])
}

// 随机密码：去掉容易混淆的 0/O/1/l/I。
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomPassword(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range buf {
		out[i] = passwordAlphabet[int(v)%len(passwordAlphabet)]
	}
	return string(out), nil
}

func validUsername(u string) error {
	if len(u) < 3 || len(u) > 32 {
		return fmt.Errorf("用户名需要 3~32 位")
	}
	for _, r := range u {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("用户名只允许字母、数字、下划线")
		}
	}
	return nil
}

// createAdmin 在数据库里没有任何账号时用它开第一个管理员。
// 密码只打印一次，不落盘、不进日志。
func (c *Console) createAdmin(ctx context.Context, username string) error {
	if err := validUsername(username); err != nil {
		return err
	}
	if _, err := c.st.GetAdminByUsername(ctx, username); err == nil {
		return fmt.Errorf("管理员 %q 已存在；改密码用 reset password %s", username, username)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	password, err := randomPassword(20)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), c.bcryptCost)
	if err != nil {
		return err
	}
	if _, err := c.st.CreateAdmin(ctx, username, string(hash), ""); err != nil {
		return err
	}
	_ = c.st.AddAudit(ctx, &store.AuditEntry{
		Actor: "console", Action: "admin_create", Target: "admin:" + username,
		IPText: "local", Detail: "后台控制台创建",
	})
	c.log.Warn("已创建管理员，请尽快登录并修改密码", "username", username)
	c.printf("已创建管理员 %s\n", username)
	c.printf("一次性密码：%s\n", password)
	c.printf("（只显示这一次，请立刻保存；登录后到「账号」页修改。）\n")
	return nil
}

func (c *Console) resetPassword(ctx context.Context, username string) error {
	admin, err := c.st.GetAdminByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("找不到管理员 %q", username)
	}
	password, err := randomPassword(20)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), c.bcryptCost)
	if err != nil {
		return err
	}
	if err := c.st.UpdateAdminPassword(ctx, admin.ID, string(hash)); err != nil {
		return err
	}
	_ = c.st.AddAudit(ctx, &store.AuditEntry{
		Actor: "console", Action: "password_reset", Target: "admin:" + username,
		IPText: "local", Detail: "后台控制台重置",
	})
	c.log.Warn("已重置密码", "username", username)
	c.printf("已重置 %s 的密码\n", username)
	c.printf("一次性密码：%s\n", password)
	c.printf("（只显示这一次，请立刻保存。）\n")
	return nil
}

func (c *Console) unbindOAuth(ctx context.Context, username string) error {
	admin, err := c.st.GetAdminByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("找不到管理员 %q", username)
	}
	if admin.OAuthSubject == "" {
		return fmt.Errorf("管理员 %q 尚未绑定外部身份", username)
	}
	if err := c.st.ClearAdminOAuth(ctx, admin.ID); err != nil {
		return err
	}
	if err := c.st.AddAudit(ctx, &store.AuditEntry{
		Actor: "console", Action: "oauth_unbind", Target: "admin:" + username,
		IPText: "local", Detail: "后台控制台执行 unbind oauth",
	}); err != nil {
		c.log.Warn("写审计失败", "action", "oauth_unbind", "err", err)
	}
	c.log.Warn("已解绑外部身份，请尽快重新绑定", "username", username)
	c.printf("已解绑 %s 的外部身份。该账号下次需要重新绑定后才能执行危险操作。\n", username)
	return nil
}
