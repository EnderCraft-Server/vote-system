package console

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
)

func setup(t *testing.T) (*Console, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New()
	if _, err := st.CreateAdmin(context.Background(), "alice", "x", ""); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	return NewWith(st, slog.New(slog.NewTextHandler(io.Discard, nil)), strings.NewReader(""), &out, 10), st, &out
}

func TestUnbindOAuth(t *testing.T) {
	c, st, out := setup(t)
	ctx := context.Background()
	admin, _ := st.GetAdminByUsername(ctx, "alice")
	if err := st.SetAdminOAuth(ctx, admin.ID, "sso-user-1", "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := c.Exec(ctx, "unbind oauth alice"); err != nil {
		t.Fatalf("解绑应成功：%v", err)
	}
	after, _ := st.GetAdminByUsername(ctx, "alice")
	if after.OAuthSubject != "" || after.OAuthBoundAt != nil {
		t.Fatalf("解绑后不应还有密钥：%+v", after)
	}
	if !strings.Contains(out.String(), "已解绑") {
		t.Fatalf("没有输出提示：%q", out.String())
	}
	logs, err := st.ListAudit(ctx, 10)
	if err != nil || len(logs) == 0 || logs[0].Action != "oauth_unbind" || logs[0].Actor != "console" {
		t.Fatalf("应写审计：%v %+v", err, logs)
	}
}

func TestCreateAdminAndResetPassword(t *testing.T) {
	c, st, out := setup(t)
	ctx := context.Background()

	if err := c.Exec(ctx, "create admin bob"); err != nil {
		t.Fatalf("创建管理员失败：%v", err)
	}
	admin, err := st.GetAdminByUsername(ctx, "bob")
	if err != nil {
		t.Fatalf("库里应有 bob：%v", err)
	}
	if admin.PasswordHash == "" {
		t.Fatal("密码哈希为空")
	}
	// 输出里应包含一次性密码（20 位），且能被 bcrypt 校验
	re := regexp.MustCompile("一次性密码：([A-Za-z2-9]{20})")
	m := re.FindStringSubmatch(out.String())
	if len(m) != 2 {
		t.Fatalf("没有打印一次性密码：%q", out.String())
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(m[1])); err != nil {
		t.Fatalf("打印的密码与哈希不匹配：%v", err)
	}

	// 重复创建应报错
	if err := c.Exec(ctx, "create admin bob"); err == nil {
		t.Fatal("重复创建应报错")
	}
	// 非法用户名
	if err := c.Exec(ctx, "create admin a"); err == nil {
		t.Fatal("过短用户名应报错")
	}
	if err := c.Exec(ctx, "create admin bad-name"); err == nil {
		t.Fatal("非法字符应报错")
	}

	// 重置密码
	out.Reset()
	if err := c.Exec(ctx, "reset password bob"); err != nil {
		t.Fatalf("重置失败：%v", err)
	}
	m2 := re.FindStringSubmatch(out.String())
	if len(m2) != 2 {
		t.Fatalf("重置没有打印密码：%q", out.String())
	}
	after, _ := st.GetAdminByUsername(ctx, "bob")
	if after.PasswordHash == admin.PasswordHash {
		t.Fatal("重置后哈希应变化")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(after.PasswordHash), []byte(m2[1])); err != nil {
		t.Fatalf("新密码校验失败：%v", err)
	}
	if err := c.Exec(ctx, "reset password nobody"); err == nil {
		t.Fatal("不存在的用户应报错")
	}

	// 审计
	logs, _ := st.ListAudit(ctx, 10)
	var created, reset bool
	for _, l := range logs {
		if l.Action == "admin_create" {
			created = true
		}
		if l.Action == "password_reset" {
			reset = true
		}
	}
	if !created || !reset {
		t.Fatalf("审计缺失：%+v", logs)
	}
}

func TestUnbindErrors(t *testing.T) {
	c, st, _ := setup(t)
	ctx := context.Background()
	if err := c.Exec(ctx, "unbind oauth nobody"); err == nil {
		t.Fatal("不存在的用户应报错")
	}
	if err := c.Exec(ctx, "unbind oauth alice"); err == nil {
		t.Fatal("未绑定时应报错")
	}
	if err := c.Exec(ctx, "unbind alice"); err == nil {
		t.Fatal("参数不全应报错")
	}
	if err := c.Exec(ctx, "rm -rf /"); err == nil {
		t.Fatal("未知命令应报错")
	}
	// list admins 应能看到未绑定
	if err := c.Exec(ctx, "list admins"); err != nil {
		t.Fatalf("list admins 失败：%v", err)
	}
	_ = st
}

func TestRunStopsOnQuit(t *testing.T) {
	c, _, out := setup(t)
	c.in = strings.NewReader("help\nquit\n")
	c.Run(context.Background())
	if !strings.Contains(out.String(), "可用命令") {
		t.Fatalf("help 没输出：%q", out.String())
	}
	var _ store.Store = (*memory.Store)(nil)
}
