package console

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

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
	return NewWith(st, slog.New(slog.NewTextHandler(io.Discard, nil)), strings.NewReader(""), &out), st, &out
}

func TestUnbindTOTP(t *testing.T) {
	c, st, out := setup(t)
	ctx := context.Background()
	admin, _ := st.GetAdminByUsername(ctx, "alice")
	if err := st.SetAdminTOTP(ctx, admin.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := c.Exec(ctx, "unbind totp alice"); err != nil {
		t.Fatalf("解绑应成功：%v", err)
	}
	after, _ := st.GetAdminByUsername(ctx, "alice")
	if after.TOTPSecret != "" || after.TOTPBoundAt != nil {
		t.Fatalf("解绑后不应还有密钥：%+v", after)
	}
	if !strings.Contains(out.String(), "已解绑") {
		t.Fatalf("没有输出提示：%q", out.String())
	}
	logs, err := st.ListAudit(ctx, 10)
	if err != nil || len(logs) == 0 || logs[0].Action != "totp_unbind" || logs[0].Actor != "console" {
		t.Fatalf("应写审计：%v %+v", err, logs)
	}
}

func TestUnbindErrors(t *testing.T) {
	c, st, _ := setup(t)
	ctx := context.Background()
	if err := c.Exec(ctx, "unbind totp nobody"); err == nil {
		t.Fatal("不存在的用户应报错")
	}
	if err := c.Exec(ctx, "unbind totp alice"); err == nil {
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
