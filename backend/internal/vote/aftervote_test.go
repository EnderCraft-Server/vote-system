package vote

import (
	"context"
	"testing"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
)

// 关掉"一 IP 一票"时，after_vote 必须退化成"立即可见"——
// 否则所有人打开结果页都是"结果暂未公开"（管理端默认就是 after_vote）。
func TestAfterVoteVisibleWhenOneVoteDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Captcha.Enabled = false
	cfg.Captcha.Pow.Enabled = false
	cfg.Limits.OneVotePerIP = false

	st := memory.New()
	svc := New(st, cfg)
	ctx := context.Background()

	p, err := st.CreatePoll(ctx, store.PollInput{
		Title: "t", Status: "open", ShowResults: "after_vote",
	}, "aftervote", 0)
	if err != nil {
		t.Fatal(err)
	}
	view, err := svc.GetPoll(ctx, p.Slug, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if !view.Poll.ResultsVisible {
		t.Fatalf("一 IP 一票关闭时 after_vote 应立即可见：%+v", view)
	}

	// 打开"一 IP 一票"后，没投过的人仍然看不到
	cfg2 := config.Default()
	cfg2.Limits.OneVotePerIP = true
	svc2 := New(st, cfg2)
	view2, err := svc2.GetPoll(ctx, p.Slug, "203.0.113.2")
	if err != nil {
		t.Fatal(err)
	}
	if view2.Poll.ResultsVisible {
		t.Fatalf("开启一 IP 一票且未投票时不应可见：%+v", view2)
	}
}
