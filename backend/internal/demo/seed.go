// Package demo 只在 database.driver=memory + demo.seed=true 时使用，
// 为了方便本地把流程跑通：一个管理员 + 一个包含四种题型的示例投票。
package demo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

// Seed 返回临时生成的管理员密码（若配置里已给出则返回空串）。
func Seed(ctx context.Context, st store.Store, cfg *config.Config) (string, error) {
	plain := cfg.Demo.AdminPassword
	generated := false
	if plain == "" {
		var b [9]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		plain = hex.EncodeToString(b[:])
		generated = true
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), cfg.Security.AdminBcryptCost)
	if err != nil {
		return "", fmt.Errorf("生成密码哈希失败：%w", err)
	}

	admin, err := st.GetAdminByUsername(ctx, cfg.Demo.AdminUsername)
	if err != nil {
		admin, err = st.CreateAdmin(ctx, cfg.Demo.AdminUsername, string(hash), "演示管理员")
		if err != nil {
			return "", err
		}
	}

	polls, err := st.ListPolls(ctx, nil)
	if err != nil {
		return "", err
	}
	if len(polls) > 0 {
		return "", nil
	}

	now := time.Now()
	ends := now.AddDate(0, 1, 0)
	poll, err := st.CreatePoll(ctx, store.PollInput{
		Title:       "2026 秋季社区公共空间改造意见征集",
		Summary:     "我们先改哪里、先解决什么问题，由你决定。全流程匿名，一个网络只能投一次。",
		Status:      "open",
		ShowResults: "after_vote",
		OnePerIP:    true,
		StartsAt:    &now,
		EndsAt:      &ends,
	}, "demo2026", admin.ID)
	if err != nil {
		return "", err
	}

	questions := []store.QuestionInput{
		{
			Type: "single", Title: "如果只能先改一处，你希望是哪一处？", Required: true,
			Options: []string{"中心广场", "儿童活动区", "夜间照明", "分类垃圾房"},
		},
		{
			Type: "multiple", Title: "这次改造最该优先解决哪些问题？", Hint: "最多选两项", Required: true,
			MinChoices: 1, MaxChoices: 2,
			Options: []string{"无障碍通道", "夜间噪音", "非机动车停放", "绿化与遮阴", "监控与照明"},
		},
		{
			Type: "rank", Title: "请按你的优先级给四块预算排序（拖到最上方为最优先）", Required: true,
			Options: []string{"硬件设施", "安全与照明", "绿化养护", "活动运营"},
		},
		{
			Type: "text", Title: "还有什么想补充的？", Hint: "选填，最多 300 字", Required: false, MaxLength: 300,
		},
	}
	if err := st.ReplaceQuestions(ctx, poll.ID, questions); err != nil {
		return "", err
	}
	if generated {
		return plain, nil
	}
	return "", nil
}
