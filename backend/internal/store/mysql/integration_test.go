package mysql

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

// 这些用例需要一个真实的 MySQL：设置 VOTE_TEST_MYSQL_DSN 才会跑，否则跳过。
// 用法（示例）：
//
//	$env:VOTE_TEST_MYSQL_DSN='vote:pw@tcp(127.0.0.1:3306)/vote_system_test?charset=utf8mb4&parseTime=true'
//	go test ./internal/store/mysql -run Integration -v
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("VOTE_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("未设置 VOTE_TEST_MYSQL_DSN，跳过 MySQL 集成测试")
	}
	st, err := Open(dsn, 4, 2, time.Minute)
	if err != nil {
		t.Fatalf("打开数据库失败：%v", err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("连接数据库失败：%v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("迁移失败：%v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestIntegrationCaptchaRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	ip := make([]byte, 16)
	ip[0], ip[10], ip[11], ip[12], ip[15] = 0, 0xff, 0xff, 192, 2

	id := "itest" + strconv.FormatInt(now.UnixNano(), 10)
	c := &store.Captcha{
		ID: id, IP: ip, IPText: "192.0.2.9", AnswerHash: strings.Repeat("a", 64),
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := st.CreateCaptcha(ctx, c); err != nil {
		t.Fatalf("CreateCaptcha: %v", err)
	}
	t.Cleanup(func() { _, _ = st.PurgeExpiredCaptchas(ctx, now.Add(time.Hour)) })

	got, err := st.GetCaptcha(ctx, id)
	if err != nil {
		t.Fatalf("GetCaptcha: %v", err)
	}
	if got.AnswerHash != c.AnswerHash {
		t.Fatalf("answer_hash 没有正确往返：%q", got.AnswerHash)
	}
	if string(got.IP) != string(ip) {
		t.Fatalf("IP 没有正确往返")
	}

	// 消费一次后不能再消费
	ok, err := st.ConsumeCaptcha(ctx, id, now)
	if err != nil || !ok {
		t.Fatalf("首次消费应成功：%v %v", ok, err)
	}
	ok, _ = st.ConsumeCaptcha(ctx, id, now.Add(time.Second))
	if ok {
		t.Fatal("同一验证码不应能消费两次")
	}
}

func TestIntegrationVoteAndDuplicate(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	poll, err := st.CreatePoll(ctx, store.PollInput{
		Title: "集成测试投票 " + time.Now().Format("150405.000"), Status: "open",
		ShowResults: "always", OnePerIP: true,
	}, "it"+time.Now().Format("150405000"), 0)
	if err != nil {
		t.Fatalf("CreatePoll: %v", err)
	}
	t.Cleanup(func() { _ = st.DeletePoll(ctx, poll.ID) })

	if err := st.ReplaceQuestions(ctx, poll.ID, []store.QuestionInput{
		{Type: "single", Title: "选一个", Required: true, Options: []string{"甲", "乙"}},
	}); err != nil {
		t.Fatalf("ReplaceQuestions: %v", err)
	}
	qs, err := st.ListQuestions(ctx, poll.ID)
	if err != nil || len(qs) != 1 || len(qs[0].Options) != 1+1 {
		t.Fatalf("题目结构不对：%v %+v", err, qs)
	}

	ip := make([]byte, 16)
	ip[0], ip[10], ip[11], ip[12], ip[15] = 0, 0xff, 0xff, 198, 51
	v := &store.Vote{PollID: poll.ID, IP: ip, IPKey: ip, IPText: "198.51.100.1", UAHash: "u", Receipt: "IT" + time.Now().Format("150405000")}
	if err := st.InsertVote(ctx, v, []store.Answer{
		{QuestionID: qs[0].ID, Choices: []int64{qs[0].Options[0].ID}},
		{QuestionID: qs[0].ID, Text: "中文答案 ✓"},
	}); err != nil {
		t.Fatalf("InsertVote: %v", err)
	}
	if v.ID == 0 {
		t.Fatal("InsertVote 没有回填 ID")
	}

	// 同 IP 第二次必须冲突
	v2 := &store.Vote{PollID: poll.ID, IP: ip, IPKey: ip, IPText: "198.51.100.1", Receipt: "IT" + time.Now().Format("150405001")}
	err = st.InsertVote(ctx, v2, nil)
	if !errors.Is(err, store.ErrDuplicateVote) {
		t.Fatalf("期望 ErrDuplicateVote，得到 %v", err)
	}

	answers, err := st.ListAnswers(ctx, poll.ID)
	if err != nil || len(answers) != 2 {
		t.Fatalf("答案条数不对：%v %d", err, len(answers))
	}
	if answers[1].Text != "中文答案 ✓" {
		t.Fatalf("中文答案往返失败：%q", answers[1].Text)
	}
	count, err := st.CountVotes(ctx, poll.ID)
	if err != nil || count != 1 {
		t.Fatalf("票数 = %d (%v)", count, err)
	}
}
