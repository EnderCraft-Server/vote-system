package vote

import (
	"bytes"
	"context"
	"errors"
	"image"
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
)

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Env = "development"
	cfg.Security.RPCSecret = strings.Repeat("s", 48)
	cfg.Captcha.Enabled = true
	cfg.Captcha.TTL = config.Duration{Duration: 5 * time.Minute}
	cfg.Captcha.MaxAttempts = 3
	cfg.Captcha.CreatePerIPMinute = 100
	cfg.Limits.VotePerIPMinute = 100
	cfg.Limits.IPDefaultAction = "allow"
	return cfg
}

type fixture struct {
	svc  *Service
	st   *memory.Store
	cfg  *config.Config
	poll *store.Poll
	q    []store.Question
}

func newFixture(t *testing.T, mutate func(*config.Config)) *fixture {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(cfg)
	}
	st := memory.New()
	poll, err := st.CreatePoll(context.Background(), store.PollInput{
		Title: "测试投票", Summary: "s", Status: "open", ShowResults: "after_vote", OnePerIP: true,
	}, "testpoll", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceQuestions(context.Background(), poll.ID, []store.QuestionInput{
		{Type: "single", Title: "单选题", Required: true, Options: []string{"A", "B"}},
		{Type: "multiple", Title: "多选题", Required: true, MinChoices: 1, MaxChoices: 2, Options: []string{"X", "Y", "Z"}},
		{Type: "rank", Title: "排序题", Required: true, Options: []string{"一", "二", "三"}},
		{Type: "text", Title: "简答题", Required: false, MaxLength: 20},
	}); err != nil {
		t.Fatal(err)
	}
	qs, err := st.ListQuestions(context.Background(), poll.ID)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: New(st, cfg), st: st, cfg: cfg, poll: poll, q: qs}
}

// seedCaptcha 直接在存储里放一条已知答案的验证码，绕开图片渲染。
func (f *fixture) seedCaptcha(t *testing.T, ipText, answer string) string {
	t.Helper()
	id := randomToken(16)
	now := time.Now()
	err := f.st.CreateCaptcha(context.Background(), &store.Captcha{
		ID: id, IP: mustIP(t, ipText), IPText: ipText,
		AnswerHash: f.svc.captchaHash(id, []byte(answer)),
		CreatedAt:  now, ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustIP(t *testing.T, s string) []byte {
	t.Helper()
	_, b, err := parseIP(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) validAnswers() []AnswerInput {
	return []AnswerInput{
		{QuestionID: f.q[0].ID, Choices: []int64{f.q[0].Options[1].ID}},
		{QuestionID: f.q[1].ID, Choices: []int64{f.q[1].Options[0].ID, f.q[1].Options[2].ID}},
		{QuestionID: f.q[2].ID, Ranking: []int64{f.q[2].Options[2].ID, f.q[2].Options[0].ID, f.q[2].Options[1].ID}},
		{QuestionID: f.q[3].ID, Text: "  夜间路灯太暗  "},
	}
}

func TestSubmitAndRejectSecondVote(t *testing.T) {
	f := newFixture(t, nil)
	capID := f.seedCaptcha(t, "203.0.113.9", "123456")
	in := SubmitInput{
		Slug: f.poll.Slug, IP: "203.0.113.9", UA: "go-test",
		Captcha: struct{ ID, Answer string }{ID: capID, Answer: "123456"},
		Answers: f.validAnswers(),
	}
	res, err := f.svc.Submit(context.Background(), in)
	if err != nil {
		t.Fatalf("首次投票失败：%v", err)
	}
	if len(res.Receipt) != 16 {
		t.Fatalf("回执长度异常：%q", res.Receipt)
	}
	// 同一 IP 第二次：先被 hasVoted 拦下
	capID2 := f.seedCaptcha(t, "203.0.113.9", "654321")
	in.Captcha.ID, in.Captcha.Answer = capID2, "654321"
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrAlreadyVoted) {
		t.Fatalf("期望 ErrAlreadyVoted，得到 %v", err)
	}
	// 换一个 IP 但复用已消费的验证码：必须失败
	in.IP = "203.0.113.10"
	in.Captcha.ID, in.Captcha.Answer = capID, "123456"
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaExpired) {
		t.Fatalf("期望验证码失效，得到 %v", err)
	}
}

func TestCreateCaptchaReturnsUsablePNG(t *testing.T) {
	f := newFixture(t, nil)
	id, ttl, err := f.svc.CreateCaptcha(context.Background(), "203.0.113.44")
	if err != nil {
		t.Fatalf("CreateCaptcha: %v", err)
	}
	if ttl <= 0 || len(id) < 16 {
		t.Fatalf("id/ttl 异常：%q %d", id, ttl)
	}
	png, err := f.svc.CaptchaImage(id)
	if err != nil {
		t.Fatalf("CaptchaImage: %v", err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(png))
	if err != nil {
		t.Fatalf("生成的图片无法解码：%v", err)
	}
	if format != "png" {
		t.Fatalf("格式 = %q，期望 png", format)
	}
	if cfg.Width != 320 || cfg.Height != 100 {
		t.Fatalf("尺寸 = %dx%d，期望 320x100", cfg.Width, cfg.Height)
	}
	// 库里只存答案的哈希，不存明文
	row, err := f.st.GetCaptcha(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(row.AnswerHash) != 64 {
		t.Fatalf("AnswerHash 长度 = %d，应为 sha256 十六进制", len(row.AnswerHash))
	}
}

func TestCaptchaRules(t *testing.T) {
	f := newFixture(t, nil)

	// 答案错误 → captcha_invalid，且尝试次数累加
	id := f.seedCaptcha(t, "198.51.100.1", "111111")
	in := SubmitInput{
		Slug: f.poll.Slug, IP: "198.51.100.1",
		Captcha: struct{ ID, Answer string }{ID: id, Answer: "222222"},
		Answers: f.validAnswers(),
	}
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatalf("期望 ErrCaptchaInvalid，得到 %v", err)
	}
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatalf("第二次错误仍应是 ErrCaptchaInvalid，得到 %v", err)
	}
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaExpired) {
		t.Fatalf("第三次应作废（max_attempts=3），得到 %v", err)
	}
	// 用正确的答案也已经失效
	in.Captcha.Answer = "111111"
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaExpired) {
		t.Fatalf("作废后正确密码也不该通过，得到 %v", err)
	}

	// 验证码与 IP 绑定
	id2 := f.seedCaptcha(t, "198.51.100.2", "999999")
	in = SubmitInput{
		Slug: f.poll.Slug, IP: "198.51.100.3",
		Captcha: struct{ ID, Answer string }{ID: id2, Answer: "999999"},
		Answers: f.validAnswers(),
	}
	if _, err := f.svc.Submit(context.Background(), in); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatalf("验证码不应跨 IP 使用，得到 %v", err)
	}
}

func TestAnswerValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fixture, a []AnswerInput) []AnswerInput
	}{
		{"缺少必填题", func(f *fixture, a []AnswerInput) []AnswerInput { return a[1:] }},
		{"单选给两个", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[0].Choices = []int64{f.q[0].Options[0].ID, f.q[0].Options[1].ID}
			return a
		}},
		{"选项不属于该题", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[0].Choices = []int64{f.q[1].Options[0].ID}
			return a
		}},
		{"多选超过上限", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[1].Choices = []int64{f.q[1].Options[0].ID, f.q[1].Options[1].ID, f.q[1].Options[2].ID}
			return a
		}},
		{"多选重复", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[1].Choices = []int64{f.q[1].Options[0].ID, f.q[1].Options[0].ID}
			return a
		}},
		{"排序缺项", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[2].Ranking = []int64{f.q[2].Options[0].ID}
			return a
		}},
		{"排序重复", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[2].Ranking = []int64{f.q[2].Options[0].ID, f.q[2].Options[0].ID, f.q[2].Options[1].ID}
			return a
		}},
		{"简答超长", func(f *fixture, a []AnswerInput) []AnswerInput {
			a[3].Text = strings.Repeat("字", 50)
			return a
		}},
		{"题目重复提交", func(f *fixture, a []AnswerInput) []AnswerInput {
			return append(a, AnswerInput{QuestionID: f.q[0].ID, Choices: []int64{f.q[0].Options[0].ID}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			id := f.seedCaptcha(t, "192.0.2.50", "123123")
			in := SubmitInput{
				Slug: f.poll.Slug, IP: "192.0.2.50",
				Captcha: struct{ ID, Answer string }{ID: id, Answer: "123123"},
				Answers: tc.mutate(f, f.validAnswers()),
			}
			_, err := f.svc.Submit(context.Background(), in)
			var ve *Error
			if !errors.As(err, &ve) || ve.Code != "invalid_argument" {
				t.Fatalf("期望 invalid_argument，得到 %v", err)
			}
		})
	}
}

func TestIPRulesAndDefaultDeny(t *testing.T) {
	f := newFixture(t, nil)
	_, net24, _ := parseIP("10.9.8.0")
	if err := f.st.AddIPRule(context.Background(), &store.IPRule{
		Kind: "block", Network: net24, PrefixLen: 96 + 24, Note: "机房",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.AddIPRule(context.Background(), &store.IPRule{
		Kind: "allow", Network: net24, PrefixLen: 96 + 16, Note: "内网",
	}); err != nil {
		t.Fatal(err)
	}
	// block 优先
	if ok, err := f.svc.ipAllowed(context.Background(), mustIP(t, "10.9.8.7")); err != nil || ok {
		t.Fatalf("block 规则未生效：ok=%v err=%v", ok, err)
	}
	// 10.9.7.7 命中 allow /16
	if ok, err := f.svc.ipAllowed(context.Background(), mustIP(t, "10.9.7.7")); err != nil || !ok {
		t.Fatalf("allow 规则未生效：ok=%v err=%v", ok, err)
	}

	// 默认拒绝时，未命中的 IP 一律不允许
	f2 := newFixture(t, func(c *config.Config) { c.Limits.IPDefaultAction = "deny" })
	if ok, _ := f2.svc.ipAllowed(context.Background(), mustIP(t, "203.0.113.77")); ok {
		t.Fatal("默认拒绝应拦住未命中 allow 的 IP")
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Limits.VotePerIPMinute = 1 })
	if !f.svc.allow("vote:1.1.1.1", 1) {
		t.Fatal("第一次应放行")
	}
	if f.svc.allow("vote:1.1.1.1", 1) {
		t.Fatal("第二次应被限流")
	}
}

func TestResultsAggregation(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	for i, ip := range []string{"203.0.113.21", "203.0.113.22", "203.0.113.23"} {
		capID := f.seedCaptcha(t, ip, "555555")
		in := SubmitInput{
			Slug: f.poll.Slug, IP: ip,
			Captcha: struct{ ID, Answer string }{ID: capID, Answer: "555555"},
			Answers: f.validAnswers(),
		}
		if i == 0 {
			in.Answers[0].Choices = []int64{f.q[0].Options[0].ID}
			in.Answers[2].Ranking = []int64{f.q[2].Options[0].ID, f.q[2].Options[1].ID, f.q[2].Options[2].ID}
		}
		if _, err := f.svc.Submit(ctx, in); err != nil {
			t.Fatalf("第 %d 票失败：%v", i, err)
		}
	}
	res, err := f.svc.Results(ctx, f.poll.Slug, "203.0.113.21")
	if err != nil {
		t.Fatalf("Results: %v", err)
	}
	if res.TotalVotes != 3 {
		t.Fatalf("总票数 = %d", res.TotalVotes)
	}
	q0 := res.Questions[0]
	if len(q0.Options) != 2 {
		t.Fatalf("选项数 = %d", len(q0.Options))
	}
	if q0.Options[0].Count != 1 || q0.Options[1].Count != 2 {
		t.Fatalf("单选统计错误：%+v", q0.Options)
	}
	if q0.Options[1].Percent < 66 || q0.Options[1].Percent > 67 {
		t.Fatalf("百分比错误：%v", q0.Options[1].Percent)
	}
	// 排序题：第一张票把"一"放第一，后两张把"三"放第一
	if res.Questions[2].Options[0].FirstPlace != 1 {
		t.Fatalf("排序第一顺位统计错误：%+v", res.Questions[2].Options[0])
	}
	if res.Questions[2].Options[2].FirstPlace != 2 {
		t.Fatalf("排序第一顺位统计错误：%+v", res.Questions[2].Options[2])
	}
	// 公开结果不含简答原文（隐私），只给份数
	if len(res.Questions[3].Texts) != 0 {
		t.Fatalf("公开结果不应包含简答原文，得到 %d 条", len(res.Questions[3].Texts))
	}
	if res.Questions[3].TotalResponses != 3 {
		t.Fatalf("简答份数 = %d", res.Questions[3].TotalResponses)
	}
	admin, err := f.svc.AdminResults(ctx, f.poll.Slug)
	if err != nil {
		t.Fatalf("AdminResults: %v", err)
	}
	if len(admin.Questions[3].Texts) != 3 || admin.Questions[3].Texts[0] != "夜间路灯太暗" {
		t.Fatalf("管理端应看到去空白的简答原文：%+v", admin.Questions[3].Texts)
	}
}

func TestResultsHiddenUntilVoted(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.svc.Results(context.Background(), f.poll.Slug, "203.0.113.99"); !errors.Is(err, ErrResultsHidden) {
		t.Fatalf("未投票不应看到结果，得到 %v", err)
	}
}

func TestPollClosedStopsVotes(t *testing.T) {
	f := newFixture(t, nil)
	past := time.Now().Add(-time.Hour)
	closed := "closed"
	if err := f.st.UpdatePoll(context.Background(), f.poll.ID, store.PollInput{
		Title: f.poll.Title, Status: closed, ShowResults: "always", OnePerIP: true, EndsAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	id := f.seedCaptcha(t, "203.0.113.31", "777777")
	_, err := f.svc.Submit(context.Background(), SubmitInput{
		Slug: f.poll.Slug, IP: "203.0.113.31",
		Captcha: struct{ ID, Answer string }{ID: id, Answer: "777777"},
		Answers: f.validAnswers(),
	})
	if !errors.Is(err, ErrPollClosed) {
		t.Fatalf("期望 ErrPollClosed，得到 %v", err)
	}
}
