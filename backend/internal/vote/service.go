// Package vote 是投票业务规则所在的层：
// 校验 IP、验证码、答案结构，编排存储事务。所有对外错误都用 *Error，便于 RPC 层映射成错误码。
package vote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mojocn/base64Captcha"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/pow"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

// Error 是带错误码的业务错误。code 与 docs/PROTOCOL.md 的错误表一致。
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

var (
	ErrPollNotFound   = &Error{Code: "poll_not_found", Message: "投票不存在"}
	ErrPollClosed     = &Error{Code: "poll_closed", Message: "投票已结束或尚未开始"}
	ErrAlreadyVoted   = &Error{Code: "already_voted", Message: "该 IP 已投过票"}
	ErrCaptchaInvalid = &Error{Code: "captcha_invalid", Message: "验证码不正确"}
	ErrCaptchaExpired = &Error{Code: "captcha_expired", Message: "验证码已过期"}
	ErrIPBlocked      = &Error{Code: "ip_blocked", Message: "该 IP 不允许投票"}
	ErrRateLimited    = &Error{Code: "rate_limited", Message: "操作过于频繁"}
	ErrInvalid        = &Error{Code: "invalid_argument", Message: "参数不合法"}
	ErrResultsHidden  = &Error{Code: "results_hidden", Message: "结果暂不公开"}
)

// Code 提取错误码，未知错误统一内部错误。
func Code(err error) (string, string) {
	var ve *Error
	if errors.As(err, &ve) {
		return ve.Code, ve.Message
	}
	if errors.Is(err, store.ErrNotFound) {
		return ErrPollNotFound.Code, ErrPollNotFound.Message
	}
	return "internal", "内部错误"
}

// 验证码图片尺寸：320x100 下 5 位数字既难被切割又足够人眼辨认（实测 6 位会糊成一团）。
const (
	captchaWidth  = 320
	captchaHeight = 100
)

type Service struct {
	st  store.Store
	cfg *config.Config
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	images  map[string]cachedImage
	secret  []byte
	pow     *pow.Verifier
}

type bucket struct {
	tokens float64
	last   time.Time
}

type cachedImage struct {
	png []byte
	exp time.Time
}

func New(st store.Store, cfg *config.Config) *Service {
	return &Service{
		st:      st,
		cfg:     cfg,
		now:     time.Now,
		buckets: make(map[string]*bucket),
		images:  make(map[string]cachedImage),
		secret:  []byte(cfg.Security.RPCSecret),
		pow:     pow.New(cfg.Captcha, []byte(cfg.Security.RPCSecret)),
	}
}

// oneVotePerIP 表示是否执行"每个 IP 只能投票一次"。
func (s *Service) oneVotePerIP() bool { return s.cfg.Limits.OneVotePerIP }

// SetClock 只在测试里用，避免测试里 sleep。
func (s *Service) SetClock(fn func() time.Time) { s.now = fn }

// ---------- 限流 ----------

// allow 是每 IP 的令牌桶：perMinute 为每分钟补充的令牌数，桶容量同上。
func (s *Service) allow(key string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(perMinute), last: now}
		s.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Minutes()
	if elapsed > 0 {
		b.tokens += elapsed * float64(perMinute)
		if b.tokens > float64(perMinute) {
			b.tokens = float64(perMinute)
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	if len(s.buckets) > 20000 {
		for k, v := range s.buckets {
			if now.Sub(v.last) > 10*time.Minute {
				delete(s.buckets, k)
			}
		}
	}
	return true
}

// ---------- IP 工具 ----------

func parseIP(text string) (netip.Addr, []byte, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil {
		return netip.Addr{}, nil, errf("invalid_argument", "IP 地址不合法")
	}
	b := addr.As16()
	return addr, b[:], nil
}

// rulePrefix 把用户填写的 CIDR 转成 16 字节形式下的前缀长度。
func rulePrefix(prefix netip.Prefix) int {
	if prefix.Addr().Is4() {
		return 96 + prefix.Bits()
	}
	return prefix.Bits()
}

func matchesRule(network []byte, prefixLen int, ip []byte) bool {
	if len(network) != 16 || len(ip) != 16 {
		return false
	}
	full := prefixLen / 8
	for i := 0; i < full; i++ {
		if network[i] != ip[i] {
			return false
		}
	}
	rem := prefixLen % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF << (8 - rem))
	return network[full]&mask == ip[full]&mask
}

// ipBlocked 依次判断：命中 block 规则 → 拒绝；命中 allow 规则 → 放行；
// 都没命中时看 limits.ip_default_action。
func (s *Service) ipAllowed(ctx context.Context, ip []byte) (bool, error) {
	rules, err := s.st.ListIPRules(ctx)
	if err != nil {
		return false, err
	}
	now := s.now()
	allowed := false
	for _, r := range rules {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if !matchesRule(r.Network, r.PrefixLen, ip) {
			continue
		}
		if r.Kind == "block" {
			return false, nil
		}
		if r.Kind == "allow" {
			allowed = true
		}
	}
	if allowed {
		return true, nil
	}
	return s.cfg.Limits.IPDefaultAction != "deny", nil
}

// ---------- 验证码 ----------

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用：" + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Service) captchaHash(id string, digits []byte) string {
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write(digits)
	h.Write([]byte{0})
	h.Write(s.secret)
	return hex.EncodeToString(h.Sum(nil))
}

// CreateCaptcha 生成验证码并缓存渲染好的 PNG（PNG 只在内存里，进程重启即失效）。
func (s *Service) CreateCaptcha(ctx context.Context, ipText string) (string, int, error) {
	if !s.cfg.Captcha.Enabled {
		return "", 0, errf("captcha_disabled", "验证码未启用")
	}
	_, ip, err := parseIP(ipText)
	if err != nil {
		return "", 0, err
	}
	if !s.allow("captcha:"+ipText, s.cfg.Captcha.CreatePerIPMinute) {
		return "", 0, ErrRateLimited
	}
	if ok, err := s.ipAllowed(ctx, ip); err != nil {
		return "", 0, err
	} else if !ok {
		return "", 0, ErrIPBlocked
	}

	png, digits, err := renderCaptcha(s.cfg.Captcha.Length)
	if err != nil {
		return "", 0, err
	}
	id := randomToken(16)
	now := s.now()
	exp := now.Add(s.cfg.Captcha.TTL.Duration)

	s.mu.Lock()
	for k, v := range s.images {
		if now.After(v.exp) {
			delete(s.images, k)
		}
	}
	if len(s.images) > 5000 {
		for k := range s.images {
			delete(s.images, k)
			if len(s.images) <= 4000 {
				break
			}
		}
	}
	s.images[id] = cachedImage{png: png, exp: exp}
	s.mu.Unlock()

	if err := s.st.CreateCaptcha(ctx, &store.Captcha{
		ID: id, IP: ip, IPText: ipText, AnswerHash: s.captchaHash(id, []byte(digits)),
		CreatedAt: now, ExpiresAt: exp,
	}); err != nil {
		return "", 0, err
	}
	return id, int(s.cfg.Captcha.TTL.Seconds()), nil
}

// CaptchaImage 返回已渲染的 PNG（尺寸见 CaptchaSize）。
func (s *Service) CaptchaImage(id string) ([]byte, error) {
	if id == "" || len(id) > 64 {
		return nil, ErrCaptchaExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	img, ok := s.images[id]
	if !ok || s.now().After(img.exp) {
		return nil, ErrCaptchaExpired
	}
	return img.png, nil
}

// verifyCaptcha 校验并消费验证码。任何失败都不会让验证码"越试越松"：
// 每次失败 +1 次尝试，达到上限直接作废。
func (s *Service) verifyCaptcha(ctx context.Context, id, answer, ipText string, ip []byte) error {
	if !s.cfg.Captcha.Enabled {
		return nil
	}
	if id == "" || answer == "" {
		return ErrCaptchaExpired
	}
	row, err := s.st.GetCaptcha(ctx, id)
	if err != nil {
		return ErrCaptchaExpired
	}
	now := s.now()
	if row.Consumed || now.After(row.ExpiresAt) {
		return ErrCaptchaExpired
	}
	if string(row.IP) != string(ip) {
		return ErrCaptchaInvalid
	}
	if row.Attempts >= s.cfg.Captcha.MaxAttempts {
		return ErrCaptchaExpired
	}

	// 先判断答案，再消费，避免"答错也算用过"。
	want := row.AnswerHash
	got := s.captchaHash(id, []byte(strings.TrimSpace(answer)))
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		n, err := s.st.IncrementCaptchaAttempts(ctx, id)
		if err != nil {
			return err
		}
		if n >= s.cfg.Captcha.MaxAttempts {
			// 尝试次数用尽：直接消费掉，防止继续暴力猜。
			_, _ = s.st.ConsumeCaptcha(ctx, id, now)
			return ErrCaptchaExpired
		}
		return ErrCaptchaInvalid
	}
	ok, err := s.st.ConsumeCaptcha(ctx, id, now)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCaptchaExpired
	}
	s.mu.Lock()
	delete(s.images, id)
	s.mu.Unlock()
	return nil
}

// ---------- 视图类型 ----------

type OptionView struct {
	ID    int64  `json:"id"`
	Label string `json:"label"`
}

type QuestionView struct {
	ID         int64        `json:"id"`
	Type       string       `json:"type"`
	Title      string       `json:"title"`
	Hint       string       `json:"hint"`
	Required   bool         `json:"required"`
	MaxLength  int          `json:"max_length"`
	MinChoices int          `json:"min_choices"`
	MaxChoices int          `json:"max_choices"`
	Options    []OptionView `json:"options"`
}

type PollView struct {
	Slug           string  `json:"slug"`
	Title          string  `json:"title"`
	Summary        string  `json:"summary"`
	Status         string  `json:"status"`
	CanVote        bool    `json:"can_vote"`
	HasVoted       bool    `json:"has_voted"`
	ResultsVisible bool    `json:"results_visible"`
	StartsAt       *string `json:"starts_at"`
	EndsAt         *string `json:"ends_at"`
}

type PollSummaryView struct {
	Slug          string  `json:"slug"`
	Title         string  `json:"title"`
	Summary       string  `json:"summary"`
	Status        string  `json:"status"`
	CanVote       bool    `json:"can_vote"`
	VoteCount     int     `json:"vote_count"`
	QuestionCount int     `json:"question_count"`
	EndsAt        *string `json:"ends_at"`
}

type PollDetail struct {
	Poll      PollView       `json:"poll"`
	Questions []QuestionView `json:"questions"`
}

type SubmitInput struct {
	Slug    string
	IP      string
	UA      string
	Captcha struct{ ID, Answer string }
	Pow     pow.Solution
	Answers []AnswerInput
}

// PowChallenge 为某个 IP 签一张工作量证明挑战。
func (s *Service) PowChallenge(ctx context.Context, ipText string) (pow.Challenge, error) {
	if !s.cfg.Captcha.Pow.Enabled {
		return pow.Challenge{}, errf("captcha_disabled", "人机验证未启用")
	}
	if _, _, err := parseIP(ipText); err != nil {
		return pow.Challenge{}, err
	}
	return s.pow.Issue(ipText)
}

type AnswerInput struct {
	QuestionID int64   `json:"question_id"`
	Choices    []int64 `json:"choices"`
	Text       string  `json:"text"`
	Ranking    []int64 `json:"ranking"`
}

type SubmitResult struct {
	Receipt string `json:"receipt"`
	VoteID  int64  `json:"vote_id"`
}

type ResultOption struct {
	ID         int64   `json:"id"`
	Label      string  `json:"label"`
	Count      int     `json:"count"`
	Percent    float64 `json:"percent"`
	FirstPlace int     `json:"first_place"`
	AvgRank    float64 `json:"avg_rank"`
}

type ResultQuestion struct {
	ID             int64          `json:"id"`
	Type           string         `json:"type"`
	Title          string         `json:"title"`
	TotalResponses int            `json:"total_responses"`
	Options        []ResultOption `json:"options"`
	Texts          []string       `json:"texts"`
}

type ResultSet struct {
	Poll       PollView         `json:"poll"`
	TotalVotes int              `json:"total_votes"`
	Questions  []ResultQuestion `json:"questions"`
}

func timeStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := t.Format(time.RFC3339)
	return &v
}

// ---------- 查询 ----------

func (s *Service) ListPolls(ctx context.Context) ([]PollSummaryView, error) {
	polls, err := s.st.ListPolls(ctx, []string{"open", "closed"})
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]PollSummaryView, 0, len(polls))
	for _, p := range polls {
		count, err := s.st.CountVotes(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		qs, err := s.st.ListQuestions(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, PollSummaryView{
			Slug: p.Slug, Title: p.Title, Summary: p.Summary, Status: p.Status,
			CanVote: p.IsOpenAt(now), VoteCount: count, QuestionCount: len(qs),
			EndsAt: timeStr(p.EndsAt),
		})
	}
	return out, nil
}

func (s *Service) pollView(ctx context.Context, p *store.Poll, hasVoted bool) PollView {
	now := s.now()
	canVote := p.IsOpenAt(now) && !hasVoted
	// 关掉"一 IP 一票"时根本没有"这个人投过没有"的概念（hasVoted 恒为 false），
	// after_vote 会永远不公开——新建投票的默认值正是 after_vote。
	// 这里明确退化：没有一票一 IP 就没有"投票后可见"的语义，按"立即公开"处理。
	visible := p.ShowResults == "always" ||
		(p.ShowResults == "after_vote" && (hasVoted || !s.oneVotePerIP()))
	return PollView{
		Slug: p.Slug, Title: p.Title, Summary: p.Summary, Status: p.Status,
		CanVote: canVote, HasVoted: hasVoted, ResultsVisible: visible,
		StartsAt: timeStr(p.StartsAt), EndsAt: timeStr(p.EndsAt),
	}
}

func (s *Service) GetPoll(ctx context.Context, slug, ipText string) (*PollDetail, error) {
	p, err := s.st.GetPollBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrPollNotFound
		}
		return nil, err
	}
	_, ipb, ipErr := parseIP(ipText)
	hasVoted := false
	if ipErr == nil && s.oneVotePerIP() {
		hasVoted, err = s.st.HasVoted(ctx, p.ID, ipb)
		if err != nil {
			return nil, err
		}
	}
	qs, err := s.st.ListQuestions(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	views := make([]QuestionView, 0, len(qs))
	for _, q := range qs {
		qv := QuestionView{
			ID: q.ID, Type: q.Type, Title: q.Title, Hint: q.Hint, Required: q.Required,
			MaxLength: q.MaxLength, MinChoices: q.MinChoices, MaxChoices: q.MaxChoices,
			Options: make([]OptionView, 0, len(q.Options)),
		}
		for _, o := range q.Options {
			qv.Options = append(qv.Options, OptionView{ID: o.ID, Label: o.Label})
		}
		views = append(views, qv)
	}
	return &PollDetail{Poll: s.pollView(ctx, p, hasVoted), Questions: views}, nil
}

// ---------- 提交 ----------

func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

const receiptAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newReceipt() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand 不可用：" + err.Error())
	}
	out := make([]byte, 0, 16)
	// 10 字节 -> 80 bit，逐 5 bit 编码成 16 个 Crockford 字符
	var acc uint
	var bits uint
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, receiptAlphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out = append(out, receiptAlphabet[(acc<<(5-bits))&31])
	}
	return string(out)
}

// validateAnswers 把提交的答案按题目定义做一棵白名单：题目必须属于该投票、
// 选项必须属于该题、数量与长度必须符合题目设置。
func (s *Service) validateAnswers(qs []store.Question, in []AnswerInput) ([]store.Answer, error) {
	byID := make(map[int64]*store.Question, len(qs))
	for i := range qs {
		byID[qs[i].ID] = &qs[i]
	}
	seen := make(map[int64]bool, len(in))
	out := make([]store.Answer, 0, len(in))

	for _, a := range in {
		q, ok := byID[a.QuestionID]
		if !ok {
			return nil, errf("invalid_argument", "题目 %d 不属于该投票", a.QuestionID)
		}
		if seen[a.QuestionID] {
			return nil, errf("invalid_argument", "题目 %d 重复提交", a.QuestionID)
		}
		seen[a.QuestionID] = true

		optIDs := make(map[int64]bool, len(q.Options))
		for _, o := range q.Options {
			optIDs[o.ID] = true
		}

		switch q.Type {
		case "single":
			if len(a.Choices) != 1 || !optIDs[a.Choices[0]] {
				return nil, errf("invalid_argument", "题目 %d 需要且只能选择一个选项", q.ID)
			}
			out = append(out, store.Answer{QuestionID: q.ID, Choices: []int64{a.Choices[0]}})
		case "multiple":
			if len(a.Choices) == 0 {
				if q.Required {
					return nil, errf("invalid_argument", "题目 %d 至少选择一项", q.ID)
				}
				continue
			}
			if q.MinChoices > 0 && len(a.Choices) < q.MinChoices {
				return nil, errf("invalid_argument", "题目 %d 至少选择 %d 项", q.ID, q.MinChoices)
			}
			if q.MaxChoices > 0 && len(a.Choices) > q.MaxChoices {
				return nil, errf("invalid_argument", "题目 %d 最多选择 %d 项", q.ID, q.MaxChoices)
			}
			picked := make(map[int64]bool, len(a.Choices))
			clean := make([]int64, 0, len(a.Choices))
			for _, c := range a.Choices {
				if !optIDs[c] {
					return nil, errf("invalid_argument", "选项 %d 不属于题目 %d", c, q.ID)
				}
				if picked[c] {
					return nil, errf("invalid_argument", "选项 %d 重复选择", c)
				}
				picked[c] = true
				clean = append(clean, c)
			}
			out = append(out, store.Answer{QuestionID: q.ID, Choices: clean})
		case "text":
			text := strings.TrimSpace(a.Text)
			if text == "" {
				if q.Required {
					return nil, errf("invalid_argument", "题目 %d 为必填", q.ID)
				}
				continue
			}
			if !validText(text) {
				return nil, errf("invalid_argument", "题目 %d 的答案含有非法字符", q.ID)
			}
			limit := q.MaxLength
			if limit <= 0 || limit > s.cfg.Limits.AnswerTextMax {
				limit = s.cfg.Limits.AnswerTextMax
			}
			if utf8.RuneCountInString(text) > limit {
				return nil, errf("invalid_argument", "题目 %d 的答案超过 %d 字", q.ID, limit)
			}
			out = append(out, store.Answer{QuestionID: q.ID, Text: text})
		case "rank":
			if len(a.Ranking) != len(q.Options) {
				return nil, errf("invalid_argument", "题目 %d 需要为全部选项排序", q.ID)
			}
			used := make(map[int64]bool, len(a.Ranking))
			for _, id := range a.Ranking {
				if !optIDs[id] || used[id] {
					return nil, errf("invalid_argument", "题目 %d 的排序含有无效或重复选项", q.ID)
				}
				used[id] = true
			}
			out = append(out, store.Answer{QuestionID: q.ID, Ranking: a.Ranking})
		default:
			return nil, errf("invalid_argument", "题目 %d 的题型未知", q.ID)
		}
	}

	for _, q := range qs {
		if q.Required && !seen[q.ID] {
			return nil, errf("invalid_argument", "题目 %d 为必填", q.ID)
		}
	}
	return out, nil
}

func (s *Service) Submit(ctx context.Context, in SubmitInput) (*SubmitResult, error) {
	_, ip, err := parseIP(in.IP)
	if err != nil {
		return nil, err
	}
	if !s.allow("vote:"+in.IP, s.cfg.Limits.VotePerIPMinute) {
		return nil, ErrRateLimited
	}
	ok, err := s.ipAllowed(ctx, ip)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrIPBlocked
	}

	p, err := s.st.GetPollBySlug(ctx, in.Slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrPollNotFound
		}
		return nil, err
	}
	if !p.IsOpenAt(s.now()) {
		return nil, ErrPollClosed
	}

	enforceOneVote := s.oneVotePerIP()
	var ipKey []byte
	if enforceOneVote {
		hasVoted, err := s.st.HasVoted(ctx, p.ID, ip)
		if err != nil {
			return nil, err
		}
		if hasVoted {
			return nil, ErrAlreadyVoted
		}
		ipKey = ip
	} else {
		// 关闭"一 IP 一票"时每票一个随机 key，唯一键依然兜底并发写入。
		ipKey = make([]byte, 16)
		if _, err := rand.Read(ipKey); err != nil {
			return nil, err
		}
	}

	// 先校验答案结构，再消费验证码：以前顺序反了，用户填错一次就烧掉一张验证码，
	// 加上每 IP 每分钟只能申请 10 次，手滑几次就得等一分钟。
	qs, err := s.st.ListQuestions(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	answers, err := s.validateAnswers(qs, in.Answers)
	if err != nil {
		return nil, err
	}

	if err := s.verifyCaptcha(ctx, in.Captcha.ID, in.Captcha.Answer, in.IP, ip); err != nil {
		return nil, err
	}
	if s.cfg.Captcha.Pow.Enabled {
		if err := s.pow.Verify(in.Pow, in.IP); err != nil {
			if errors.Is(err, pow.ErrExpired) || errors.Is(err, pow.ErrReplay) {
				return nil, ErrCaptchaExpired
			}
			return nil, ErrCaptchaInvalid
		}
	}

	uaHash := ""
	if in.UA != "" {
		sum := sha256.Sum256([]byte(in.UA))
		uaHash = hex.EncodeToString(sum[:])
	}

	for attempt := 0; attempt < 3; attempt++ {
		v := &store.Vote{
			PollID: p.ID, IP: ip, IPKey: ipKey, IPText: in.IP,
			UAHash: uaHash, Receipt: newReceipt(),
		}
		err = s.st.InsertVote(ctx, v, answers)
		switch {
		case err == nil:
			return &SubmitResult{Receipt: v.Receipt, VoteID: v.ID}, nil
		case errors.Is(err, store.ErrDuplicateVote):
			return nil, ErrAlreadyVoted
		case errors.Is(err, store.ErrConflict):
			continue // receipt 撞车，换一个再试
		default:
			return nil, err
		}
	}
	return nil, errf("internal", "写入投票失败")
}

// ---------- 结果 ----------

// Results 是给前台看的：遵守 show_results 设置，且不包含简答原文。
func (s *Service) Results(ctx context.Context, slug, ipText string) (*ResultSet, error) {
	p, err := s.st.GetPollBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrPollNotFound
		}
		return nil, err
	}
	_, ipb, ipErr := parseIP(ipText)
	hasVoted := false
	if ipErr == nil && s.oneVotePerIP() {
		hasVoted, err = s.st.HasVoted(ctx, p.ID, ipb)
		if err != nil {
			return nil, err
		}
	}
	view := s.pollView(ctx, p, hasVoted)
	if !view.ResultsVisible {
		return nil, ErrResultsHidden
	}
	return s.aggregate(ctx, p, view, false)
}

// AdminResults 是给管理端看的：不看 show_results，且带上简答原文。
func (s *Service) AdminResults(ctx context.Context, slug string) (*ResultSet, error) {
	p, err := s.st.GetPollBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrPollNotFound
		}
		return nil, err
	}
	return s.aggregate(ctx, p, s.pollView(ctx, p, true), true)
}

func (s *Service) aggregate(ctx context.Context, p *store.Poll, view PollView, includeTexts bool) (*ResultSet, error) {
	qs, err := s.st.ListQuestions(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	answers, err := s.st.ListAnswers(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	total, err := s.st.CountVotes(ctx, p.ID)
	if err != nil {
		return nil, err
	}

	byQuestion := make(map[int64][]store.Answer, len(qs))
	for _, a := range answers {
		byQuestion[a.QuestionID] = append(byQuestion[a.QuestionID], a)
	}

	out := &ResultSet{Poll: view, TotalVotes: total, Questions: make([]ResultQuestion, 0, len(qs))}
	for _, q := range qs {
		rq := ResultQuestion{ID: q.ID, Type: q.Type, Title: q.Title}
		as := byQuestion[q.ID]
		rq.TotalResponses = len(as)
		switch q.Type {
		case "single", "multiple":
			counts := make(map[int64]int, len(q.Options))
			for _, a := range as {
				for _, c := range a.Choices {
					counts[c]++
				}
			}
			rq.Options = make([]ResultOption, 0, len(q.Options))
			for _, o := range q.Options {
				percent := 0.0
				if rq.TotalResponses > 0 {
					percent = float64(counts[o.ID]) * 100 / float64(rq.TotalResponses)
				}
				rq.Options = append(rq.Options, ResultOption{ID: o.ID, Label: o.Label, Count: counts[o.ID], Percent: percent})
			}
		case "rank":
			labels := make(map[int64]string, len(q.Options))
			for _, o := range q.Options {
				labels[o.ID] = o.Label
			}
			first := make(map[int64]int, len(q.Options))
			sum := make(map[int64]int, len(q.Options))
			cnt := make(map[int64]int, len(q.Options))
			for _, a := range as {
				for i, id := range a.Ranking {
					sum[id] += i + 1
					cnt[id]++
					if i == 0 {
						first[id]++
					}
				}
			}
			rq.Options = make([]ResultOption, 0, len(q.Options))
			for _, o := range q.Options {
				avg := 0.0
				if rq.TotalResponses > 0 {
					avg = float64(sum[o.ID]) / float64(rq.TotalResponses)
				}
				rq.Options = append(rq.Options, ResultOption{
					ID: o.ID, Label: labels[o.ID], Count: cnt[o.ID],
					FirstPlace: first[o.ID], AvgRank: avg,
				})
			}
		case "text":
			rq.Texts = make([]string, 0, len(as))
			if includeTexts {
				for _, a := range as {
					if a.Text != "" {
						rq.Texts = append(rq.Texts, a.Text)
					}
				}
				if len(rq.Texts) > 200 {
					rq.Texts = rq.Texts[:200]
				}
			}
		}
		out.Questions = append(out.Questions, rq)
	}
	return out, nil
}

// captchaStore 是个丢弃实现的 Store：答案由我们自己按 IP 绑定存放，
// 图片生成库内部那份缓存不需要（也不该）留在内存里。
type captchaStore struct{}

func (captchaStore) Set(string, string) error         { return nil }
func (captchaStore) Get(string, bool) string          { return "" }
func (captchaStore) Verify(string, string, bool) bool { return false }

// renderCaptcha 用 base64Captcha 生成一张"人眼能认"的数字验证码，返回 PNG 与答案。
// 之前用 dchest/captcha，5 位数字在 320x100 下被扭曲成一团，实测三个人里两个读不出。
func renderCaptcha(length int) ([]byte, string, error) {
	driver := base64Captcha.NewDriverDigit(captchaHeight, captchaWidth, length, 0.4, 30)
	c := base64Captcha.NewCaptcha(driver, captchaStore{})
	_, b64, answer, err := c.Generate()
	if err != nil {
		return nil, "", err
	}
	const prefix = "data:image/png;base64,"
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(b64, prefix))
	if err != nil {
		return nil, "", err
	}
	return png, answer, nil
}

// CaptchaSize 让上层（RPC 响应）不用重复写尺寸。
func CaptchaSize() (int, int) { return captchaWidth, captchaHeight }
