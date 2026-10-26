// Package store 定义存储层接口与数据模型。
// 业务规则一律不写在这里：本包只负责"存/取"，MySQL 与内存两种实现都必须满足同一语义。
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound 记录不存在。
	ErrNotFound = errors.New("记录不存在")
	// ErrDuplicateVote 同一 IP 已对该投票投过票（唯一键冲突）。
	ErrDuplicateVote = errors.New("该 IP 已投票")
	// ErrConflict 并发写入冲突。
	ErrConflict = errors.New("写入冲突")
)

type Poll struct {
	ID          int64
	Slug        string
	Title       string
	Summary     string
	Status      string // draft | open | closed
	ShowResults string // never | after_vote | always
	OnePerIP    bool
	StartsAt    *time.Time
	EndsAt      *time.Time
	CreatedBy   *int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (p *Poll) IsOpenAt(now time.Time) bool {
	if p.Status != "open" {
		return false
	}
	if p.StartsAt != nil && now.Before(*p.StartsAt) {
		return false
	}
	if p.EndsAt != nil && now.After(*p.EndsAt) {
		return false
	}
	return true
}

type Option struct {
	ID         int64
	QuestionID int64
	Position   int
	Label      string
}

type Question struct {
	ID         int64
	PollID     int64
	Position   int
	Type       string // single | multiple | text | rank
	Title      string
	Hint       string
	Required   bool
	MaxLength  int
	MinChoices int
	MaxChoices int
	Options    []Option
}

type Vote struct {
	ID     int64
	PollID int64
	IP     []byte
	// IPKey 是唯一键里参与去重的那一列：开启"一 IP 一票"时等于 IP，
	// 关闭时每票随机，从而实现"同一 IP 可重复投票"。
	IPKey     []byte
	IPText    string
	UAHash    string
	Receipt   string
	CreatedAt time.Time
}

type Answer struct {
	VoteID     int64
	QuestionID int64
	Text       string
	Choices    []int64
	Ranking    []int64
}

type Captcha struct {
	ID         string
	IP         []byte
	IPText     string
	AnswerHash string
	Attempts   int
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Consumed   bool
}

type IPRule struct {
	ID        int64
	Kind      string // block | allow
	Network   []byte // 16 字节
	PrefixLen int
	Note      string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	DisplayName  string
	Active       bool
	FailedLogins int
	LockedUntil  *time.Time
	LastLoginAt  *time.Time
	LastLoginIP  string
	CreatedAt    time.Time
}

type AdminSession struct {
	ID         int64
	AdminID    int64
	TokenHash  string
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// IPStat 是"按 IP 聚合"的一行，用来判断是否有人刷票。
type IPStat struct {
	IPText  string
	Votes   int
	FirstAt time.Time
	LastAt  time.Time
}

type AuditEntry struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	IPText    string
	Detail    string
	CreatedAt time.Time
}

// PollInput 是管理端提交的投票元信息。
type PollInput struct {
	Title       string
	Summary     string
	Status      string
	ShowResults string
	OnePerIP    bool
	StartsAt    *time.Time
	EndsAt      *time.Time
}

// QuestionInput 是管理端提交的题目（含选项文本，按顺序）。
type QuestionInput struct {
	Type       string
	Title      string
	Hint       string
	Required   bool
	MaxLength  int
	MinChoices int
	MaxChoices int
	Options    []string
}

// Store 是两种实现的共同契约。
type Store interface {
	Ping(ctx context.Context) error
	Close() error

	// 投票与题目
	ListPolls(ctx context.Context, statuses []string) ([]Poll, error)
	GetPollBySlug(ctx context.Context, slug string) (*Poll, error)
	GetPoll(ctx context.Context, id int64) (*Poll, error)
	CreatePoll(ctx context.Context, in PollInput, slug string, createdBy int64) (*Poll, error)
	UpdatePoll(ctx context.Context, id int64, in PollInput) error
	DeletePoll(ctx context.Context, id int64) error
	ListQuestions(ctx context.Context, pollID int64) ([]Question, error)
	ReplaceQuestions(ctx context.Context, pollID int64, qs []QuestionInput) error

	// 票与答案
	HasVoted(ctx context.Context, pollID int64, ip []byte) (bool, error)
	InsertVote(ctx context.Context, v *Vote, answers []Answer) error
	CountVotes(ctx context.Context, pollID int64) (int, error)
	ListAnswers(ctx context.Context, pollID int64) ([]Answer, error)
	ListVotes(ctx context.Context, pollID int64, limit int) ([]Vote, error)
	// PollIPStats 按 IP 聚合该投票的票数，按票数降序。
	PollIPStats(ctx context.Context, pollID int64, limit int) ([]IPStat, error)

	// 验证码
	CreateCaptcha(ctx context.Context, c *Captcha) error
	GetCaptcha(ctx context.Context, id string) (*Captcha, error)
	IncrementCaptchaAttempts(ctx context.Context, id string) (int, error)
	ConsumeCaptcha(ctx context.Context, id string, at time.Time) (bool, error)
	PurgeExpiredCaptchas(ctx context.Context, before time.Time) (int64, error)

	// IP 规则
	ListIPRules(ctx context.Context) ([]IPRule, error)
	AddIPRule(ctx context.Context, r *IPRule) error
	DeleteIPRule(ctx context.Context, id int64) error

	// 管理员与会话
	GetAdminByUsername(ctx context.Context, username string) (*Admin, error)
	GetAdminByID(ctx context.Context, id int64) (*Admin, error)
	ListAdmins(ctx context.Context) ([]Admin, error)
	CreateAdmin(ctx context.Context, username, passwordHash, displayName string) (*Admin, error)
	UpdateAdminPassword(ctx context.Context, id int64, hash string) error
	SetAdminActive(ctx context.Context, id int64, active bool) error
	RecordLoginFailure(ctx context.Context, id int64, lockUntil *time.Time) error
	RecordLoginSuccess(ctx context.Context, id int64, ip string) error
	DeleteAdmin(ctx context.Context, id int64) error
	CreateSession(ctx context.Context, s *AdminSession) error
	GetSession(ctx context.Context, tokenHash string) (*AdminSession, error)
	TouchSession(ctx context.Context, tokenHash string, at time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)

	// 审计
	AddAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
}
