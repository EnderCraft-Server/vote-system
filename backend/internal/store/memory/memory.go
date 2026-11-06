// Package memory 是 store.Store 的内存实现。
// 只用于本地调试/测试（database.driver=memory，production 会拒绝启动）：进程重启数据即丢。
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

type Store struct {
	mu       sync.RWMutex
	seq      int64
	polls    map[int64]*store.Poll
	question map[int64][]store.Question
	votes    map[int64][]store.Vote
	answers  map[int64][]store.Answer
	captchas map[string]*store.Captcha
	ipRules  map[int64]*store.IPRule
	admins   map[int64]*store.Admin
	sessions map[string]*store.AdminSession
	audits   []store.AuditEntry
}

func New() *Store {
	return &Store{
		polls:    make(map[int64]*store.Poll),
		question: make(map[int64][]store.Question),
		votes:    make(map[int64][]store.Vote),
		answers:  make(map[int64][]store.Answer),
		captchas: make(map[string]*store.Captcha),
		ipRules:  make(map[int64]*store.IPRule),
		admins:   make(map[int64]*store.Admin),
		sessions: make(map[string]*store.AdminSession),
	}
}

func (s *Store) nextID() int64 {
	s.seq++
	return s.seq
}

func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close() error               { return nil }

func (s *Store) ListPolls(_ context.Context, statuses []string) ([]store.Poll, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	want := make(map[string]bool, len(statuses))
	for _, st := range statuses {
		want[st] = true
	}
	out := make([]store.Poll, 0, len(s.polls))
	for _, p := range s.polls {
		if len(want) > 0 && !want[p.Status] {
			continue
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) GetPollBySlug(_ context.Context, slug string) (*store.Poll, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.polls {
		if p.Slug == slug {
			cp := *p
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetPoll(_ context.Context, id int64) (*store.Poll, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.polls[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *Store) CreatePoll(_ context.Context, in store.PollInput, slug string, createdBy int64) (*store.Poll, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, p := range s.polls {
		if p.Slug == slug {
			return nil, store.ErrConflict
		}
	}
	p := &store.Poll{
		ID: s.nextID(), Slug: slug, Title: in.Title, Summary: in.Summary,
		Status: in.Status, ShowResults: in.ShowResults, OnePerIP: in.OnePerIP,
		StartsAt: in.StartsAt, EndsAt: in.EndsAt,
		CreatedAt: now, UpdatedAt: now,
	}
	if createdBy > 0 {
		cb := createdBy
		p.CreatedBy = &cb
	}
	s.polls[p.ID] = p
	cp := *p
	return &cp, nil
}

func (s *Store) UpdatePoll(_ context.Context, id int64, in store.PollInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.polls[id]
	if !ok {
		return store.ErrNotFound
	}
	p.Title, p.Summary, p.Status, p.ShowResults = in.Title, in.Summary, in.Status, in.ShowResults
	p.OnePerIP, p.StartsAt, p.EndsAt = in.OnePerIP, in.StartsAt, in.EndsAt
	p.UpdatedAt = time.Now()
	return nil
}

func (s *Store) DeletePoll(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.polls[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.polls, id)
	delete(s.question, id)
	for _, v := range s.votes[id] {
		delete(s.answers, v.ID)
	}
	delete(s.votes, id)
	return nil
}

func (s *Store) ListQuestions(_ context.Context, pollID int64) ([]store.Question, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.question[pollID]
	out := make([]store.Question, len(src))
	for i, q := range src {
		out[i] = q
		out[i].Options = append([]store.Option(nil), q.Options...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out, nil
}

func (s *Store) ReplaceQuestions(_ context.Context, pollID int64, qs []store.QuestionInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.polls[pollID]; !ok {
		return store.ErrNotFound
	}
	list := make([]store.Question, 0, len(qs))
	for i, in := range qs {
		q := store.Question{
			ID: s.nextID(), PollID: pollID, Position: i, Type: in.Type, Title: in.Title,
			Hint: in.Hint, Required: in.Required, MaxLength: in.MaxLength,
			MinChoices: in.MinChoices, MaxChoices: in.MaxChoices,
		}
		for j, label := range in.Options {
			q.Options = append(q.Options, store.Option{ID: s.nextID(), QuestionID: q.ID, Position: j, Label: label})
		}
		list = append(list, q)
	}
	s.question[pollID] = list
	return nil
}

func (s *Store) HasVoted(_ context.Context, pollID int64, ip []byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.votes[pollID] {
		if string(keyOf(v)) == string(ip) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) InsertVote(_ context.Context, v *store.Vote, answers []store.Answer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.votes[v.PollID] {
		if string(keyOf(old)) == string(keyOf(*v)) {
			return store.ErrDuplicateVote
		}
	}
	for _, list := range s.votes {
		for _, old := range list {
			if old.Receipt == v.Receipt {
				return store.ErrConflict
			}
		}
	}
	v.ID = s.nextID()
	v.CreatedAt = time.Now()
	s.votes[v.PollID] = append(s.votes[v.PollID], *v)
	for _, a := range answers {
		a.VoteID = v.ID
		s.answers[v.ID] = append(s.answers[v.ID], a)
	}
	return nil
}

func (s *Store) CountVotes(_ context.Context, pollID int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.votes[pollID]), nil
}

func (s *Store) ListAnswers(_ context.Context, pollID int64) ([]store.Answer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Answer
	for _, v := range s.votes[pollID] {
		for _, a := range s.answers[v.ID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *Store) ListVotes(_ context.Context, pollID int64, limit int) ([]store.Vote, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.votes[pollID]
	out := make([]store.Vote, 0, len(src))
	for i := len(src) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, src[i])
	}
	return out, nil
}

// keyOf 返回参与去重的列：有 IPKey 用 IPKey，否则退回 IP（兼容老数据）。
func keyOf(v store.Vote) []byte {
	if len(v.IPKey) > 0 {
		return v.IPKey
	}
	return v.IP
}

func (s *Store) PollIPStats(_ context.Context, pollID int64, limit int) ([]store.IPStat, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type agg struct {
		text  string
		n     int
		first time.Time
		last  time.Time
	}
	byIP := make(map[string]*agg)
	for _, v := range s.votes[pollID] {
		key := string(v.IP)
		a, ok := byIP[key]
		if !ok {
			a = &agg{text: v.IPText, first: v.CreatedAt, last: v.CreatedAt}
			byIP[key] = a
		}
		a.n++
		if v.CreatedAt.Before(a.first) {
			a.first = v.CreatedAt
		}
		if v.CreatedAt.After(a.last) {
			a.last = v.CreatedAt
		}
	}
	out := make([]store.IPStat, 0, len(byIP))
	for _, a := range byIP {
		out = append(out, store.IPStat{IPText: a.text, Votes: a.n, FirstAt: a.first, LastAt: a.last})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Votes == out[j].Votes {
			return out[i].LastAt.After(out[j].LastAt)
		}
		return out[i].Votes > out[j].Votes
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) CountVotesByIP(_ context.Context, pollID int64, ip []byte) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, v := range s.votes[pollID] {
		if string(v.IP) == string(ip) {
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteVotesByIP(_ context.Context, pollID int64, ip []byte) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]store.Vote, 0, len(s.votes[pollID]))
	var removed int64
	for _, v := range s.votes[pollID] {
		if string(v.IP) == string(ip) {
			delete(s.answers, v.ID)
			removed++
			continue
		}
		kept = append(kept, v)
	}
	s.votes[pollID] = kept
	return removed, nil
}

func (s *Store) CreateCaptcha(_ context.Context, c *store.Captcha) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.captchas[c.ID] = &cp
	return nil
}

func (s *Store) GetCaptcha(_ context.Context, id string) (*store.Captcha, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.captchas[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *Store) IncrementCaptchaAttempts(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.captchas[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (s *Store) ConsumeCaptcha(_ context.Context, id string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.captchas[id]
	if !ok || c.Consumed || at.After(c.ExpiresAt) {
		return false, nil
	}
	c.Consumed = true
	return true, nil
}

func (s *Store) PurgeExpiredCaptchas(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, c := range s.captchas {
		if c.ExpiresAt.Before(before) {
			delete(s.captchas, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) ListIPRules(context.Context) ([]store.IPRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.IPRule, 0, len(s.ipRules))
	for _, r := range s.ipRules {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) AddIPRule(_ context.Context, r *store.IPRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ID = s.nextID()
	r.CreatedAt = time.Now()
	cp := *r
	s.ipRules[r.ID] = &cp
	return nil
}

func (s *Store) DeleteIPRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ipRules[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.ipRules, id)
	return nil
}

func (s *Store) GetAdminByUsername(_ context.Context, username string) (*store.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.admins {
		if a.Username == username {
			cp := *a
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetAdminByID(_ context.Context, id int64) (*store.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.admins[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) ListAdmins(context.Context) ([]store.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Admin, 0, len(s.admins))
	for _, a := range s.admins {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) CreateAdmin(_ context.Context, username, passwordHash, displayName string) (*store.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.admins {
		if a.Username == username {
			return nil, store.ErrConflict
		}
	}
	a := &store.Admin{
		ID: s.nextID(), Username: username, PasswordHash: passwordHash,
		DisplayName: displayName, Active: true, CreatedAt: time.Now(),
	}
	s.admins[a.ID] = a
	cp := *a
	return &cp, nil
}

func (s *Store) UpdateAdminPassword(_ context.Context, id int64, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.PasswordHash = hash
	return nil
}

func (s *Store) SetAdminActive(_ context.Context, id int64, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.Active = active
	return nil
}

func (s *Store) RecordLoginFailure(_ context.Context, id int64, lockUntil *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.FailedLogins++
	a.LockedUntil = lockUntil
	return nil
}

func (s *Store) RecordLoginSuccess(_ context.Context, id int64, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	a.FailedLogins = 0
	a.LockedUntil = nil
	a.LastLoginAt = &now
	a.LastLoginIP = ip
	return nil
}

func (s *Store) DeleteAdmin(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.admins[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.admins, id)
	for k, sess := range s.sessions {
		if sess.AdminID == id {
			delete(s.sessions, k)
		}
	}
	return nil
}

func (s *Store) SetAdminTOTP(_ context.Context, id int64, secret string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.TOTPSecret = secret
	a.TOTPBoundAt = &at
	a.TOTPLastStep = 0
	return nil
}

func (s *Store) ClearAdminTOTP(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.TOTPSecret = ""
	a.TOTPBoundAt = nil
	a.TOTPLastStep = 0
	return nil
}

func (s *Store) UpdateAdminTOTPStep(_ context.Context, id int64, step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.TOTPLastStep = step
	return nil
}

func (s *Store) SetAdminOAuth(_ context.Context, id int64, subject, email string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.OAuthSubject = subject
	a.OAuthEmail = email
	a.OAuthBoundAt = &at
	return nil
}

func (s *Store) ClearAdminOAuth(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[id]
	if !ok {
		return store.ErrNotFound
	}
	a.OAuthSubject = ""
	a.OAuthEmail = ""
	a.OAuthBoundAt = nil
	return nil
}

func (s *Store) CreateSession(_ context.Context, sess *store.AdminSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.ID = s.nextID()
	cp := *sess
	s.sessions[sess.TokenHash] = &cp
	return nil
}

func (s *Store) GetSession(_ context.Context, tokenHash string) (*store.AdminSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[tokenHash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *Store) TouchSession(_ context.Context, tokenHash string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[tokenHash]
	if !ok {
		return store.ErrNotFound
	}
	sess.LastSeenAt = at
	return nil
}

func (s *Store) DeleteSession(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[tokenHash]; !ok {
		return store.ErrNotFound
	}
	delete(s.sessions, tokenHash)
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, sess := range s.sessions {
		if sess.ExpiresAt.Before(before) {
			delete(s.sessions, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) AddAudit(_ context.Context, e *store.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = s.nextID()
	e.CreatedAt = time.Now()
	s.audits = append(s.audits, *e)
	return nil
}

func (s *Store) ListAudit(_ context.Context, limit int) ([]store.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.AuditEntry, 0, len(s.audits))
	for i := len(s.audits) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, s.audits[i])
	}
	return out, nil
}
