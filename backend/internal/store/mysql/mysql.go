// Package mysql 是 store.Store 的 MySQL 实现。
// 所有语句都用占位符；时间列要求 DSN 带 parseTime=true。
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

type Store struct {
	db *sql.DB
}

func Open(dsn string, maxOpen, maxIdle int, connMaxLifetime time.Duration) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败：%w", err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &Store{db: db}, nil
}

// DB 暴露底层连接给迁移逻辑用。
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Close() error { return s.db.Close() }

func isDup(err error) (string, bool) {
	var me *mysql.MySQLError
	if errors.As(err, &me) && me.Number == 1062 {
		// 1062 的 Message 形如：Duplicate entry 'x' for key 'votes.uk_votes_poll_ip'
		return me.Message, true
	}
	return "", false
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) ListPolls(ctx context.Context, statuses []string) ([]store.Poll, error) {
	q := `SELECT id, slug, title, summary, status, show_results, one_per_ip, starts_at, ends_at, created_by, created_at, updated_at FROM polls`
	var args []any
	if len(statuses) > 0 {
		q += " WHERE status IN (" + strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",") + ")"
		for _, st := range statuses {
			args = append(args, st)
		}
	}
	q += " ORDER BY created_at DESC, id DESC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Poll
	for rows.Next() {
		p, err := scanPoll(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanPoll(row scannable) (*store.Poll, error) {
	var (
		p                store.Poll
		starts, ends     sql.NullTime
		createdBy        sql.NullInt64
		created, updated time.Time
	)
	if err := row.Scan(&p.ID, &p.Slug, &p.Title, &p.Summary, &p.Status, &p.ShowResults,
		&p.OnePerIP, &starts, &ends, &createdBy, &created, &updated); err != nil {
		return nil, wrap(err)
	}
	if starts.Valid {
		t := starts.Time
		p.StartsAt = &t
	}
	if ends.Valid {
		t := ends.Time
		p.EndsAt = &t
	}
	if createdBy.Valid {
		id := createdBy.Int64
		p.CreatedBy = &id
	}
	p.CreatedAt, p.UpdatedAt = created, updated
	return &p, nil
}

const pollColumns = "id, slug, title, summary, status, show_results, one_per_ip, starts_at, ends_at, created_by, created_at, updated_at"

func (s *Store) GetPollBySlug(ctx context.Context, slug string) (*store.Poll, error) {
	return scanPoll(s.db.QueryRowContext(ctx, "SELECT "+pollColumns+" FROM polls WHERE slug = ?", slug))
}

func (s *Store) GetPoll(ctx context.Context, id int64) (*store.Poll, error) {
	return scanPoll(s.db.QueryRowContext(ctx, "SELECT "+pollColumns+" FROM polls WHERE id = ?", id))
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func (s *Store) CreatePoll(ctx context.Context, in store.PollInput, slug string, createdBy int64) (*store.Poll, error) {
	var creator any
	if createdBy > 0 {
		creator = createdBy
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO polls (slug, title, summary, status, show_results, one_per_ip, starts_at, ends_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		slug, in.Title, in.Summary, in.Status, in.ShowResults, in.OnePerIP, nullableTime(in.StartsAt), nullableTime(in.EndsAt), creator)
	if err != nil {
		if _, dup := isDup(err); dup {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.GetPoll(ctx, id)
}

func (s *Store) UpdatePoll(ctx context.Context, id int64, in store.PollInput) error {
	res, err := s.db.ExecContext(ctx, `UPDATE polls SET title=?, summary=?, status=?, show_results=?, one_per_ip=?, starts_at=?, ends_at=? WHERE id=?`,
		in.Title, in.Summary, in.Status, in.ShowResults, in.OnePerIP, nullableTime(in.StartsAt), nullableTime(in.EndsAt), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.GetPoll(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeletePoll(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM polls WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListQuestions(ctx context.Context, pollID int64) ([]store.Question, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, poll_id, position, type, title, hint, required, max_length, min_choices, max_choices
		FROM questions WHERE poll_id = ? ORDER BY position, id`, pollID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Question
	index := map[int64]int{}
	for rows.Next() {
		var q store.Question
		if err := rows.Scan(&q.ID, &q.PollID, &q.Position, &q.Type, &q.Title, &q.Hint,
			&q.Required, &q.MaxLength, &q.MinChoices, &q.MaxChoices); err != nil {
			return nil, err
		}
		index[q.ID] = len(out)
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	orows, err := s.db.QueryContext(ctx, `SELECT o.id, o.question_id, o.position, o.label
		FROM options o JOIN questions q ON q.id = o.question_id
		WHERE q.poll_id = ? ORDER BY o.question_id, o.position, o.id`, pollID)
	if err != nil {
		return nil, err
	}
	defer orows.Close()
	for orows.Next() {
		var o store.Option
		if err := orows.Scan(&o.ID, &o.QuestionID, &o.Position, &o.Label); err != nil {
			return nil, err
		}
		if i, ok := index[o.QuestionID]; ok {
			out[i].Options = append(out[i].Options, o)
		}
	}
	return out, orows.Err()
}

// ReplaceQuestions 会先删后插。注意：vote_answers 对 questions 是级联删除，
// 因此业务层必须保证"已有票的投票不允许改题目"，否则历史答案会被清掉。
func (s *Store) ReplaceQuestions(ctx context.Context, pollID int64, qs []store.QuestionInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE o FROM options o JOIN questions q ON q.id = o.question_id WHERE q.poll_id = ?`, pollID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM questions WHERE poll_id = ?", pollID); err != nil {
		return err
	}
	for i, in := range qs {
		res, err := tx.ExecContext(ctx, `INSERT INTO questions (poll_id, position, type, title, hint, required, max_length, min_choices, max_choices)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			pollID, i, in.Type, in.Title, in.Hint, in.Required, in.MaxLength, in.MinChoices, in.MaxChoices)
		if err != nil {
			return err
		}
		qid, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for j, label := range in.Options {
			if _, err := tx.ExecContext(ctx, "INSERT INTO options (question_id, position, label) VALUES (?, ?, ?)", qid, j, label); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) HasVoted(ctx context.Context, pollID int64, ip []byte) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM votes WHERE poll_id = ? AND ip = ?", pollID, ip).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) InsertVote(ctx context.Context, v *store.Vote, answers []store.Answer) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, "INSERT INTO votes (poll_id, ip, ip_text, ua_hash, receipt) VALUES (?, ?, ?, ?, ?)",
		v.PollID, v.IP, v.IPText, v.UAHash, v.Receipt)
	if err != nil {
		if msg, dup := isDup(err); dup {
			if strings.Contains(msg, "uk_votes_poll_ip") {
				return store.ErrDuplicateVote
			}
			return store.ErrConflict
		}
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for _, a := range answers {
		var choiceJSON, rankJSON any
		if len(a.Choices) > 0 {
			b, err := json.Marshal(a.Choices)
			if err != nil {
				return err
			}
			choiceJSON = string(b)
		}
		if len(a.Ranking) > 0 {
			b, err := json.Marshal(a.Ranking)
			if err != nil {
				return err
			}
			rankJSON = string(b)
		}
		text := a.Text
		if text == "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vote_answers (vote_id, question_id, text_value, choice_json, rank_json) VALUES (?, ?, NULL, ?, ?)`,
				id, a.QuestionID, choiceJSON, rankJSON); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vote_answers (vote_id, question_id, text_value, choice_json, rank_json) VALUES (?, ?, ?, ?, ?)`,
			id, a.QuestionID, text, choiceJSON, rankJSON); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	v.ID = id
	return nil
}

func (s *Store) CountVotes(ctx context.Context, pollID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM votes WHERE poll_id = ?", pollID).Scan(&n)
	return n, err
}

func (s *Store) ListAnswers(ctx context.Context, pollID int64) ([]store.Answer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.vote_id, a.question_id, a.text_value, a.choice_json, a.rank_json
		FROM vote_answers a JOIN votes v ON v.id = a.vote_id WHERE v.poll_id = ?`, pollID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Answer
	for rows.Next() {
		var (
			a          store.Answer
			text       sql.NullString
			choiceJSON sql.NullString
			rankJSON   sql.NullString
		)
		if err := rows.Scan(&a.VoteID, &a.QuestionID, &text, &choiceJSON, &rankJSON); err != nil {
			return nil, err
		}
		a.Text = text.String
		if choiceJSON.Valid && choiceJSON.String != "" {
			if err := json.Unmarshal([]byte(choiceJSON.String), &a.Choices); err != nil {
				return nil, fmt.Errorf("解析 choice_json 失败：%w", err)
			}
		}
		if rankJSON.Valid && rankJSON.String != "" {
			if err := json.Unmarshal([]byte(rankJSON.String), &a.Ranking); err != nil {
				return nil, fmt.Errorf("解析 rank_json 失败：%w", err)
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListVotes(ctx context.Context, pollID int64, limit int) ([]store.Vote, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, poll_id, ip, ip_text, ua_hash, receipt, created_at
		FROM votes WHERE poll_id = ? ORDER BY id DESC LIMIT ?`, pollID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Vote
	for rows.Next() {
		var v store.Vote
		if err := rows.Scan(&v.ID, &v.PollID, &v.IP, &v.IPText, &v.UAHash, &v.Receipt, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) CreateCaptcha(ctx context.Context, c *store.Captcha) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO captchas (id, ip, ip_text, answer_hash, attempts, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.IP, c.IPText, c.AnswerHash, c.Attempts, c.ExpiresAt)
	return err
}

func (s *Store) GetCaptcha(ctx context.Context, id string) (*store.Captcha, error) {
	var (
		c        store.Captcha
		consumed sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, ip, ip_text, answer_hash, attempts, created_at, expires_at, consumed_at
		FROM captchas WHERE id = ?`, id).
		Scan(&c.ID, &c.IP, &c.IPText, &c.AnswerHash, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &consumed)
	if err != nil {
		return nil, wrap(err)
	}
	c.Consumed = consumed.Valid
	return &c, nil
}

func (s *Store) IncrementCaptchaAttempts(ctx context.Context, id string) (int, error) {
	if _, err := s.db.ExecContext(ctx, "UPDATE captchas SET attempts = attempts + 1 WHERE id = ?", id); err != nil {
		return 0, err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT attempts FROM captchas WHERE id = ?", id).Scan(&n); err != nil {
		return 0, wrap(err)
	}
	return n, nil
}

func (s *Store) ConsumeCaptcha(ctx context.Context, id string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, "UPDATE captchas SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?",
		at, id, at)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) PurgeExpiredCaptchas(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM captchas WHERE expires_at < ?", before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) ListIPRules(ctx context.Context) ([]store.IPRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, network, prefix_len, note, expires_at, created_at
		FROM ip_rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.IPRule
	for rows.Next() {
		var (
			r       store.IPRule
			expires sql.NullTime
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.Network, &r.PrefixLen, &r.Note, &expires, &r.CreatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddIPRule(ctx context.Context, r *store.IPRule) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO ip_rules (kind, network, prefix_len, note, expires_at) VALUES (?, ?, ?, ?, ?)`,
		r.Kind, r.Network, r.PrefixLen, r.Note, nullableTime(r.ExpiresAt))
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	r.ID = id
	return nil
}

func (s *Store) DeleteIPRule(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM ip_rules WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

const adminColumns = "id, username, password_hash, display_name, is_active, failed_logins, locked_until, last_login_at, last_login_ip, created_at"

func scanAdmin(row scannable) (*store.Admin, error) {
	var (
		a                 store.Admin
		locked, lastLogin sql.NullTime
	)
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.DisplayName, &a.Active,
		&a.FailedLogins, &locked, &lastLogin, &a.LastLoginIP, &a.CreatedAt); err != nil {
		return nil, wrap(err)
	}
	if locked.Valid {
		t := locked.Time
		a.LockedUntil = &t
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		a.LastLoginAt = &t
	}
	return &a, nil
}

func (s *Store) GetAdminByUsername(ctx context.Context, username string) (*store.Admin, error) {
	return scanAdmin(s.db.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE username = ?", username))
}

func (s *Store) GetAdminByID(ctx context.Context, id int64) (*store.Admin, error) {
	return scanAdmin(s.db.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE id = ?", id))
}

func (s *Store) ListAdmins(ctx context.Context) ([]store.Admin, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+adminColumns+" FROM admins ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash, displayName string) (*store.Admin, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO admins (username, password_hash, display_name) VALUES (?, ?, ?)",
		username, passwordHash, displayName)
	if err != nil {
		if _, dup := isDup(err); dup {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.GetAdminByID(ctx, id)
}

func (s *Store) UpdateAdminPassword(ctx context.Context, id int64, hash string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE admins SET password_hash = ? WHERE id = ?", hash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) SetAdminActive(ctx context.Context, id int64, active bool) error {
	if _, err := s.db.ExecContext(ctx, "UPDATE admins SET is_active = ? WHERE id = ?", active, id); err != nil {
		return err
	}
	return nil
}

func (s *Store) RecordLoginFailure(ctx context.Context, id int64, lockUntil *time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE admins SET failed_logins = failed_logins + 1, locked_until = ? WHERE id = ?",
		nullableTime(lockUntil), id)
	return err
}

func (s *Store) RecordLoginSuccess(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE admins SET failed_logins = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = ? WHERE id = ?",
		ip, id)
	return err
}

func (s *Store) DeleteAdmin(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM admins WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, sess *store.AdminSession) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions (token_hash, admin_id, ip, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.AdminID, sess.IP, sess.UserAgent, sess.ExpiresAt)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	sess.ID = id
	return nil
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (*store.AdminSession, error) {
	var sess store.AdminSession
	err := s.db.QueryRowContext(ctx, `SELECT id, admin_id, token_hash, ip, user_agent, created_at, last_seen_at, expires_at
		FROM admin_sessions WHERE token_hash = ?`, tokenHash).
		Scan(&sess.ID, &sess.AdminID, &sess.TokenHash, &sess.IP, &sess.UserAgent, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt)
	if err != nil {
		return nil, wrap(err)
	}
	return &sess, nil
}

func (s *Store) TouchSession(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?", at, tokenHash)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash = ?", tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires_at < ?", before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) AddAudit(ctx context.Context, e *store.AuditEntry) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (actor, action, target, ip_text, detail) VALUES (?, ?, ?, ?, ?)`,
		e.Actor, e.Action, e.Target, e.IPText, e.Detail)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	e.ID = id
	return nil
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, actor, action, target, ip_text, COALESCE(detail, ''), created_at
		FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AuditEntry
	for rows.Next() {
		var e store.AuditEntry
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.IPText, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
