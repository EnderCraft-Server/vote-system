// Package admin 是后台管理界面：独立端口、独立会话，与前台没有任何共享状态。
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

const sessionCookie = "vote_admin_session"

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg   *config.Config
	st    store.Store
	svc   *vote.Service
	log   *slog.Logger
	tpl   *template.Template
	now   func() time.Time
	httpS *http.Server

	mu       sync.Mutex
	attempts map[string]*loginAttempt

	pendingMu sync.Mutex
	pending   map[string]*pendingAction
}

type loginAttempt struct {
	count int
	last  time.Time
}

func New(cfg *config.Config, st store.Store, svc *vote.Service, log *slog.Logger) (*Server, error) {
	tpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, st: st, svc: svc, log: log,
		tpl: tpl, now: time.Now,
		attempts: make(map[string]*loginAttempt),
		pending:  make(map[string]*pendingAction),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.auth(s.handleLogout))

	mux.HandleFunc("GET /{$}", s.auth(s.handleDashboard))

	mux.HandleFunc("GET /polls/new", s.auth(s.handlePollForm))
	mux.HandleFunc("GET /polls/{id}", s.auth(s.handlePollForm))
	mux.HandleFunc("POST /polls", s.auth(s.handlePollSave))
	mux.HandleFunc("POST /polls/{id}", s.auth(s.handlePollSave))
	mux.HandleFunc("POST /polls/{id}/status", s.auth(s.handlePollStatus))
	mux.HandleFunc("POST /polls/{id}/delete", s.auth(s.handlePollDelete))
	mux.HandleFunc("GET /polls/{id}/results", s.auth(s.handleResults))

	mux.HandleFunc("GET /ip-rules", s.auth(s.handleIPRules))
	mux.HandleFunc("POST /ip-rules", s.auth(s.handleIPRuleAdd))
	mux.HandleFunc("POST /ip-rules/{id}/delete", s.auth(s.handleIPRuleDelete))

	mux.HandleFunc("GET /audit", s.auth(s.handleAudit))
	mux.HandleFunc("GET /account", s.auth(s.handleAccount))
	mux.HandleFunc("GET /account/oauth", s.auth(s.handleOAuthAccount))
	mux.HandleFunc("POST /account/oauth/bind", s.auth(s.handleOAuthBindStart))
	mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

	mux.HandleFunc("GET /super/danger", s.auth(s.handleDanger))
	mux.HandleFunc("POST /super/danger/delete-ip", s.auth(s.handleDeleteByIP))
	mux.HandleFunc("POST /super/danger/delete-poll", s.auth(s.handleDeletePoll))
	mux.HandleFunc("POST /account/password", s.auth(s.handlePasswordChange))
	mux.HandleFunc("GET /admins", s.auth(s.handleAdmins))
	mux.HandleFunc("POST /admins", s.auth(s.handleAdminCreate))
	mux.HandleFunc("POST /admins/{id}/toggle", s.auth(s.handleAdminToggle))
	mux.HandleFunc("POST /admins/{id}/delete", s.auth(s.handleAdminDelete))

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(mustSub(staticFS, "static"))))

	return s.chain(mux)
}

func mustSub(fsys embed.FS, dir string) http.FileSystem {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

// chain：panic 兜底 → 安全响应头 → 管理端 IP 白名单。
func (s *Server) chain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("管理界面 panic", "panic", rec, "path", r.URL.Path)
				http.Error(w, "服务器内部错误", http.StatusInternalServerError)
			}
		}()

		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")

		if !s.allowedByCIDR(r) {
			s.log.Warn("管理界面拒绝非白名单来源", "remote", clientIP(r))
			http.Error(w, "来源不在允许范围内", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedByCIDR(r *http.Request) bool {
	if len(s.cfg.Server.AdminAllowedCIDRs) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return false
	}
	for _, raw := range s.cfg.Server.AdminAllowedCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if p.Contains(addr) || (addr.Is4In6() && p.Contains(addr.Unmap())) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ---------- 渲染 ----------

type pageData struct {
	Title  string
	Nav    string
	Admin  *store.Admin
	CSRF   string
	Flash  string
	Error  string
	Data   any
	Now    time.Time
	IsProd bool
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data pageData) {
	data.Now = s.now()
	data.IsProd = s.cfg.IsProduction()
	if data.Nav == "" {
		data.Nav = page
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, page+".html", data); err != nil {
		s.log.Error("渲染模板失败", "page", page, "err", err)
	}
}

func (s *Server) flashRedirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	// 用一次性查询参数传递提示，避免引入服务端 flash 存储
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	http.Redirect(w, r, path+sep+"ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, page string, status int, msg string, data pageData) {
	w.WriteHeader(status)
	data.Error = msg
	s.render(w, r, page, data)
}

// ---------- 会话 ----------

func (s *Server) currentSession(r *http.Request) (*store.AdminSession, *store.Admin, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil, errors.New("no session")
	}
	hash := tokenHash(c.Value)
	sess, err := s.st.GetSession(r.Context(), hash)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.cfg.Security.AdminIdleTimeout.Duration {
		_ = s.st.DeleteSession(r.Context(), hash)
		return nil, nil, errors.New("session expired")
	}
	admin, err := s.st.GetAdminByID(r.Context(), sess.AdminID)
	if err != nil || !admin.Active {
		return nil, nil, errors.New("admin inactive")
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.st.TouchSession(r.Context(), hash, now)
	}
	return sess, admin, nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) csrfToken(session *store.AdminSession) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Security.RPCSecret))
	mac.Write([]byte("csrf|"))
	mac.Write([]byte(session.TokenHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// anonCSRF 给登录页用：不依赖会话，按 IP + 当天签发，防止登录 CSRF。
func (s *Server) anonCSRF(ip string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Security.RPCSecret))
	mac.Write([]byte("anon|"))
	mac.Write([]byte(ip))
	mac.Write([]byte("|"))
	mac.Write([]byte(s.now().Format("2006-01-02")))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) checkCSRF(r *http.Request, want string) bool {
	got := r.PostFormValue("csrf")
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

type ctxKey struct{}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, admin, err := s.currentSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, admin)))
	}
}

func adminFrom(r *http.Request) *store.Admin {
	if v, ok := r.Context().Value(ctxKey{}).(*store.Admin); ok {
		return v
	}
	return nil
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	admin := adminFrom(r)
	actor := "anonymous"
	if admin != nil {
		actor = admin.Username
	}
	if err := s.st.AddAudit(r.Context(), &store.AuditEntry{
		Actor: actor, Action: action, Target: target, IPText: clientIP(r), Detail: detail,
	}); err != nil {
		s.log.Warn("写审计日志失败", "action", action, "err", err)
	}
}

// ---------- 登录 ----------

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.currentSession(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", pageData{
		Title: "登录", Nav: "login",
		CSRF: s.anonCSRF(clientIP(r)),
		Data: map[string]any{"Next": r.URL.Query().Get("next")},
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, "login", http.StatusBadRequest, "请求格式不正确", pageData{Title: "登录"})
		return
	}
	ip := clientIP(r)
	if !s.checkCSRF(r, s.anonCSRF(ip)) {
		s.fail(w, r, "login", http.StatusBadRequest, "页面已过期，请重新打开登录页", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	if username == "" || password == "" {
		s.fail(w, r, "login", http.StatusBadRequest, "请输入用户名和密码", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	if !s.loginAllowed(ip) {
		s.fail(w, r, "login", http.StatusTooManyRequests, "尝试次数过多，请稍后再试", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	s.recordAttempt(ip)

	admin, err := s.st.GetAdminByUsername(r.Context(), username)
	if err != nil || !admin.Active {
		// 无论用户是否存在都返回同一句话，避免枚举账号
		s.fail(w, r, "login", http.StatusUnauthorized, "用户名或密码不正确", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	now := s.now()
	if admin.LockedUntil != nil && now.Before(*admin.LockedUntil) {
		s.fail(w, r, "login", http.StatusUnauthorized, "该账号已被临时锁定，请稍后再试", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		next := admin.FailedLogins + 1
		var lock *time.Time
		if next >= s.cfg.Security.AdminLoginMaxAttempt {
			t := now.Add(s.cfg.Security.AdminLoginLockout.Duration)
			lock = &t
		}
		_ = s.st.RecordLoginFailure(r.Context(), admin.ID, lock)
		s.log.Warn("管理端登录失败", "username", username, "ip", ip, "failed", next)
		s.st.AddAudit(r.Context(), &store.AuditEntry{Actor: username, Action: "login_failed", Target: "admin", IPText: ip,
			Detail: fmt.Sprintf("失败次数 %d", next)})
		s.fail(w, r, "login", http.StatusUnauthorized, "用户名或密码不正确", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}

	_ = s.st.RecordLoginSuccess(r.Context(), admin.ID, ip)
	_, _ = s.st.DeleteExpiredSessions(r.Context(), now)

	token := randomHex(32)
	if err := s.st.CreateSession(r.Context(), &store.AdminSession{
		TokenHash: tokenHash(token), AdminID: admin.ID, IP: ip,
		UserAgent: truncate(r.UserAgent(), 255),
		CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(s.cfg.Security.AdminSessionTTL.Duration),
	}); err != nil {
		s.log.Error("创建会话失败", "err", err)
		s.fail(w, r, "login", http.StatusInternalServerError, "登录失败，请稍后再试", pageData{Title: "登录", CSRF: s.anonCSRF(ip)})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: s.cfg.Security.AdminCookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.cfg.Security.AdminSessionTTL.Duration.Seconds()),
	})
	ctx := context.WithValue(r.Context(), ctxKey{}, admin)
	s.audit(r.WithContext(ctx), "login", "admin:"+strconv.FormatInt(admin.ID, 10), "登录成功")
	s.flashRedirect(w, r, "/", "欢迎回来，"+admin.Username)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _, err := s.currentSession(r)
	if err == nil {
		_ = s.st.DeleteSession(r.Context(), sess.TokenHash)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.cfg.Security.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	s.audit(r, "logout", "admin", "退出登录")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) loginAllowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[ip]
	if !ok {
		return true
	}
	if s.now().Sub(a.last) > 10*time.Minute {
		delete(s.attempts, ip)
		return true
	}
	return a.count < 20
}

func (s *Server) recordAttempt(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[ip]
	if !ok || s.now().Sub(a.last) > 10*time.Minute {
		a = &loginAttempt{}
		s.attempts[ip] = a
	}
	a.count++
	a.last = s.now()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用：" + err.Error())
	}
	return hex.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------- 仪表盘 ----------

type pollRow struct {
	Poll      store.Poll
	VoteCount int
	Questions int
	IsOpen    bool
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	polls, err := s.st.ListPolls(r.Context(), nil)
	if err != nil {
		s.fail(w, r, "dashboard", http.StatusInternalServerError, "读取投票列表失败", pageData{Title: "投票", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	rows := make([]pollRow, 0, len(polls))
	now := s.now()
	totalVotes := 0
	for _, p := range polls {
		c, _ := s.st.CountVotes(r.Context(), p.ID)
		qs, _ := s.st.ListQuestions(r.Context(), p.ID)
		totalVotes += c
		rows = append(rows, pollRow{Poll: p, VoteCount: c, Questions: len(qs), IsOpen: p.IsOpenAt(now)})
	}
	audits, _ := s.st.ListAudit(r.Context(), 8)
	s.render(w, r, "dashboard", pageData{
		Title: "投票", Nav: "dashboard", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data: map[string]any{
			"Polls": rows, "TotalVotes": totalVotes, "RecentAudit": audits,
		},
	})
}

// csrfFor 从 cookie 反推会话签名令牌；取不到时返回空串（表单会因此被拒绝，属于预期）。
func (s *Server) csrfFor(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return s.csrfToken(&store.AdminSession{TokenHash: tokenHash(c.Value)})
}

// ---------- 投票编辑 ----------

type pollFormData struct {
	Poll          *store.Poll
	QuestionsJSON string
	HasVotes      bool
}

func (s *Server) handlePollForm(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	var (
		p   *store.Poll
		qs  []store.Question
		err error
	)
	if idStr := r.PathValue("id"); idStr != "" {
		id, perr := strconv.ParseInt(idStr, 10, 64)
		if perr != nil {
			http.NotFound(w, r)
			return
		}
		p, err = s.st.GetPoll(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		qs, err = s.st.ListQuestions(r.Context(), p.ID)
		if err != nil {
			s.fail(w, r, "dashboard", http.StatusInternalServerError, "读取题目失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
			return
		}
	}
	hasVotes := false
	if p != nil {
		if c, _ := s.st.CountVotes(r.Context(), p.ID); c > 0 {
			hasVotes = true
		}
	}
	title := "新建投票"
	if p != nil {
		title = "编辑：" + p.Title
	}
	s.render(w, r, "poll_form", pageData{
		Title: title, Nav: "dashboard", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data:  pollFormData{Poll: p, HasVotes: hasVotes, QuestionsJSON: storedQuestionsJSON(qs)},
	})
}

func (s *Server) handlePollSave(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, "poll_form", http.StatusBadRequest, "表单数据过大或格式错误", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	if !s.checkCSRF(r, s.csrfFor(r)) {
		s.fail(w, r, "poll_form", http.StatusBadRequest, "页面已过期，请刷新后重试", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}

	var pollID int64
	if idStr := r.PathValue("id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		pollID = id
	}

	in, qs, problems := parsePollForm(r)
	var existing *store.Poll
	if pollID > 0 {
		existing, _ = s.st.GetPoll(r.Context(), pollID)
		if existing == nil {
			http.NotFound(w, r)
			return
		}
	}
	if existing != nil {
		if c, _ := s.st.CountVotes(r.Context(), existing.ID); c > 0 && len(qs) > 0 {
			// 已有票时题目只读（页面已禁用），这里再兜一层，避免手工构造请求改坏历史答案
			cur, _ := s.st.ListQuestions(r.Context(), existing.ID)
			if questionsDiffer(cur, qs) {
				problems = append(problems, "该投票已有投票记录，不能再修改题目")
			}
		}
	}

	if len(problems) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "poll_form", pageData{
			Title: "编辑投票", Nav: "dashboard", Admin: admin, CSRF: s.csrfFor(r),
			Error: strings.Join(problems, "；"),
			Data:  pollFormData{Poll: existing, HasVotes: existing != nil, QuestionsJSON: inputQuestionsJSON(qs)},
		})
		return
	}

	if existing == nil {
		slug, err := s.uniqueSlug(r.Context())
		if err != nil {
			s.fail(w, r, "poll_form", http.StatusInternalServerError, "生成投票标识失败", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
			return
		}
		p, err := s.st.CreatePoll(r.Context(), in, slug, admin.ID)
		if err != nil {
			s.log.Error("创建投票失败", "err", err)
			s.fail(w, r, "poll_form", http.StatusInternalServerError, "保存失败，请稍后再试", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
			return
		}
		if err := s.st.ReplaceQuestions(r.Context(), p.ID, qs); err != nil {
			s.log.Error("写入题目失败", "err", err)
			s.fail(w, r, "poll_form", http.StatusInternalServerError, "保存题目失败，请稍后再试", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
			return
		}
		s.audit(r, "poll_create", "poll:"+strconv.FormatInt(p.ID, 10), p.Title)
		s.flashRedirect(w, r, "/polls/"+strconv.FormatInt(p.ID, 10), "已创建")
		return
	}

	if err := s.st.UpdatePoll(r.Context(), existing.ID, in); err != nil {
		s.log.Error("更新投票失败", "err", err)
		s.fail(w, r, "poll_form", http.StatusInternalServerError, "保存失败，请稍后再试", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	hasVotes := false
	if c, _ := s.st.CountVotes(r.Context(), existing.ID); c > 0 {
		hasVotes = true
	}
	if !hasVotes {
		if err := s.st.ReplaceQuestions(r.Context(), existing.ID, qs); err != nil {
			s.log.Error("更新题目失败", "err", err)
			s.fail(w, r, "poll_form", http.StatusInternalServerError, "保存题目失败，请稍后再试", pageData{Title: "编辑投票", Admin: admin, CSRF: s.csrfFor(r)})
			return
		}
	}
	s.audit(r, "poll_update", "poll:"+strconv.FormatInt(existing.ID, 10), existing.Title)
	s.flashRedirect(w, r, "/polls/"+strconv.FormatInt(existing.ID, 10), "已保存")
}

func (s *Server) handlePollStatus(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	p, err := s.st.GetPoll(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	status := r.PostFormValue("status")
	if status != "draft" && status != "open" && status != "closed" {
		http.Error(w, "状态不合法", http.StatusBadRequest)
		return
	}
	in := store.PollInput{
		Title: p.Title, Summary: p.Summary, Status: status, ShowResults: p.ShowResults,
		OnePerIP: p.OnePerIP, StartsAt: p.StartsAt, EndsAt: p.EndsAt,
	}
	if err := s.st.UpdatePoll(r.Context(), p.ID, in); err != nil {
		s.log.Error("更新投票状态失败", "err", err)
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}
	s.audit(r, "poll_status", "poll:"+strconv.FormatInt(p.ID, 10), status)
	s.flashRedirect(w, r, "/", "状态已更新："+statusZh(status))
	_ = admin
}

func (s *Server) handlePollDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if c, _ := s.st.CountVotes(r.Context(), id); c > 0 {
		s.flashRedirect(w, r, "/super/danger", "该投票已有 "+strconv.Itoa(c)+" 票，需要到「危险操作」页用动态验证码删除")
		return
	}
	if err := s.st.DeletePoll(r.Context(), id); err != nil {
		s.log.Error("删除投票失败", "err", err)
		s.flashRedirect(w, r, "/", "删除失败")
		return
	}
	s.audit(r, "poll_delete", "poll:"+strconv.FormatInt(id, 10), "")
	s.flashRedirect(w, r, "/", "已删除")
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.st.GetPoll(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	res, err := s.svc.AdminResults(r.Context(), p.Slug)
	if err != nil {
		s.log.Error("读取结果失败", "err", err)
		s.fail(w, r, "dashboard", http.StatusInternalServerError, "读取结果失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	votes, _ := s.st.ListVotes(r.Context(), p.ID, 100)
	ipStats, _ := s.st.PollIPStats(r.Context(), p.ID, 50)
	s.render(w, r, "results", pageData{
		Title: "结果：" + p.Title, Nav: "dashboard", Admin: admin, CSRF: s.csrfFor(r),
		Data: map[string]any{"Poll": p, "Result": res, "Votes": votes, "IPStats": ipStats},
	})
}

// ---------- IP 规则 ----------

func (s *Server) handleIPRules(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	rules, err := s.st.ListIPRules(r.Context())
	if err != nil {
		s.fail(w, r, "ip_rules", http.StatusInternalServerError, "读取规则失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	s.render(w, r, "ip_rules", pageData{
		Title: "IP 规则", Nav: "ip", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data:  map[string]any{"Rules": rules, "DefaultAction": s.cfg.Limits.IPDefaultAction},
	})
}

func (s *Server) handleIPRuleAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.PostFormValue("cidr"))
	kind := r.PostFormValue("kind")
	note := strings.TrimSpace(r.PostFormValue("note"))
	if kind != "block" && kind != "allow" {
		s.flashRedirect(w, r, "/ip-rules", "类型只能是拦截或放行")
		return
	}
	var network []byte
	var prefixLen int
	if p, err := netip.ParsePrefix(raw); err == nil {
		a := p.Masked().Addr().As16()
		network = a[:]
		prefixLen = p.Bits()
		if p.Addr().Is4() {
			prefixLen += 96
		}
	} else if a, err := netip.ParseAddr(raw); err == nil {
		b := a.As16()
		network = b[:]
		prefixLen = 128
	} else {
		s.flashRedirect(w, r, "/ip-rules", "请填写 IP 或 CIDR，例如 203.0.113.7 或 10.0.0.0/8")
		return
	}
	if len(note) > 200 {
		note = note[:200]
	}
	if err := s.st.AddIPRule(r.Context(), &store.IPRule{Kind: kind, Network: network, PrefixLen: prefixLen, Note: note}); err != nil {
		s.log.Error("新增 IP 规则失败", "err", err)
		s.flashRedirect(w, r, "/ip-rules", "保存失败")
		return
	}
	s.audit(r, "ip_rule_add", kind+":"+raw, note)
	s.flashRedirect(w, r, "/ip-rules", "已添加")
}

func (s *Server) handleIPRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if err := s.st.DeleteIPRule(r.Context(), id); err != nil {
		s.flashRedirect(w, r, "/ip-rules", "删除失败")
		return
	}
	s.audit(r, "ip_rule_delete", "ip_rule:"+strconv.FormatInt(id, 10), "")
	s.flashRedirect(w, r, "/ip-rules", "已删除")
}

// ---------- 审计 ----------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	logs, err := s.st.ListAudit(r.Context(), 300)
	if err != nil {
		s.fail(w, r, "audit", http.StatusInternalServerError, "读取审计日志失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	s.render(w, r, "audit", pageData{Title: "审计日志", Nav: "audit", Admin: admin, CSRF: s.csrfFor(r),
		Data: map[string]any{"Logs": logs}})
}

// ---------- 账号 ----------

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	s.render(w, r, "account", pageData{Title: "账号", Nav: "account", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok")})
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	current := r.PostFormValue("current")
	next := r.PostFormValue("next")
	confirm := r.PostFormValue("confirm")
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(current)); err != nil {
		s.render(w, r, "account", pageData{Title: "账号", Nav: "account", Admin: admin, CSRF: s.csrfFor(r), Error: "当前密码不正确"})
		return
	}
	if len(next) < 12 {
		s.render(w, r, "account", pageData{Title: "账号", Nav: "account", Admin: admin, CSRF: s.csrfFor(r), Error: "新密码至少 12 位"})
		return
	}
	if next != confirm {
		s.render(w, r, "account", pageData{Title: "账号", Nav: "account", Admin: admin, CSRF: s.csrfFor(r), Error: "两次输入的新密码不一致"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), s.cfg.Security.AdminBcryptCost)
	if err != nil {
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	if err := s.st.UpdateAdminPassword(r.Context(), admin.ID, string(hash)); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}
	s.audit(r, "password_change", "admin:"+strconv.FormatInt(admin.ID, 10), "")
	s.flashRedirect(w, r, "/account", "密码已更新")
}

// ---------- 管理员 ----------

func (s *Server) handleAdmins(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	list, err := s.st.ListAdmins(r.Context())
	if err != nil {
		s.fail(w, r, "admins", http.StatusInternalServerError, "读取管理员失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	s.render(w, r, "admins", pageData{Title: "管理员", Nav: "admins", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"), Data: map[string]any{"Admins": list}})
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	display := strings.TrimSpace(r.PostFormValue("display_name"))
	if !validUsername(username) {
		s.render(w, r, "admins", pageData{Title: "管理员", Nav: "admins", Admin: admin, CSRF: s.csrfFor(r),
			Error: "用户名需 3~32 位，且只允许字母、数字、下划线", Data: map[string]any{"Admins": nil}})
		return
	}
	if len(password) < 12 {
		s.render(w, r, "admins", pageData{Title: "管理员", Nav: "admins", Admin: admin, CSRF: s.csrfFor(r),
			Error: "初始密码至少 12 位"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.Security.AdminBcryptCost)
	if err != nil {
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	if _, err := s.st.CreateAdmin(r.Context(), username, string(hash), display); err != nil {
		s.render(w, r, "admins", pageData{Title: "管理员", Nav: "admins", Admin: admin, CSRF: s.csrfFor(r),
			Error: "创建失败，用户名可能已存在"})
		return
	}
	s.audit(r, "admin_create", "admin:"+username, "")
	s.flashRedirect(w, r, "/admins", "已创建")
}

func (s *Server) handleAdminToggle(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if id == admin.ID {
		s.flashRedirect(w, r, "/admins", "不能停用自己的账号")
		return
	}
	target, err := s.st.GetAdminByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.st.SetAdminActive(r.Context(), id, !target.Active); err != nil {
		s.flashRedirect(w, r, "/admins", "操作失败")
		return
	}
	s.audit(r, "admin_toggle", "admin:"+strconv.FormatInt(id, 10), target.Username)
	s.flashRedirect(w, r, "/admins", "已更新")
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if id == admin.ID {
		s.flashRedirect(w, r, "/admins", "不能删除自己的账号")
		return
	}
	list, _ := s.st.ListAdmins(r.Context())
	if len(list) <= 1 {
		s.flashRedirect(w, r, "/admins", "至少要保留一个管理员")
		return
	}
	if err := s.st.DeleteAdmin(r.Context(), id); err != nil {
		s.flashRedirect(w, r, "/admins", "删除失败")
		return
	}
	s.audit(r, "admin_delete", "admin:"+strconv.FormatInt(id, 10), "")
	s.flashRedirect(w, r, "/admins", "已删除")
}

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func (s *Server) uniqueSlug(ctx context.Context) (string, error) {
	for i := 0; i < 8; i++ {
		slug := strings.ToLower(randomHex(6))
		if _, err := s.st.GetPollBySlug(ctx, slug); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return slug, nil
			}
			return "", err
		}
	}
	return "", errors.New("无法生成唯一的投票标识")
}

// ---------- 生命周期 ----------

// Serve 在给定 listener 上运行，便于优雅关闭与测试。
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.httpS = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	srv := s.httpS
	s.mu.Unlock()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpS == nil {
		return nil
	}
	return s.httpS.Shutdown(ctx)
}
