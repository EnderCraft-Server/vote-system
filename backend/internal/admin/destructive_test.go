package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

// mockProvider 起一个最小的 OAuth2 提供方：token 换 access_token，userinfo 返回 sub/email。
type mockProvider struct {
	srv      *httptest.Server
	subject  string
	email    string
	codeUsed bool
}

func newMockProvider(t *testing.T) *mockProvider {
	t.Helper()
	m := &mockProvider{subject: "sso-user-1", email: "alice@example.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("code") == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		m.codeUsed = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + m.subject, "token_type": "Bearer"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-"+m.subject {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": m.subject, "email": m.email})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		u := q.Get("redirect_uri") + "?code=test-code&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, u, http.StatusFound)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockProvider) configure(cfg *config.Config) {
	cfg.OAuth.Enabled = true
	cfg.OAuth.AuthorizeURL = m.srv.URL + "/authorize"
	cfg.OAuth.TokenURL = m.srv.URL + "/token"
	cfg.OAuth.UserinfoURL = m.srv.URL + "/userinfo"
	cfg.OAuth.ClientID = "vote-admin"
	cfg.OAuth.ClientSecret = "secret"
	cfg.OAuth.RedirectURI = "http://admin.local/oauth/callback"
	cfg.OAuth.SubjectField = "sub"
	cfg.OAuth.EmailField = "email"
	cfg.OAuth.PendingTTL = config.Duration{Duration: 5 * time.Minute}
}

func newOAuthTestServer(t *testing.T) (*Server, *memory.Store, *mockProvider) {
	t.Helper()
	cfg := config.Default()
	cfg.Env = "development"
	cfg.Security.RPCSecret = strings.Repeat("z", 48)
	cfg.Security.AdminBcryptCost = 10
	cfg.Security.AdminCookieSecure = false
	cfg.Captcha.Enabled = false
	cfg.Captcha.Pow.Enabled = false
	mp := newMockProvider(t)
	mp.configure(cfg)
	st := memory.New()
	hash, err := bcrypt.GenerateFromPassword([]byte("DevPassw0rd!"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAdmin(context.Background(), "admin", string(hash), ""); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, vote.New(st, cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, mp
}

func stateOf(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("解析跳转地址失败：%v", err)
	}
	if !strings.Contains(u.Host, "127.0.0.1") {
		t.Fatalf("应跳转到 mock provider，实际 %s", loc)
	}
	return u.Query().Get("state")
}

var voteKeySeq uint64

func seedVotes(t *testing.T, st store.Store, pollID int64, ipStr string, n int) {
	t.Helper()
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		t.Fatal(err)
	}
	b := addr.As16()
	for i := 0; i < n; i++ {
		seq := atomic.AddUint64(&voteKeySeq, 1)
		v := &store.Vote{PollID: pollID, IP: b[:], IPKey: []byte(fmt.Sprintf("k-%d", seq)), IPText: ipStr,
			Receipt: fmt.Sprintf("PT%06d", seq)}
		if err := st.InsertVote(context.Background(), v, nil); err != nil {
			t.Fatalf("插入票失败：%v", err)
		}
	}
}

func TestOAuthBindThenDeleteByIP(t *testing.T) {
	srv, st, mp := newOAuthTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()

	// 未绑定：危险页给出引导
	rec := do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	if !strings.Contains(rec.Body.String(), "还没有绑定外部身份") {
		t.Fatalf("应提示未绑定")
	}

	// 绑定：POST 拿到跳转，回调完成绑定
	rec = do(t, h, "GET", "/account/oauth", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/account/oauth/bind", url.Values{"csrf": {csrf}}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("应跳转到 provider，得到 %d", rec.Code)
	}
	state := stateOf(t, rec.Header().Get("Location"))
	rec = do(t, h, "GET", "/oauth/callback?code=abc&state="+state, nil, nil, false)
	if !strings.Contains(rec.Body.String(), "已完成绑定") {
		t.Fatalf("绑定应成功：%s", rec.Body.String())
	}
	admin, _ := st.GetAdminByUsername(context.Background(), "admin")
	if admin.OAuthSubject != mp.subject || admin.OAuthEmail != mp.email {
		t.Fatalf("绑定信息不对：%+v", admin)
	}

	// 造一批票，然后按 IP 删除
	p, err := st.CreatePoll(context.Background(), store.PollInput{Title: "刷票", Status: "open", ShowResults: "always"}, "spam", 0)
	if err != nil {
		t.Fatal(err)
	}
	seedVotes(t, st, p.ID, "203.0.113.9", 3)
	seedVotes(t, st, p.ID, "203.0.113.10", 1)

	rec = do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	csrf = csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/super/danger/delete-ip", url.Values{
		"csrf": {csrf}, "poll_id": {fmt.Sprint(p.ID)}, "ip": {"203.0.113.9"}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("应跳转授权，得到 %d", rec.Code)
	}
	state = stateOf(t, rec.Header().Get("Location"))

	// 未授权前不能删
	if n, _ := st.CountVotes(context.Background(), p.ID); n != 4 {
		t.Fatalf("回调前不应删除，剩余 %d", n)
	}

	rec = do(t, h, "GET", "/oauth/callback?code=abc&state="+state, nil, nil, false)
	if !strings.Contains(rec.Body.String(), "已删除") {
		t.Fatalf("应删除成功：%s", rec.Body.String())
	}
	if n, _ := st.CountVotes(context.Background(), p.ID); n != 1 {
		t.Fatalf("应只删掉该 IP 的 3 票，剩余 %d", n)
	}
	logs, _ := st.ListAudit(context.Background(), 5)
	found := false
	for _, l := range logs {
		if l.Action == "votes_deleted_by_ip" && strings.Contains(l.Detail, "删除票数=3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少审计：%+v", logs)
	}

	// 同一个 state 再用一次 → 拒绝
	rec = do(t, h, "GET", "/oauth/callback?code=abc&state="+state, nil, nil, false)
	if !strings.Contains(rec.Body.String(), "已过期或已被使用") {
		t.Fatalf("state 重放应被拒：%s", rec.Body.String())
	}
}

func TestOAuthSubjectMismatchRejected(t *testing.T) {
	srv, st, mp := newOAuthTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	admin, _ := st.GetAdminByUsername(context.Background(), "admin")
	if err := st.SetAdminOAuth(context.Background(), admin.ID, "someone-else", "x@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	p, _ := st.CreatePoll(context.Background(), store.PollInput{Title: "x", Status: "open", ShowResults: "always"}, "x1", 0)
	seedVotes(t, st, p.ID, "198.51.100.5", 2)

	rec := do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/super/danger/delete-poll", url.Values{
		"csrf": {csrf}, "poll_id": {fmt.Sprint(p.ID)}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	state := stateOf(t, rec.Header().Get("Location"))
	rec = do(t, h, "GET", "/oauth/callback?code=abc&state="+state, nil, nil, false)
	if !strings.Contains(rec.Body.String(), "不一致") {
		t.Fatalf("身份不一致应拒绝：%s", rec.Body.String())
	}
	if _, err := st.GetPoll(context.Background(), p.ID); err != nil {
		t.Fatal("身份不一致时不应删除投票")
	}
	logs, _ := st.ListAudit(context.Background(), 3)
	if logs[0].Action != "oauth_subject_mismatch" {
		t.Fatalf("应记录 mismatch 审计：%+v", logs[0])
	}
	_ = mp
}

func TestDeletePollWithVotesViaOAuth(t *testing.T) {
	srv, st, mp := newOAuthTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	admin, _ := st.GetAdminByUsername(context.Background(), "admin")
	if err := st.SetAdminOAuth(context.Background(), admin.ID, mp.subject, mp.email, time.Now()); err != nil {
		t.Fatal(err)
	}
	p, _ := st.CreatePoll(context.Background(), store.PollInput{Title: "待删", Status: "open", ShowResults: "always"}, "del1", 0)
	seedVotes(t, st, p.ID, "198.51.100.6", 2)

	rec := do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/super/danger/delete-poll", url.Values{
		"csrf": {csrf}, "poll_id": {fmt.Sprint(p.ID)}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	state := stateOf(t, rec.Header().Get("Location"))
	rec = do(t, h, "GET", "/oauth/callback?code=abc&state="+state, nil, nil, false)
	if !strings.Contains(rec.Body.String(), "已删除投票") {
		t.Fatalf("应删除成功：%s", rec.Body.String())
	}
	if _, err := st.GetPoll(context.Background(), p.ID); err == nil {
		t.Fatal("投票应已删除")
	}
	logs, _ := st.ListAudit(context.Background(), 3)
	if logs[0].Action != "poll_deleted_with_votes" || !strings.Contains(logs[0].Detail, "删除前票数=2") {
		t.Fatalf("审计不对：%+v", logs[0])
	}
}
