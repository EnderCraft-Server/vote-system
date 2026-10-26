package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

func newTestServer(t *testing.T) (*Server, *memory.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.Env = "development"
	cfg.Security.RPCSecret = strings.Repeat("z", 48)
	cfg.Security.AdminBcryptCost = 10
	cfg.Security.AdminCookieSecure = false
	cfg.Captcha.Enabled = false
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
	return srv, st
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if len(m) < 2 {
		t.Fatal("页面里没有 csrf 字段")
	}
	return m[1]
}

func do(t *testing.T, h http.Handler, method, path string, form url.Values, cookies []*http.Cookie, noRedirect bool) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	if noRedirect {
		h.ServeHTTP(rec, req)
		return rec
	}
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, srv *Server) *http.Cookie {
	t.Helper()
	h := srv.Handler()
	rec := do(t, h, "GET", "/login", nil, nil, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/login", url.Values{
		"csrf": {csrf}, "username": {"admin"}, "password": {"DevPassw0rd!"},
	}, nil, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("登录应 303，得到 %d：%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("登录后没有下发会话 cookie")
	return nil
}

func TestRequiresLogin(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv.Handler(), "GET", "/", nil, nil, false)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("未登录访问应跳转登录页，得到 %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	rec := do(t, h, "GET", "/login", nil, nil, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/login", url.Values{"csrf": {csrf}, "username": {"admin"}, "password": {"wrong"}}, nil, false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码应 401，得到 %d", rec.Code)
	}
}

func TestLoginAndDashboard(t *testing.T) {
	srv, _ := newTestServer(t)
	cookie := login(t, srv)
	rec := do(t, srv.Handler(), "GET", "/", nil, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("仪表盘应 200，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "投票") {
		t.Fatal("仪表盘内容异常")
	}
}

func TestCreatePollRequiresCSRF(t *testing.T) {
	srv, _ := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	form := url.Values{"title": {"无 CSRF"}, "status": {"open"}, "show_results": {"never"}}
	rec := do(t, h, "POST", "/polls", form, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 CSRF 应 400，得到 %d", rec.Code)
	}
}

func TestCreatePollAndRenderQuestions(t *testing.T) {
	srv, st := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	rec := do(t, h, "GET", "/polls/new", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())

	form := url.Values{
		"csrf": {csrf}, "title": {"新投票"}, "summary": {"简介"}, "status": {"open"}, "show_results": {"after_vote"},
		"q0_type": {"single"}, "q0_title": {"选择题"}, "q0_required": {"on"}, "q0_opt0": {"甲"}, "q0_opt1": {"乙"},
		"q1_type": {"rank"}, "q1_title": {"排序题"}, "q1_required": {"on"}, "q1_opt0": {"一"}, "q1_opt1": {"二"}, "q1_opt2": {"三"},
		"q2_type": {"text"}, "q2_title": {"简答题"}, "q2_max_length": {"100"},
	}
	rec = do(t, h, "POST", "/polls", form, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("创建应 303，得到 %d：%s", rec.Code, rec.Body.String())
	}
	polls, err := st.ListPolls(context.Background(), nil)
	if err != nil || len(polls) != 1 {
		t.Fatalf("应创建 1 个投票：%v %d", err, len(polls))
	}
	qs, err := st.ListQuestions(context.Background(), polls[0].ID)
	if err != nil || len(qs) != 3 {
		t.Fatalf("应写入 3 道题：%v %d", err, len(qs))
	}
	if qs[1].Type != "rank" || len(qs[1].Options) != 3 {
		t.Fatalf("排序题结构不对：%+v", qs[1])
	}
}

func TestCreatePollRejectsBadQuestions(t *testing.T) {
	srv, st := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	rec := do(t, h, "GET", "/polls/new", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	form := url.Values{
		"csrf": {csrf}, "title": {"只有选项的题"}, "status": {"open"}, "show_results": {"never"},
		"q0_type": {"single"}, "q0_title": {"缺选项"}, "q0_opt0": {""}, "q0_opt1": {""},
	}
	rec = do(t, h, "POST", "/polls", form, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法题目应 400，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "至少需要两个选项") {
		t.Fatalf("应给出具体原因：%s", rec.Body.String())
	}
	polls, _ := st.ListPolls(context.Background(), nil)
	if len(polls) != 0 {
		t.Fatal("校验失败时不应写入投票")
	}
}

func TestAdminCannotEditQuestionsAfterVotes(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	// 先建一个投票并塞一票（直接写存储，绕过前台流程）
	p, err := st.CreatePoll(ctx, store.PollInput{Title: "已有票", Status: "open", ShowResults: "always", OnePerIP: true}, "hasvote", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceQuestions(ctx, p.ID, []store.QuestionInput{
		{Type: "single", Title: "原题", Required: true, Options: []string{"A", "B"}},
	}); err != nil {
		t.Fatal(err)
	}
	ip := make([]byte, 16)
	ip[0] = 1
	if err := st.InsertVote(ctx, &store.Vote{PollID: p.ID, IP: ip, IPText: "1.0.0.1", Receipt: "ABCDEFGH12345678"},
		[]store.Answer{{QuestionID: 0}}); err != nil {
		t.Fatal(err)
	}

	cookie := login(t, srv)
	h := srv.Handler()
	rec := do(t, h, "GET", "/polls/"+itoa(p.ID), nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	form := url.Values{
		"csrf": {csrf}, "title": {"已有票"}, "status": {"open"}, "show_results": {"always"},
		"q0_type": {"single"}, "q0_title": {"被改过的题"}, "q0_required": {"on"}, "q0_opt0": {"A"}, "q0_opt1": {"B"},
	}
	rec = do(t, h, "POST", "/polls/"+itoa(p.ID), form, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能再修改题目") {
		t.Fatalf("已有票时改题应被拒绝，得到 %d", rec.Code)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
