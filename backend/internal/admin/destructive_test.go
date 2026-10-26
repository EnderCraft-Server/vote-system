package admin

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/totp"
)

// bindTOTP 给 admin 账号绑定一个 authenticator，并返回能算出当前动态码的密钥。
func bindTOTP(t *testing.T, srv *Server, st store.Store) string {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := st.GetAdminByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdminTOTP(context.Background(), admin.ID, secret, time.Now()); err != nil {
		t.Fatal(err)
	}
	return secret
}

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.Code(secret, totp.Step(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func seedVotes(t *testing.T, st store.Store, pollID int64, ipStr string, n int) {
	t.Helper()
	addr := netipMust(t, ipStr)
	for i := 0; i < n; i++ {
		v := &store.Vote{PollID: pollID, IP: addr, IPKey: []byte{byte(i), 1}, IPText: ipStr,
			Receipt: "PT" + time.Now().Format("150405") + string(rune('A'+i))}
		if err := st.InsertVote(context.Background(), v, nil); err != nil {
			t.Fatalf("插入票失败：%v", err)
		}
	}
}

func netipMust(t *testing.T, s string) []byte {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	b := addr.As16()
	return b[:]
}

func regexpMust(body, pattern string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(m) < 2 {
		panic("pattern not found: " + pattern)
	}
	return m[1]
}

func TestDangerRequiresTOTP(t *testing.T) {
	srv, st := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()

	p, err := st.CreatePoll(context.Background(), store.PollInput{Title: "刷票测试", Status: "open", ShowResults: "always", OnePerIP: false}, "spamtest", 0)
	if err != nil {
		t.Fatal(err)
	}
	seedVotes(t, st, p.ID, "203.0.113.9", 3)

	rec := do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "还没有绑定动态验证码") {
		t.Fatalf("未绑定时应提示：%d body=%s", rec.Code, rec.Body.String()[:min(300, rec.Body.Len())])
	}
	csrf := csrfOf(t, rec.Body.String())

	// 未绑定 → 拒绝
	rec = do(t, h, "POST", "/super/danger/delete-ip", url.Values{
		"csrf": {csrf}, "poll_id": {itoa(p.ID)}, "ip": {"203.0.113.9"}, "totp": {"123456"}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if n, _ := st.CountVotes(context.Background(), p.ID); n != 3 {
		t.Fatalf("未绑定时不应删票，剩余 %d", n)
	}

	// 绑定后：错码 → 拒绝
	secret := bindTOTP(t, srv, st)
	rec = do(t, h, "POST", "/super/danger/delete-ip", url.Values{
		"csrf": {csrf}, "poll_id": {itoa(p.ID)}, "ip": {"203.0.113.9"}, "totp": {"000000"}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if n, _ := st.CountVotes(context.Background(), p.ID); n != 3 {
		t.Fatalf("错码不应删票，剩余 %d", n)
	}

	// 正确码 → 删除 3 票
	code := currentCode(t, secret)
	rec = do(t, h, "POST", "/super/danger/delete-ip", url.Values{
		"csrf": {csrf}, "poll_id": {itoa(p.ID)}, "ip": {"203.0.113.9"}, "totp": {code}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("正确码应 303，得到 %d：%s", rec.Code, rec.Body.String())
	}
	if n, _ := st.CountVotes(context.Background(), p.ID); n != 0 {
		t.Fatalf("应删光该 IP 的票，剩余 %d", n)
	}
	logs, _ := st.ListAudit(context.Background(), 5)
	found := false
	for _, l := range logs {
		if l.Action == "votes_deleted_by_ip" && strings.Contains(l.Detail, "删除票数=3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少审计记录：%+v", logs)
	}

	// 同一个动态码再用一次 → 重放被拒
	rec = do(t, h, "POST", "/super/danger/delete-poll", url.Values{
		"csrf": {csrf}, "poll_id": {itoa(p.ID)}, "totp": {code}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if _, err := st.GetPoll(context.Background(), p.ID); err != nil {
		t.Fatal("重放的动态码不应删掉投票")
	}
}

func TestDeletePollWithVotes(t *testing.T) {
	srv, st := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()
	secret := bindTOTP(t, srv, st)

	p, err := st.CreatePoll(context.Background(), store.PollInput{Title: "待删投票", Status: "open", ShowResults: "always"}, "todelete", 0)
	if err != nil {
		t.Fatal(err)
	}
	seedVotes(t, st, p.ID, "198.51.100.2", 2)

	rec := do(t, h, "GET", "/super/danger", nil, []*http.Cookie{cookie}, false)
	csrf := csrfOf(t, rec.Body.String())
	rec = do(t, h, "POST", "/super/danger/delete-poll", url.Values{
		"csrf": {csrf}, "poll_id": {itoa(p.ID)}, "totp": {currentCode(t, secret)}, "confirm": {"on"},
	}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("应 303，得到 %d：%s", rec.Code, rec.Body.String())
	}
	if _, err := st.GetPoll(context.Background(), p.ID); err == nil {
		t.Fatal("投票应已被删除")
	}
	logs, _ := st.ListAudit(context.Background(), 3)
	if logs[0].Action != "poll_deleted_with_votes" || !strings.Contains(logs[0].Detail, "删除前票数=2") {
		t.Fatalf("审计不对：%+v", logs[0])
	}
}

func TestTOTPBindPageAndBind(t *testing.T) {
	srv, st := newTestServer(t)
	cookie := login(t, srv)
	h := srv.Handler()

	rec := do(t, h, "GET", "/account/totp", nil, []*http.Cookie{cookie}, false)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "/account/totp/qr?secret=") || !strings.Contains(body, "Vote%20Super%20Admin%20Access") {
		t.Fatalf("绑定页应含二维码与 otpauth 链接：%d body=%s", rec.Code, body[:min(400, len(body))])
	}
	csrf := csrfOf(t, body)
	secret := regexpMust(body, `name="secret" value="([A-Z2-7]+)"`)
	sig := regexpMust(body, `name="sig" value="([0-9a-f]+)"`)

	// 错码
	rec = do(t, h, "POST", "/account/totp", url.Values{
		"csrf": {csrf}, "secret": {secret}, "sig": {sig}, "code": {"000000"},
	}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("错码应 400，得到 %d", rec.Code)
	}

	// 正确码
	rec = do(t, h, "POST", "/account/totp", url.Values{
		"csrf": {csrf}, "secret": {secret}, "sig": {sig}, "code": {currentCode(t, secret)},
	}, []*http.Cookie{cookie}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("应 303，得到 %d：%s", rec.Code, rec.Body.String())
	}
	admin, _ := st.GetAdminByUsername(context.Background(), "admin")
	if admin.TOTPSecret != secret || admin.TOTPBoundAt == nil {
		t.Fatalf("绑定没有落库：%+v", admin)
	}

	// 再次访问绑定页应只显示"已绑定"，且不能重复绑定
	rec = do(t, h, "GET", "/account/totp", nil, []*http.Cookie{cookie}, false)
	if !strings.Contains(rec.Body.String(), "已绑定") {
		t.Fatal("应显示已绑定")
	}
	rec = do(t, h, "POST", "/account/totp", url.Values{
		"csrf": {csrf}, "secret": {secret}, "sig": {sig}, "code": {currentCode(t, secret)},
	}, []*http.Cookie{cookie}, false)
	admin2, _ := st.GetAdminByUsername(context.Background(), "admin")
	if admin2.TOTPSecret != secret {
		t.Fatal("重复绑定不应覆盖原密钥")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
