package rpc

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/protocol"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store/memory"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

func testSetup(t *testing.T) (*Server, *vote.Service, *memory.Store, []byte, *store.Poll) {
	t.Helper()
	cfg := config.Default()
	cfg.Env = "development"
	cfg.Security.RPCSecret = strings.Repeat("k", 48)
	cfg.Captcha.Enabled = false
	cfg.Limits.VotePerIPMinute = 100
	st := memory.New()
	poll, err := st.CreatePoll(context.Background(), store.PollInput{
		Title: "端到端投票", Status: "open", ShowResults: "always", OnePerIP: true,
	}, "e2epoll", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceQuestions(context.Background(), poll.ID, []store.QuestionInput{
		{Type: "single", Title: "选一个", Required: true, Options: []string{"甲", "乙"}},
	}); err != nil {
		t.Fatal(err)
	}
	svc := vote.New(st, cfg)
	srv := New(Options{
		Secret:        []byte(cfg.Security.RPCSecret),
		MaxFrameBytes: 1 << 20,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		IdleTimeout:   10 * time.Second,
		ClockSkew:     time.Minute,
		NonceTTL:      time.Minute,
		MaxConns:      8,
	}, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return srv, svc, st, []byte(cfg.Security.RPCSecret), poll
}

func startServer(t *testing.T, srv *Server) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln
}

func call(t *testing.T, conn net.Conn, secret []byte, method string, body any) (byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeRequest(secret, method, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respPayload, err := protocol.ReadFrame(conn, 1<<20)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	resp, err := protocol.DecodeResponse(secret, respPayload, time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("响应验签失败：%v", err)
	}
	return resp.Status, resp.Body
}

func TestPingAndPopulatedPollFlow(t *testing.T) {
	srv, _, _, secret, poll := testSetup(t)
	ln := startServer(t, srv)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	status, body := call(t, conn, secret, "ping", map[string]any{})
	if status != protocol.StatusOK {
		t.Fatalf("ping 失败：%s", body)
	}
	var pong map[string]any
	_ = json.Unmarshal(body, &pong)
	if pong["pong"] != true {
		t.Fatalf("ping 返回异常：%s", body)
	}

	status, body = call(t, conn, secret, "poll.list", map[string]any{})
	if status != protocol.StatusOK || !strings.Contains(string(body), "e2epoll") {
		t.Fatalf("poll.list 异常：%d %s", status, body)
	}

	status, body = call(t, conn, secret, "poll.get", map[string]any{"slug": "e2epoll", "ip": "203.0.113.5"})
	if status != protocol.StatusOK {
		t.Fatalf("poll.get 失败：%s", body)
	}
	var detail vote.PollDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Questions) != 1 || len(detail.Questions[0].Options) != 2 {
		t.Fatalf("题目结构异常：%s", body)
	}
	optID := detail.Questions[0].Options[1].ID

	status, body = call(t, conn, secret, "vote.submit", map[string]any{
		"slug": poll.Slug, "ip": "203.0.113.5", "ua": "rpc-test",
		"captcha": map[string]string{"id": "", "answer": ""},
		"answers": []map[string]any{{"question_id": detail.Questions[0].ID, "choices": []int64{optID}}},
	})
	if status != protocol.StatusOK {
		t.Fatalf("vote.submit 失败：%s", body)
	}

	status, body = call(t, conn, secret, "vote.submit", map[string]any{
		"slug": poll.Slug, "ip": "203.0.113.5", "ua": "rpc-test",
		"captcha": map[string]string{"id": "", "answer": ""},
		"answers": []map[string]any{{"question_id": detail.Questions[0].ID, "choices": []int64{optID}}},
	})
	if status != protocol.StatusError || !strings.Contains(string(body), "already_voted") {
		t.Fatalf("重复投票应返回 already_voted：%d %s", status, body)
	}

	status, body = call(t, conn, secret, "poll.results", map[string]any{"slug": poll.Slug, "ip": "203.0.113.5"})
	if status != protocol.StatusOK || !strings.Contains(string(body), `"total_votes":1`) {
		t.Fatalf("poll.results 异常：%d %s", status, body)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv, _, _, secret, _ := testSetup(t)
	ln := startServer(t, srv)
	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()
	status, body := call(t, conn, secret, "admin.drop_tables", map[string]any{})
	if status != protocol.StatusError || !strings.Contains(string(body), "unknown_method") {
		t.Fatalf("未知方法应被拒绝：%d %s", status, body)
	}
}

func TestWrongSecretClosesConnection(t *testing.T) {
	srv, _, _, _, _ := testSetup(t)
	ln := startServer(t, srv)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wrong := []byte(strings.Repeat("x", 48))
	payload, _ := protocol.EncodeRequest(wrong, "ping", []byte(`{}`))
	if err := protocol.WriteFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := protocol.ReadFrame(conn, 1<<20); err == nil {
		t.Fatal("密钥不符时服务端必须断开且不回包")
	}
}

func TestReplayRejected(t *testing.T) {
	srv, _, _, secret, _ := testSetup(t)
	ln := startServer(t, srv)
	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	payload, _ := protocol.EncodeRequest(secret, "ping", []byte(`{}`))
	if err := protocol.WriteFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := protocol.ReadFrame(conn, 1<<20); err != nil {
		t.Fatalf("首次请求应成功：%v", err)
	}
	// 原样重放同一帧
	if err := protocol.WriteFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := protocol.ReadFrame(conn, 1<<20); err == nil {
		t.Fatal("重放帧必须被拒绝并断开")
	}
}
