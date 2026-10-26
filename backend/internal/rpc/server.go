// Package rpc 提供前台(PHP)调用的 TCP 服务：帧校验、方法分发表、连接管理。
package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/protocol"
	"github.com/EnderCraft-Server/vote-system/backend/internal/vote"
)

type Options struct {
	Secret        []byte
	MaxFrameBytes int
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	ClockSkew     time.Duration
	NonceTTL      time.Duration
	MaxConns      int
}

type Server struct {
	opts   Options
	svc    *vote.Service
	log    *slog.Logger
	nonces *protocol.NonceCache

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	sem      chan struct{}
	stopping bool
}

func New(opts Options, svc *vote.Service, log *slog.Logger) *Server {
	if opts.MaxFrameBytes <= 0 || opts.MaxFrameBytes > protocol.MaxFrameBytes {
		opts.MaxFrameBytes = protocol.MaxFrameBytes
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 128
	}
	return &Server{
		opts: opts, svc: svc, log: log,
		nonces: protocol.NewNonceCache(opts.NonceTTL),
		conns:  make(map[net.Conn]struct{}),
		sem:    make(chan struct{}, opts.MaxConns),
	}
}

// Serve 阻塞运行，直到 listener 关闭。
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			stopping := s.stopping
			s.mu.Unlock()
			if stopping {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// 连接数已满：立刻关掉，避免堆积。
			_ = conn.Close()
			s.log.Warn("rpc 连接数达到上限，拒绝新连接")
			continue
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handle(conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.SetDeadline(time.Now())
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	for {
		if s.opts.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		}
		payload, err := protocol.ReadFrame(conn, s.opts.MaxFrameBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTimeout(err) {
				s.log.Warn("rpc 读帧失败", "remote", remote, "err", err)
			}
			return
		}
		req, err := protocol.DecodeRequest(s.opts.Secret, payload, time.Now(), s.opts.ClockSkew)
		if err != nil {
			// 协议违例：不返回业务数据，直接断开。
			s.log.Warn("rpc 帧被拒绝", "remote", remote, "reason", protocol.ProtocolError(err))
			return
		}
		if s.nonces.Seen(req.Nonce, time.Now()) {
			s.log.Warn("rpc 重放请求被拒绝", "remote", remote, "method", req.Method)
			return
		}

		body, status := s.dispatch(conn, req)
		if sal := protocol.EncodeResponse(s.opts.Secret, req.RequestID, status, body); sal != nil {
			if s.opts.WriteTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(s.opts.WriteTimeout))
			}
			if err := protocol.WriteFrame(conn, sal); err != nil {
				s.log.Warn("rpc 写响应失败", "remote", remote, "err", err)
				return
			}
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]{6,16}$`)

func (s *Server) dispatch(conn net.Conn, req *protocol.Request) ([]byte, byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := s.call(ctx, req.Method, req.Body)
	if err != nil {
		code, msg := vote.Code(err)
		if code == "internal" {
			s.log.Error("rpc 方法内部错误", "method", req.Method, "remote", conn.RemoteAddr().String(), "err", err)
		}
		body, _ := json.Marshal(map[string]string{"code": code, "message": msg})
		return body, protocol.StatusError
	}
	body, err := json.Marshal(res)
	if err != nil {
		s.log.Error("rpc 序列化响应失败", "method", req.Method, "err", err)
		body, _ = json.Marshal(map[string]string{"code": "internal", "message": "内部错误"})
		return body, protocol.StatusError
	}
	return body, protocol.StatusOK
}

type captchaCreateBody struct {
	IP string `json:"ip"`
}

type captchaImageBody struct {
	ID string `json:"id"`
}

type pollGetBody struct {
	Slug string `json:"slug"`
	IP   string `json:"ip"`
}

type submitBody struct {
	Slug    string `json:"slug"`
	IP      string `json:"ip"`
	UA      string `json:"ua"`
	Captcha struct {
		ID     string `json:"id"`
		Answer string `json:"answer"`
	} `json:"captcha"`
	Answers []vote.AnswerInput `json:"answers"`
}

func decode(body []byte, dst any) error {
	if len(body) == 0 {
		return fmt.Errorf("body 为空")
	}
	if len(body) > protocol.MaxBodyBytes {
		return fmt.Errorf("body 过大")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return vote.ErrInvalid
	}
	return nil
}

func (s *Server) call(ctx context.Context, method string, body []byte) (any, error) {
	switch method {
	case "ping":
		return map[string]any{"pong": true, "time": time.Now().Unix()}, nil

	case "captcha.create":
		var in captchaCreateBody
		if err := decode(body, &in); err != nil {
			return nil, err
		}
		if len(in.IP) == 0 || len(in.IP) > 45 {
			return nil, vote.ErrInvalid
		}
		id, ttl, err := s.svc.CreateCaptcha(ctx, in.IP)
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "ttl": ttl}, nil

	case "captcha.image":
		var in captchaImageBody
		if err := decode(body, &in); err != nil {
			return nil, err
		}
		png, err := s.svc.CaptchaImage(in.ID)
		if err != nil {
			return nil, err
		}
		w, h := vote.CaptchaSize()
		return map[string]any{
			"png":    base64.StdEncoding.EncodeToString(png),
			"width":  w,
			"height": h,
		}, nil

	case "poll.list":
		polls, err := s.svc.ListPolls(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"polls": polls}, nil

	case "poll.get":
		var in pollGetBody
		if err := decode(body, &in); err != nil {
			return nil, err
		}
		if !slugPattern.MatchString(in.Slug) {
			return nil, vote.ErrPollNotFound
		}
		detail, err := s.svc.GetPoll(ctx, in.Slug, in.IP)
		if err != nil {
			return nil, err
		}
		return detail, nil

	case "vote.submit":
		var in submitBody
		if err := decode(body, &in); err != nil {
			return nil, err
		}
		if !slugPattern.MatchString(in.Slug) {
			return nil, vote.ErrPollNotFound
		}
		if len(in.UA) > 512 || len(in.Answers) > 64 {
			return nil, vote.ErrInvalid
		}
		res, err := s.svc.Submit(ctx, vote.SubmitInput{
			Slug:    in.Slug,
			IP:      in.IP,
			UA:      in.UA,
			Captcha: struct{ ID, Answer string }{ID: in.Captcha.ID, Answer: in.Captcha.Answer},
			Answers: in.Answers,
		})
		if err != nil {
			return nil, err
		}
		return res, nil

	case "poll.results":
		var in pollGetBody
		if err := decode(body, &in); err != nil {
			return nil, err
		}
		if !slugPattern.MatchString(in.Slug) {
			return nil, vote.ErrPollNotFound
		}
		res, err := s.svc.Results(ctx, in.Slug, in.IP)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, &vote.Error{Code: "unknown_method", Message: "未知方法"}
}
