package admin

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/oauth"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

// 危险操作改成"跳出去做一次 OAuth2 授权再回来执行"：
//
//	POST /super/danger/delete-ip  → 建一条一次性 pending → 302 到 provider
//	provider 授权 → GET /oauth/callback?code=..&state=<pending id> → 执行 → 结果页
//
// pending 只在服务端内存里，绑定发起人、动作、目标与过期时间；callback 不依赖会话
// Cookie（跨站跳回来时 SameSite=Strict 的会话本来就不会带上），身份由 pending 保证，
// 且只能用一次。

const (
	kindBind       = "bind"
	kindDeleteIP   = "delete_ip"
	kindDeletePoll = "delete_poll"
)

type pendingAction struct {
	ID      string
	AdminID int64
	Kind    string
	PollID  int64
	IP      string
	Expires time.Time
}

func (s *Server) putPending(p *pendingAction) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	now := s.now()
	for k, v := range s.pending {
		if now.After(v.Expires) {
			delete(s.pending, k)
		}
	}
	s.pending[p.ID] = p
}

// peekPending 只查看不消费，/oauth/go 用它确认 state 还活着。
func (s *Server) peekPending(id string) (*pendingAction, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	p, ok := s.pending[id]
	if !ok || s.now().After(p.Expires) {
		return nil, false
	}
	return p, true
}

// handleOAuthGo 是表单提交后的同源落点。
//
// 这里**不能**直接 303 到 provider：我们的 CSP 是 form-action 'self'，
// Chrome 会把"表单提交 + 重定向链"整体按 form-action 检查，跨源那一跳会被拦掉
// （现象就是点按钮没反应）。所以先返回一个同源页面，用 meta refresh 做一次
// 普通顶层导航——导航不受 form-action 约束。
func (s *Server) handleOAuthGo(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if _, ok := s.peekPending(state); !ok {
		s.renderOAuthDone(w, r, false, "授权请求已过期或不存在，请回到上一页重新发起")
		return
	}
	s.render(w, r, "oauth_go", pageData{
		Title: "正在跳转授权",
		Data:  map[string]any{"URL": s.oauthClient().AuthCodeURL(state)},
	})
}

func (s *Server) takePending(id string) (*pendingAction, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return nil, false
	}
	delete(s.pending, id)
	if s.now().After(p.Expires) {
		return nil, false
	}
	return p, true
}

func (s *Server) pendingTTL() time.Duration {
	if s.cfg.OAuth.PendingTTL.Duration > 0 {
		return s.cfg.OAuth.PendingTTL.Duration
	}
	return 5 * time.Minute
}

func (s *Server) startOAuth(w http.ResponseWriter, r *http.Request, p *pendingAction) {
	p.ID = randomHex(24)
	if p.Expires.IsZero() {
		p.Expires = s.now().Add(s.pendingTTL())
	}
	s.putPending(p)
	// 不能直接把表单响应 302 到 provider：我们的 CSP 是 form-action 'self'，
	// Chrome 会把"表单提交 + 跨源重定向"判成违规并直接拦掉请求。
	// 所以先回到本站的一个 GET 页面，再由它做顶层导航跳出去。
	http.Redirect(w, r, "/oauth/go?state="+url.QueryEscape(p.ID), http.StatusSeeOther)
}

// ---------- 绑定 ----------

func (s *Server) handleOAuthAccount(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	s.render(w, r, "oauth", pageData{
		Title: "外部身份授权", Nav: "account", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data: map[string]any{
			"Enabled": s.cfg.OAuth.Enabled,
			"Bound":   admin.OAuthSubject != "",
			"Subject": admin.OAuthSubject,
			"Email":   admin.OAuthEmail,
			"BoundAt": admin.OAuthBoundAt,
		},
	})
}

func (s *Server) handleOAuthBindStart(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if !s.cfg.OAuth.Enabled {
		s.flashRedirect(w, r, "/account/oauth", "后台没有启用 OAuth2")
		return
	}
	if admin.OAuthSubject != "" {
		s.flashRedirect(w, r, "/account/oauth", "该账号已经绑定过外部身份")
		return
	}
	s.startOAuth(w, r, &pendingAction{AdminID: admin.ID, Kind: kindBind})
}

// ---------- callback ----------

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if e := r.URL.Query().Get("error"); e != "" {
		desc := r.URL.Query().Get("error_description")
		s.log.Warn("provider 拒绝了授权", "error", e, "description", desc)
		msg := "授权被拒绝：" + e
		if desc != "" {
			msg += "（" + desc + "）"
		}
		s.renderOAuthDone(w, r, false, msg)
		return
	}
	if code == "" || state == "" {
		s.renderOAuthDone(w, r, false, "回调参数不完整")
		return
	}
	p, ok := s.takePending(state)
	if !ok {
		s.renderOAuthDone(w, r, false, "授权请求已过期或已被使用，请回到危险操作页重新发起")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	client := s.oauthClient()
	token, err := client.Exchange(ctx, code)
	if err != nil {
		s.log.Warn("oauth 换 token 失败", "err", err, "kind", p.Kind)
		s.renderOAuthDone(w, r, false, "无法完成授权（令牌交换失败）")
		return
	}
	info, err := client.Userinfo(ctx, token)
	if err != nil {
		s.log.Warn("oauth 读取用户信息失败", "err", err, "kind", p.Kind)
		s.renderOAuthDone(w, r, false, "无法读取授权账号信息")
		return
	}
	subject := oauth.Lookup(info, s.cfg.OAuth.SubjectField)
	email := oauth.Lookup(info, s.cfg.OAuth.EmailField)
	if subject == "" {
		s.renderOAuthDone(w, r, false, "授权账号缺少身份标识字段（检查 oauth.subject_field）")
		return
	}

	if p.Kind == kindBind {
		if len(s.cfg.OAuth.AllowedEmailDomain) > 0 && !emailInDomains(email, s.cfg.OAuth.AllowedEmailDomain) {
			s.renderOAuthDone(w, r, false, "该邮箱域名不允许绑定")
			return
		}
		if err := s.st.SetAdminOAuth(ctx, p.AdminID, subject, email, s.now()); err != nil {
			s.log.Error("保存 oauth 绑定失败", "err", err)
			s.renderOAuthDone(w, r, false, "保存绑定失败")
			return
		}
		_ = s.st.AddAudit(ctx, &store.AuditEntry{
			Actor: "oauth", Action: "oauth_bind", Target: "admin:" + subject,
			IPText: clientIP(r), Detail: "email=" + email,
		})
		s.renderOAuthDone(w, r, true, "已完成绑定。之后执行危险操作时，浏览器会再跳一次授权页。")
		return
	}

	admin, err := s.st.GetAdminByID(ctx, p.AdminID)
	if err != nil {
		s.renderOAuthDone(w, r, false, "发起人账号不存在")
		return
	}
	if admin.OAuthSubject == "" {
		s.renderOAuthDone(w, r, false, "账号未绑定外部身份")
		return
	}
	if admin.OAuthSubject != subject {
		_ = s.st.AddAudit(ctx, &store.AuditEntry{
			Actor: "oauth", Action: "oauth_subject_mismatch", Target: "admin:" + admin.Username,
			IPText: clientIP(r), Detail: "期望=" + admin.OAuthSubject + " 实际=" + subject,
		})
		s.renderOAuthDone(w, r, false, "授权账号与绑定身份不一致，操作已拒绝（已记入审计）")
		return
	}

	var msg string
	switch p.Kind {
	case kindDeleteIP:
		msg, err = s.doDeleteByIP(ctx, admin.Username, clientIP(r), p.PollID, p.IP)
	case kindDeletePoll:
		msg, err = s.doDeletePoll(ctx, admin.Username, clientIP(r), p.PollID)
	default:
		s.renderOAuthDone(w, r, false, "未知操作")
		return
	}
	if err != nil {
		s.log.Error("危险操作执行失败", "err", err, "kind", p.Kind)
		s.renderOAuthDone(w, r, false, "执行失败："+err.Error())
		return
	}
	s.renderOAuthDone(w, r, true, msg)
}

func (s *Server) renderOAuthDone(w http.ResponseWriter, r *http.Request, ok bool, message string) {
	s.render(w, r, "oauth_done", pageData{
		Title: "授权结果",
		Data:  map[string]any{"OK": ok, "Message": message},
	})
}

func emailInDomains(email string, domains []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range domains {
		if strings.ToLower(strings.TrimSpace(d)) == domain {
			return true
		}
	}
	return false
}

// ---------- 由 callback 调用的执行逻辑 ----------

func (s *Server) doDeleteByIP(ctx context.Context, actor, ipText string, pollID int64, rawIP string) (string, error) {
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return "", err
	}
	poll, err := s.st.GetPoll(ctx, pollID)
	if err != nil {
		return "", err
	}
	b := addr.As16()
	before, err := s.st.CountVotesByIP(ctx, pollID, b[:])
	if err != nil {
		return "", err
	}
	deleted, err := s.st.DeleteVotesByIP(ctx, pollID, b[:])
	if err != nil {
		return "", err
	}
	_ = s.st.AddAudit(ctx, &store.AuditEntry{
		Actor: actor, Action: "votes_deleted_by_ip", Target: "poll:" + poll.Slug,
		IPText: ipText,
		Detail: "ip=" + rawIP + " 删除票数=" + strconv.FormatInt(deleted, 10) + " 预览=" + strconv.Itoa(before),
	})
	return "已删除「" + poll.Title + "」中 " + rawIP + " 的 " + strconv.FormatInt(deleted, 10) + " 张票。", nil
}

func (s *Server) doDeletePoll(ctx context.Context, actor, ipText string, pollID int64) (string, error) {
	poll, err := s.st.GetPoll(ctx, pollID)
	if err != nil {
		return "", err
	}
	votes, _ := s.st.CountVotes(ctx, pollID)
	if err := s.st.DeletePoll(ctx, pollID); err != nil {
		return "", err
	}
	_ = s.st.AddAudit(ctx, &store.AuditEntry{
		Actor: actor, Action: "poll_deleted_with_votes", Target: "poll:" + poll.Slug,
		IPText: ipText,
		Detail: "标题=" + poll.Title + " 删除前票数=" + strconv.Itoa(votes),
	})
	return "已删除投票「" + poll.Title + "」，连同 " + strconv.Itoa(votes) + " 张票。", nil
}

func (s *Server) oauthClient() *oauth.Client { return oauth.New(s.cfg.OAuth) }
