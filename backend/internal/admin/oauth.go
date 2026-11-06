package admin

import (
	"context"
	"net/http"
	"net/netip"
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
	http.Redirect(w, r, s.oauthClient().AuthCodeURL(p.ID), http.StatusSeeOther)
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
		s.renderOAuthDone(w, r, false, "授权被拒绝："+e)
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
