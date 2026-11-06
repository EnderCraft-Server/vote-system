package admin

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// handleDanger 危险操作页。真正执行不在这个页面：点按钮只创建一次性 pending，
// 跳到 OAuth2 授权页，授权回调回来才执行。
func (s *Server) handleDanger(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	polls, err := s.st.ListPolls(r.Context(), nil)
	if err != nil {
		s.fail(w, r, "danger", http.StatusInternalServerError, "读取投票失败", pageData{Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	rows := make([]pollRow, 0, len(polls))
	for _, p := range polls {
		c, _ := s.st.CountVotes(r.Context(), p.ID)
		rows = append(rows, pollRow{Poll: p, VoteCount: c})
	}
	s.render(w, r, "danger", pageData{
		Title: "危险操作", Nav: "danger", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data: map[string]any{
			"Polls":      rows,
			"OAuthOn":    s.cfg.OAuth.Enabled,
			"OAuthBound": admin.OAuthSubject != "",
			"OAuthEmail": admin.OAuthEmail,
		},
	})
}

func (s *Server) handleDeleteByIP(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if !s.cfg.OAuth.Enabled {
		s.flashRedirect(w, r, "/super/danger", "后台没有启用 OAuth2，无法执行删除")
		return
	}
	pollID, err := strconv.ParseInt(r.PostFormValue("poll_id"), 10, 64)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "请选择投票")
		return
	}
	ipText := strings.TrimSpace(r.PostFormValue("ip"))
	if _, err := netip.ParseAddr(ipText); err != nil {
		s.flashRedirect(w, r, "/super/danger", "IP 格式不正确")
		return
	}
	if r.PostFormValue("confirm") != "on" {
		s.flashRedirect(w, r, "/super/danger", "请勾选确认")
		return
	}
	s.startOAuth(w, r, &pendingAction{AdminID: admin.ID, Kind: kindDeleteIP, PollID: pollID, IP: ipText})
}

func (s *Server) handleDeletePoll(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if !s.cfg.OAuth.Enabled {
		s.flashRedirect(w, r, "/super/danger", "后台没有启用 OAuth2，无法执行删除")
		return
	}
	pollID, err := strconv.ParseInt(r.PostFormValue("poll_id"), 10, 64)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "请选择投票")
		return
	}
	if r.PostFormValue("confirm") != "on" {
		s.flashRedirect(w, r, "/super/danger", "请勾选确认")
		return
	}
	s.startOAuth(w, r, &pendingAction{AdminID: admin.ID, Kind: kindDeletePoll, PollID: pollID})
}
