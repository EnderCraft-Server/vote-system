package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
	"github.com/EnderCraft-Server/vote-system/backend/internal/totp"
)

// totpIssuer 是 authenticator 里显示的名字，需求指定为 "Vote Super Admin Access"。
const totpIssuer = "Vote Super Admin Access"

func (s *Server) totpSecretSig(admin *store.Admin, secret string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Security.RPCSecret))
	mac.Write([]byte("totpbind|" + strconv.FormatInt(admin.ID, 10) + "|" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyTOTP 校验动态码并做防重放：同一个 30 秒窗口只接受一次。
func (s *Server) verifyTOTP(r *http.Request, admin *store.Admin, code string) error {
	if admin.TOTPSecret == "" {
		return errors.New("当前账号还没有绑定 authenticator，请先到「账号 → 动态验证码」绑定")
	}
	step, err := totp.Verify(admin.TOTPSecret, code, s.now(), totp.DefaultWindow)
	if err != nil {
		return errors.New("动态验证码不正确")
	}
	if step <= admin.TOTPLastStep {
		return errors.New("这个验证码刚刚用过，请等 30 秒后用新的验证码")
	}
	if err := s.st.UpdateAdminTOTPStep(r.Context(), admin.ID, step); err != nil {
		return err
	}
	return nil
}

// ---------- 绑定页 ----------

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if admin.TOTPSecret != "" {
		s.render(w, r, "totp", pageData{
			Title: "动态验证码", Nav: "account", Admin: admin, CSRF: s.csrfFor(r),
			Data: map[string]any{"Bound": true, "BoundAt": admin.TOTPBoundAt},
		})
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		s.fail(w, r, "totp", http.StatusInternalServerError, "生成密钥失败", pageData{Title: "动态验证码", Admin: admin, CSRF: s.csrfFor(r), Data: nil})
		return
	}
	uri := totp.ProvisioningURI(totpIssuer, admin.Username, secret)
	s.render(w, r, "totp", pageData{
		Title: "动态验证码", Nav: "account", Admin: admin, CSRF: s.csrfFor(r),
		Flash: r.URL.Query().Get("ok"),
		Data: map[string]any{
			"Bound":  false,
			"Secret": secret,
			"URI":    uri,
			"Sig":    s.totpSecretSig(admin, secret),
		},
	})
}

// handleTOTPQR 输出绑定二维码。二维码必须单独成一个路由：html/template 会把
// src="data:image/png;base64,…" 里的 data: 换成 #ZgotmplZ，图片就显示不出来。
func (s *Server) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if admin.TOTPSecret != "" {
		http.NotFound(w, r)
		return
	}
	secret := strings.TrimSpace(r.URL.Query().Get("secret"))
	sig := r.URL.Query().Get("sig")
	if secret == "" || !hmac.Equal([]byte(sig), []byte(s.totpSecretSig(admin, secret))) {
		http.Error(w, "链接已失效", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(totp.ProvisioningURI(totpIssuer, admin.Username, secret), qrcode.Medium, 240)
	if err != nil {
		http.Error(w, "生成二维码失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

func (s *Server) handleTOTPBind(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	if admin.TOTPSecret != "" {
		s.flashRedirect(w, r, "/account/totp", "该账号已经绑定过，不能重复绑定；解绑请在后台控制台执行")
		return
	}
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	sig := r.PostFormValue("sig")
	code := r.PostFormValue("code")
	if secret == "" || !hmac.Equal([]byte(sig), []byte(s.totpSecretSig(admin, secret))) {
		s.fail(w, r, "totp", http.StatusBadRequest, "绑定信息已失效，请刷新页面重试", pageData{Title: "动态验证码", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	step, err := totp.Verify(secret, code, s.now(), totp.DefaultWindow)
	if err != nil {
		s.fail(w, r, "totp", http.StatusBadRequest, "验证码不正确，请确认手机时间准确后重试", pageData{Title: "动态验证码", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	if err := s.st.SetAdminTOTP(r.Context(), admin.ID, secret, s.now()); err != nil {
		s.fail(w, r, "totp", http.StatusInternalServerError, "保存失败", pageData{Title: "动态验证码", Admin: admin, CSRF: s.csrfFor(r)})
		return
	}
	_ = s.st.UpdateAdminTOTPStep(r.Context(), admin.ID, step)
	s.audit(r, "totp_bind", "admin:"+strconv.FormatInt(admin.ID, 10), "绑定 authenticator")
	s.flashRedirect(w, r, "/account/totp", "绑定成功")
}

// ---------- 危险操作页 ----------

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
			"Polls": rows, "TOTPBound": admin.TOTPSecret != "",
		},
	})
}

func (s *Server) handleDeleteByIP(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
		return
	}
	pollID, err := strconv.ParseInt(r.PostFormValue("poll_id"), 10, 64)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "请选择投票")
		return
	}
	ipText := strings.TrimSpace(r.PostFormValue("ip"))
	addr, err := netip.ParseAddr(ipText)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "IP 格式不正确")
		return
	}
	if r.PostFormValue("confirm") != "on" {
		s.flashRedirect(w, r, "/super/danger", "请勾选确认")
		return
	}
	if err := s.verifyTOTP(r, admin, r.PostFormValue("totp")); err != nil {
		s.flashRedirect(w, r, "/super/danger", err.Error())
		return
	}
	poll, err := s.st.GetPoll(r.Context(), pollID)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "投票不存在")
		return
	}
	ipBytes := addr.As16()
	before, err := s.st.CountVotesByIP(r.Context(), pollID, ipBytes[:])
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "统计失败")
		return
	}
	deleted, err := s.st.DeleteVotesByIP(r.Context(), pollID, ipBytes[:])
	if err != nil {
		s.log.Error("按 IP 删除投票失败", "err", err, "poll", poll.Slug, "ip", ipText)
		s.flashRedirect(w, r, "/super/danger", "删除失败")
		return
	}
	s.audit(r, "votes_deleted_by_ip", "poll:"+poll.Slug, "ip="+ipText+" 删除票数="+strconv.FormatInt(deleted, 10)+" 预览="+strconv.Itoa(before))
	s.flashRedirect(w, r, "/super/danger", "已删除 "+poll.Title+" 中 "+ipText+" 的 "+strconv.FormatInt(deleted, 10)+" 票")
}

func (s *Server) handleDeletePoll(w http.ResponseWriter, r *http.Request) {
	admin := adminFrom(r)
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r, s.csrfFor(r)) {
		http.Error(w, "页面已过期", http.StatusBadRequest)
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
	if err := s.verifyTOTP(r, admin, r.PostFormValue("totp")); err != nil {
		s.flashRedirect(w, r, "/super/danger", err.Error())
		return
	}
	poll, err := s.st.GetPoll(r.Context(), pollID)
	if err != nil {
		s.flashRedirect(w, r, "/super/danger", "投票不存在")
		return
	}
	votes, _ := s.st.CountVotes(r.Context(), pollID)
	if err := s.st.DeletePoll(r.Context(), pollID); err != nil {
		s.log.Error("删除投票失败", "err", err, "slug", poll.Slug)
		s.flashRedirect(w, r, "/super/danger", "删除失败")
		return
	}
	s.audit(r, "poll_deleted_with_votes", "poll:"+poll.Slug, "标题="+poll.Title+" 删除前票数="+strconv.Itoa(votes))
	s.flashRedirect(w, r, "/super/danger", "已删除投票「"+poll.Title+"」（含 "+strconv.Itoa(votes)+" 票）")
}
