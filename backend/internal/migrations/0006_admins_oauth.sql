-- 0006：危险操作改成"外部 OAuth2 二次授权"，管理员绑定一个外部身份。
-- totp_* 三列保留但不再使用（历史数据留着，等 OAuth2 稳定后再单独清理）。
ALTER TABLE admins
  ADD COLUMN oauth_subject  VARCHAR(255) NOT NULL DEFAULT '' AFTER totp_last_step,
  ADD COLUMN oauth_email    VARCHAR(255) NOT NULL DEFAULT '' AFTER oauth_subject,
  ADD COLUMN oauth_bound_at DATETIME     NULL              AFTER oauth_email;
