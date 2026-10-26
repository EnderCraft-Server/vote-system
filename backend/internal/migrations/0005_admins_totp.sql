-- 0005：管理员绑定 authenticator（TOTP）。
-- 每个账号只能绑一次；解绑只能由运维在后台控制台执行 unbind totp <username>。
ALTER TABLE admins
  ADD COLUMN totp_secret    VARCHAR(64) NOT NULL DEFAULT '' AFTER password_hash,
  ADD COLUMN totp_bound_at  DATETIME    NULL              AFTER totp_secret,
  ADD COLUMN totp_last_step BIGINT      NOT NULL DEFAULT 0 AFTER totp_bound_at;
