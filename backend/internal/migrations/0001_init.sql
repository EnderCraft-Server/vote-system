-- 0001_init.sql —— Vote 系统初始结构
-- 约定：所有表 utf8mb4；时间列一律 DATETIME(0)（服务器时区，部署时统一为 Asia/Shanghai）；
-- 所有 IP 用 VARBINARY(16) 存 IPv4-mapped 形式（::ffff:a.b.c.d），另存一份可读文本用于展示。

CREATE TABLE IF NOT EXISTS admins (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username       VARCHAR(64)     NOT NULL,
  password_hash  VARCHAR(255)    NOT NULL,
  display_name   VARCHAR(64)     NOT NULL DEFAULT '',
  is_active      TINYINT(1)      NOT NULL DEFAULT 1,
  failed_logins  INT             NOT NULL DEFAULT 0,
  locked_until   DATETIME        NULL,
  last_login_at  DATETIME        NULL,
  last_login_ip  VARCHAR(45)     NOT NULL DEFAULT '',
  created_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_admins_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_sessions (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  token_hash    CHAR(64)        NOT NULL,
  admin_id      BIGINT UNSIGNED NOT NULL,
  ip            VARCHAR(45)     NOT NULL DEFAULT '',
  user_agent    VARCHAR(255)    NOT NULL DEFAULT '',
  created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at    DATETIME        NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_sessions_token (token_hash),
  KEY idx_sessions_admin (admin_id, expires_at),
  CONSTRAINT fk_sessions_admin FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS polls (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  slug         VARCHAR(16)     NOT NULL,
  title        VARCHAR(160)    NOT NULL,
  summary      VARCHAR(500)    NOT NULL DEFAULT '',
  status       VARCHAR(16)     NOT NULL DEFAULT 'draft',
  show_results VARCHAR(16)     NOT NULL DEFAULT 'after_vote',
  one_per_ip   TINYINT(1)      NOT NULL DEFAULT 1,
  starts_at    DATETIME        NULL,
  ends_at      DATETIME        NULL,
  created_by   BIGINT UNSIGNED NULL,
  created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_polls_slug (slug),
  KEY idx_polls_status (status, starts_at, ends_at),
  CONSTRAINT fk_polls_creator FOREIGN KEY (created_by) REFERENCES admins (id) ON DELETE SET NULL,
  CONSTRAINT ck_polls_status CHECK (status IN ('draft', 'open', 'closed')),
  CONSTRAINT ck_polls_show_results CHECK (show_results IN ('never', 'after_vote', 'always'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS questions (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  poll_id     BIGINT UNSIGNED NOT NULL,
  position    INT             NOT NULL DEFAULT 0,
  type        VARCHAR(16)     NOT NULL,
  title       VARCHAR(300)    NOT NULL,
  hint        VARCHAR(300)    NOT NULL DEFAULT '',
  required    TINYINT(1)      NOT NULL DEFAULT 1,
  max_length  INT             NOT NULL DEFAULT 300,
  min_choices INT             NOT NULL DEFAULT 0,
  max_choices INT             NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY idx_questions_poll (poll_id, position),
  CONSTRAINT fk_questions_poll FOREIGN KEY (poll_id) REFERENCES polls (id) ON DELETE CASCADE,
  CONSTRAINT ck_questions_type CHECK (type IN ('single', 'multiple', 'text', 'rank'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS options (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  question_id BIGINT UNSIGNED NOT NULL,
  position    INT             NOT NULL DEFAULT 0,
  label       VARCHAR(200)    NOT NULL,
  PRIMARY KEY (id),
  KEY idx_options_question (question_id, position),
  CONSTRAINT fk_options_question FOREIGN KEY (question_id) REFERENCES questions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS votes (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  poll_id    BIGINT UNSIGNED NOT NULL,
  ip         VARBINARY(16)    NOT NULL,
  ip_text    VARCHAR(45)      NOT NULL DEFAULT '',
  ua_hash    CHAR(64)         NOT NULL DEFAULT '',
  receipt    VARCHAR(24)      NOT NULL DEFAULT '',
  created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_votes_poll_ip (poll_id, ip),
  UNIQUE KEY uk_votes_receipt (receipt),
  KEY idx_votes_poll_time (poll_id, created_at),
  CONSTRAINT fk_votes_poll FOREIGN KEY (poll_id) REFERENCES polls (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vote_answers (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vote_id     BIGINT UNSIGNED NOT NULL,
  question_id BIGINT UNSIGNED NOT NULL,
  text_value  VARCHAR(2000)   NULL,
  choice_json JSON            NULL,
  rank_json   JSON            NULL,
  PRIMARY KEY (id),
  KEY idx_answers_vote (vote_id),
  KEY idx_answers_question (question_id),
  CONSTRAINT fk_answers_vote FOREIGN KEY (vote_id) REFERENCES votes (id) ON DELETE CASCADE,
  CONSTRAINT fk_answers_question FOREIGN KEY (question_id) REFERENCES questions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS captchas (
  id          VARCHAR(64)     NOT NULL,
  ip          VARBINARY(16)   NOT NULL,
  ip_text     VARCHAR(45)     NOT NULL DEFAULT '',
  attempts    INT             NOT NULL DEFAULT 0,
  created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME        NOT NULL,
  consumed_at DATETIME        NULL,
  PRIMARY KEY (id),
  KEY idx_captchas_ip (ip, created_at),
  KEY idx_captchas_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip_rules (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  kind       VARCHAR(8)      NOT NULL,
  network    VARBINARY(16)   NOT NULL,
  prefix_len TINYINT UNSIGNED NOT NULL,
  note       VARCHAR(200)    NOT NULL DEFAULT '',
  expires_at DATETIME        NULL,
  created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_ip_rules_net (network, prefix_len),
  CONSTRAINT ck_ip_rules_kind CHECK (kind IN ('block', 'allow'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  actor      VARCHAR(64)     NOT NULL DEFAULT '',
  action     VARCHAR(64)     NOT NULL,
  target     VARCHAR(128)    NOT NULL DEFAULT '',
  ip_text    VARCHAR(45)     NOT NULL DEFAULT '',
  detail     TEXT            NULL,
  created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_created (created_at),
  KEY idx_audit_action (action, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
