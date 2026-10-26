-- 0002：captchas 表补上 answer_hash。
-- 0001 里漏了这个问题：内存实现把答案哈希放在结构体里，MySQL 实现没有列可放，
-- 结果 GetCaptcha 读回来是空串，验证码永远校验失败（用真库跑端到端时才发现）。
ALTER TABLE captchas ADD COLUMN answer_hash CHAR(64) NOT NULL DEFAULT '' AFTER ip_text;
