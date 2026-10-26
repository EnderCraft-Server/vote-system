-- 0003：为"一 IP 一票"加上可关闭的开关。
-- 唯一键从 (poll_id, ip) 改成 (poll_id, ip_key)：
--   one_vote_per_ip=true  → ip_key = ip，行为与 0001 完全一致；
--   one_vote_per_ip=false → ip_key 每票随机 16 字节，等价于"同一 IP 可重复投票"。
-- 这样唯一性仍由数据库兜底（并发安全），而不是只靠应用层判断。
ALTER TABLE votes ADD COLUMN ip_key VARBINARY(16) NULL AFTER ip;
UPDATE votes SET ip_key = ip WHERE ip_key IS NULL;
ALTER TABLE votes MODIFY COLUMN ip_key VARBINARY(16) NOT NULL;
ALTER TABLE votes DROP INDEX uk_votes_poll_ip, ADD UNIQUE KEY uk_votes_poll_ipkey (poll_id, ip_key);
