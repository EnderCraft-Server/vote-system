-- 0004：为"按 IP 统计"加索引（关闭一 IP 一票后，需要能快速看同一 IP 投了几票）。
CREATE INDEX idx_votes_ip ON votes (ip, created_at);
