package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

func cfg() config.Risk {
	return config.Risk{
		Window:         config.Duration{Duration: 24 * time.Hour},
		MinVotes:       3,
		VolumeWarn:     10,
		VolumeHigh:     30,
		BurstPerMinute: 5,
		PollSpread:     3,
		RegularityCV:   0.15,
		UAChange:       3,
		SharedUA:       3,
		SubnetVotes:    8,
	}
}

func vote(ip string, pollID int64, at time.Time, ua string) store.Vote {
	return store.Vote{IP: []byte(ip), IPText: ip, PollID: pollID, CreatedAt: at, UAHash: ua}
}

func TestEvaluateLevels(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)

	// A：一分钟内狂刷 12 票 → 高
	var votes []store.Vote
	for i := 0; i < 12; i++ {
		votes = append(votes, vote("1.1.1.1", 1, base.Add(time.Duration(i)*3*time.Second), "ua-a"))
	}
	// B：很规律地每 10 秒一票，共 6 票 → 高（节奏）
	for i := 0; i < 6; i++ {
		votes = append(votes, vote("2.2.2.2", 1, base.Add(time.Duration(i)*10*time.Second), "ua-b"))
	}
	// C：正常用户，3 票、间隔很长 → 低
	votes = append(votes,
		vote("3.3.3.3", 1, base, "ua-c"),
		vote("3.3.3.3", 1, base.Add(2*time.Hour), "ua-c"),
		vote("3.3.3.3", 1, base.Add(5*time.Hour), "ua-c"),
	)
	// D：没有 UA 的脚本 → 至少 +1
	for i := 0; i < 3; i++ {
		votes = append(votes, vote("4.4.4.4", 2, base.Add(time.Duration(i)*40*time.Minute), ""))
	}

	reports := Evaluate(votes, cfg())
	byIP := map[string]Report{}
	for _, r := range reports {
		byIP[r.IP] = r
	}

	if byIP["1.1.1.1"].Level != "high" || byIP["1.1.1.1"].PeakPerMinute < 5 {
		t.Fatalf("A 应为 high：%+v", byIP["1.1.1.1"])
	}
	if byIP["2.2.2.2"].Level != "high" {
		t.Fatalf("B 应为 high（节奏）：%+v", byIP["2.2.2.2"])
	}
	if byIP["3.3.3.3"].Level != "low" {
		t.Fatalf("C 应为 low：%+v", byIP["3.3.3.3"])
	}
	if byIP["4.4.4.4"].Score < 1 {
		t.Fatalf("D 应有缺 UA 的扣分项：%+v", byIP["4.4.4.4"])
	}
	// 排序：分高的在前
	if reports[0].IP != "1.1.1.1" {
		t.Fatalf("应按分数排序，第一条是 %s", reports[0].IP)
	}
	// 明细时间不超过上限且按时间排列
	if len(byIP["1.1.1.1"].Times) != 12 {
		t.Fatalf("明细条数不对：%d", len(byIP["1.1.1.1"].Times))
	}
}

// 分布式刷票：每个 IP 只投 1~2 票，单看每个 IP 都很"干净"，
// 但同一个 UA 出现在很多 IP 上、且集中在同一个 /24。
func TestDistributedBotCaughtByCrossIPSignals(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	var votes []store.Vote
	for i := 0; i < 6; i++ {
		// 同一 /24：203.0.113.0/24，每 20 秒一票，UA 全都一样
		ip := []byte{203, 0, 113, byte(10 + i)}
		votes = append(votes, store.Vote{
			IP: ip, IPText: "203.0.113." + string(rune('0'+10+i)), PollID: 1,
			CreatedAt: base.Add(time.Duration(i) * 20 * time.Second), UAHash: "same-ua",
		})
	}
	reports := Evaluate(votes, cfg())
	if len(reports) == 0 {
		t.Fatal("应有报告")
	}
	// 至少有一条被判为中/高，且理由里出现跨 IP 信号
	found := false
	for _, r := range reports {
		if r.Level == "medium" || r.Level == "high" {
			for _, reason := range r.Reasons {
				if strings.Contains(reason, "/24") || strings.Contains(reason, "同一个 UA") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("跨 IP 信号没触发：%+v", reports[0])
	}
}

func TestUnderMinVotesIsLow(t *testing.T) {
	base := time.Now()
	votes := []store.Vote{
		vote("9.9.9.9", 1, base, "u"),
		vote("9.9.9.9", 1, base.Add(time.Second), "u"),
	}
	r := Evaluate(votes, cfg())
	if len(r) != 1 || r[0].Level != "low" || r[0].Score != 0 {
		t.Fatalf("低于 min_votes 应直接 low：%+v", r)
	}
}

func TestIntervalCV(t *testing.T) {
	base := time.Now()
	var regular []time.Time
	for i := 0; i < 5; i++ {
		regular = append(regular, base.Add(time.Duration(i)*10*time.Second))
	}
	if cv := intervalCV(regular); cv > 0.01 {
		t.Fatalf("等间隔的 CV 应接近 0，得到 %f", cv)
	}
	irregular := []time.Time{base, base.Add(3 * time.Second), base.Add(100 * time.Second), base.Add(101 * time.Second)}
	if cv := intervalCV(irregular); cv < 0.3 {
		t.Fatalf("不规则间隔的 CV 应较大，得到 %f", cv)
	}
}
