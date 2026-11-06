// Package risk 是"同一个 IP 投了太多票/节奏像机器"的轻量风控打分。
//
// 只做判断，不做拦截：系统默认允许同一 IP 投多票（limits.one_vote_per_ip=false），
// 所以需要把异常模式显式列出来给人看，再由人在危险操作页处理。
package risk

import (
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

type Report struct {
	IP            string
	Votes         int
	Polls         int
	FirstSeen     time.Time
	LastSeen      time.Time
	PeakPerMinute int
	IntervalCV    float64
	UAHashCount   int
	Score         int
	Level         string // low | medium | high
	// 跨 IP 信号：单个 IP 的票数可以伪装，但"同一个 UA 出现在多个 IP"、
	// "同一 /24 突然集中投票" 这类行为很难同时伪装。
	SharedUA     int // 使用同一个 UA 的不同 IP 数（取该 IP 上最大的那个）
	SubnetVotes  int // 同 /24 网段在 subnet_window 内的票数
	SubnetMinute int // 该网段 60 秒内的峰值票数
	Reasons      []string
	Times        []time.Time
	PollIDs      []int64
}

type agg struct {
	ip    []byte
	text  string
	times []time.Time
	polls map[int64]bool
	uas   map[string]bool
	order []int64
}

// Evaluate 按 IP 聚合窗口内的票并打分。votes 需按时间升序。
func Evaluate(votes []store.Vote, cfg config.Risk) []Report {
	byIP := make(map[string]*agg)
	for _, v := range votes {
		key := string(v.IP)
		a, ok := byIP[key]
		if !ok {
			a = &agg{ip: v.IP, text: v.IPText, polls: map[int64]bool{}, uas: map[string]bool{}}
			byIP[key] = a
		}
		a.times = append(a.times, v.CreatedAt)
		if !a.polls[v.PollID] {
			a.polls[v.PollID] = true
			a.order = append(a.order, v.PollID)
		}
		if v.UAHash != "" {
			a.uas[v.UAHash] = true
		}
	}

	// UA → 使用它的不同 IP 数
	uaIPs := make(map[string]map[string]bool)
	// /24 → 票时间
	subnetTimes := make(map[string][]time.Time)
	for _, a := range byIP {
		for ua := range a.uas {
			set, ok := uaIPs[ua]
			if !ok {
				set = make(map[string]bool)
				uaIPs[ua] = set
			}
			set[string(a.ip)] = true
		}
		subnetTimes[subnet24(a.ip)] = append(subnetTimes[subnet24(a.ip)], a.times...)
	}

	out := make([]Report, 0, len(byIP))
	for _, a := range byIP {
		r := Report{
			IP: a.text, Votes: len(a.times), Polls: len(a.polls),
			FirstSeen: a.times[0], LastSeen: a.times[len(a.times)-1],
			UAHashCount: len(a.uas), PollIDs: a.order,
		}
		if r.IP == "" {
			r.IP = "(未知)"
		}
		for ua := range a.uas {
			if n := len(uaIPs[ua]); n > r.SharedUA {
				r.SharedUA = n
			}
		}
		if st := subnetTimes[subnet24(a.ip)]; len(st) > 0 {
			sort.Slice(st, func(i, j int) bool { return st[i].Before(st[j]) })
			r.SubnetVotes = len(st)
			r.SubnetMinute = peakPerMinute(st)
		}
		r.PeakPerMinute = peakPerMinute(a.times)
		r.IntervalCV = intervalCV(a.times)
		if len(a.times) > 200 {
			r.Times = a.times[len(a.times)-200:]
		} else {
			r.Times = a.times
		}
		score(&r, cfg)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			if out[i].Votes == out[j].Votes {
				return out[i].LastSeen.After(out[j].LastSeen)
			}
			return out[i].Votes > out[j].Votes
		}
		return out[i].Score > out[j].Score
	})
	return out
}

// peakPerMinute 用双指针求任意 60 秒窗口内的最大票数。
func peakPerMinute(times []time.Time) int {
	best, left := 0, 0
	for right := 0; right < len(times); right++ {
		for times[right].Sub(times[left]) > time.Minute {
			left++
		}
		if n := right - left + 1; n > best {
			best = n
		}
	}
	return best
}

// intervalCV 是相邻两票间隔的变异系数；越小越像机器定时提交。
func intervalCV(times []time.Time) float64 {
	if len(times) < 3 {
		return -1
	}
	intervals := make([]float64, 0, len(times)-1)
	var sum float64
	for i := 1; i < len(times); i++ {
		d := times[i].Sub(times[i-1]).Seconds()
		intervals = append(intervals, d)
		sum += d
	}
	mean := sum / float64(len(intervals))
	if mean <= 0 {
		return 0
	}
	var sq float64
	for _, d := range intervals {
		sq += (d - mean) * (d - mean)
	}
	return math.Sqrt(sq/float64(len(intervals))) / mean
}

// subnet24 取 IPv4 的前 3 字节（IPv4-mapped IPv6 取最后 4 字节）用于 /24 聚合。
func subnet24(ip []byte) string {
	if len(ip) == 16 {
		return "24:" + string(ip[13:16])
	}
	if len(ip) >= 3 {
		return "24:" + string(ip[:3])
	}
	return "24:" + string(ip)
}

func levelFor(score int) string {
	switch {
	case score >= 6:
		return "high"
	case score >= 3:
		return "medium"
	}
	return "low"
}

func score(r *Report, cfg config.Risk) {
	add := func(points int, reason string) {
		r.Score += points
		r.Reasons = append(r.Reasons, reason)
	}

	// 跨 IP 信号放在最前面：它们和"这个 IP 投了几票"无关。
	// 分布式刷票每个 IP 只投一票，如果先按 min_votes 一刀切掉，
	// 就正好放过最典型的那种攻击。
	if cfg.SharedUA > 0 && r.SharedUA >= cfg.SharedUA {
		add(3, "同一个 UA 出现在 "+strconv.Itoa(r.SharedUA)+" 个 IP 上（阈值 "+strconv.Itoa(cfg.SharedUA)+"）")
	}
	if cfg.SubnetVotes > 0 && r.SubnetVotes >= cfg.SubnetVotes {
		add(3, "同 /24 网段共 "+strconv.Itoa(r.SubnetVotes)+" 票，60 秒峰值 "+strconv.Itoa(r.SubnetMinute))
	}

	if r.Votes < cfg.MinVotes {
		r.Level = levelFor(r.Score)
		return
	}

	if r.Votes >= cfg.VolumeHigh {
		add(5, "票数 "+strconv.Itoa(r.Votes)+"（阈值 "+strconv.Itoa(cfg.VolumeHigh)+"）")
	} else if r.Votes >= cfg.VolumeWarn {
		add(3, "票数 "+strconv.Itoa(r.Votes)+"（阈值 "+strconv.Itoa(cfg.VolumeWarn)+"）")
	}
	if r.PeakPerMinute >= cfg.BurstPerMinute {
		add(4, "60 秒内最多 "+strconv.Itoa(r.PeakPerMinute)+" 票（阈值 "+strconv.Itoa(cfg.BurstPerMinute)+"）")
	}
	if r.Polls >= cfg.PollSpread {
		add(2, "横跨 "+strconv.Itoa(r.Polls)+" 个投票")
	}
	if r.IntervalCV >= 0 && r.IntervalCV < cfg.RegularityCV {
		add(3, "投票间隔过于规律（CV="+strconv.FormatFloat(r.IntervalCV, 'f', 2, 64)+"）")
	}
	if r.UAHashCount >= cfg.UAChange {
		add(2, "同一 IP 出现 "+strconv.Itoa(r.UAHashCount)+" 个不同 UA")
	}
	if r.UAHashCount == 0 {
		add(1, "没有 UA（疑似脚本）")
	}
	r.Level = levelFor(r.Score)
}
