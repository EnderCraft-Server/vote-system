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
	Reasons       []string
	Times         []time.Time
	PollIDs       []int64
}

type agg struct {
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
			a = &agg{text: v.IPText, polls: map[int64]bool{}, uas: map[string]bool{}}
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

func score(r *Report, cfg config.Risk) {
	add := func(points int, reason string) {
		r.Score += points
		r.Reasons = append(r.Reasons, reason)
	}
	if r.Votes < cfg.MinVotes {
		r.Level = "low"
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
	if r.UAHashCount == 0 && r.Votes >= cfg.MinVotes {
		add(1, "全部投票没有 UA（疑似脚本）")
	}
	switch {
	case r.Score >= 6:
		r.Level = "high"
	case r.Score >= 3:
		r.Level = "medium"
	default:
		r.Level = "low"
	}
}
