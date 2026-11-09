package admin

import (
	"encoding/json"
	"html/template"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/store"
)

// questionJSON 是交给前端题目编辑器的结构。
type questionJSON struct {
	Type       string   `json:"type"`
	Title      string   `json:"title"`
	Hint       string   `json:"hint"`
	Required   bool     `json:"required"`
	MaxLength  int      `json:"max_length"`
	MinChoices int      `json:"min_choices"`
	MaxChoices int      `json:"max_choices"`
	Options    []string `json:"options"`
}

func storedQuestionsJSON(qs []store.Question) string {
	out := make([]questionJSON, 0, len(qs))
	for _, q := range qs {
		item := questionJSON{
			Type: q.Type, Title: q.Title, Hint: q.Hint, Required: q.Required,
			MaxLength: q.MaxLength, MinChoices: q.MinChoices, MaxChoices: q.MaxChoices,
			Options: make([]string, 0, len(q.Options)),
		}
		for _, o := range q.Options {
			item.Options = append(item.Options, o.Label)
		}
		out = append(out, item)
	}
	return mustJSON(out)
}

func inputQuestionsJSON(qs []store.QuestionInput) string {
	out := make([]questionJSON, 0, len(qs))
	for _, q := range qs {
		out = append(out, questionJSON{
			Type: q.Type, Title: q.Title, Hint: q.Hint, Required: q.Required,
			MaxLength: q.MaxLength, MinChoices: q.MinChoices, MaxChoices: q.MaxChoices,
			Options: append([]string{}, q.Options...),
		})
	}
	return mustJSON(out)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ruleCIDR 把 16 字节网段还原成可读的 CIDR。
func ruleCIDR(r store.IPRule) string {
	addr, ok := netip.AddrFromSlice(r.Network)
	if !ok {
		return "?"
	}
	// 库里存的是 16 字节形式（IPv4 是 ::ffff:a.b.c.d），prefix_len 也按 16 字节算；
	// 显示前必须 Unmap 回 4 字节，否则掩码长度和地址族对不上，1.2.3.0/24 会显示成 ::/24。
	bits := int(r.PrefixLen)
	addr = addr.Unmap()
	if addr.Is4() {
		bits -= 96
		if bits < 0 {
			bits = 0
		}
		if bits > 32 {
			bits = 32
		}
	}
	return netip.PrefixFrom(addr, bits).String()
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"zhStatus":    statusZh,
		"zhType":      typeZh,
		"zhShow":      showZh,
		"fmtDate":     func(t time.Time) string { return t.Format("2006-01-02") },
		"fmtDateTime": func(t time.Time) string { return t.Format("2006-01-02 15:04") },
		"fmtOpt": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.Format("2006-01-02 15:04")
		},
		"fmtLocalIn": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.Format("2006-01-02T15:04")
		},
		"percent": func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
		// pct5 把百分比量化到 5% 一档：CSP 禁内联 style，条形图宽度只能用预生成类。
		"pct5": func(f float64) int {
			n := int(math.Round(f/5)) * 5
			if n < 0 {
				n = 0
			}
			if n > 100 {
				n = 100
			}
			return n
		},
		"fmtRank": func(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) },
		"add":     func(a, b int) int { return a + b },
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
		"ruleCIDR": ruleCIDR,
	}
	return template.New("root").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
}

func statusZh(s string) string {
	switch s {
	case "draft":
		return "草稿"
	case "open":
		return "进行中"
	case "closed":
		return "已关闭"
	}
	return s
}

func showZh(s string) string {
	switch s {
	case "never":
		return "不公开"
	case "after_vote":
		return "投票后可见"
	case "always":
		return "立即公开"
	}
	return s
}

func typeZh(t string) string {
	switch t {
	case "single":
		return "单选"
	case "multiple":
		return "多选"
	case "text":
		return "简答"
	case "rank":
		return "排序"
	}
	return t
}

// parsePollForm 把管理端表单解析成存储层输入，同时返回可回显的题目结构与校验问题列表。
func parsePollForm(r *http.Request) (store.PollInput, []store.QuestionInput, []string) {
	f := r.PostForm
	var problems []string

	in := store.PollInput{
		Title:       strings.TrimSpace(f.Get("title")),
		Summary:     strings.TrimSpace(f.Get("summary")),
		Status:      f.Get("status"),
		ShowResults: f.Get("show_results"),
		OnePerIP:    true, // 一 IP 一票由唯一键强制，管理端不提供开关
		StartsAt:    parseLocalTime(f.Get("starts_at")),
		EndsAt:      parseLocalTime(f.Get("ends_at")),
	}
	if in.Status != "draft" && in.Status != "open" && in.Status != "closed" {
		in.Status = "draft"
	}
	if in.ShowResults != "never" && in.ShowResults != "after_vote" && in.ShowResults != "always" {
		in.ShowResults = "after_vote"
	}
	if in.Title == "" {
		problems = append(problems, "标题不能为空")
	} else if len([]rune(in.Title)) > 160 {
		problems = append(problems, "标题最多 160 字")
	}
	if len([]rune(in.Summary)) > 500 {
		problems = append(problems, "简介最多 500 字")
	}
	if in.StartsAt != nil && in.EndsAt != nil && in.EndsAt.Before(*in.StartsAt) {
		problems = append(problems, "结束时间不能早于开始时间")
	}

	questions, qProblems := parseQuestions(f)
	problems = append(problems, qProblems...)
	if len(questions) == 0 {
		problems = append(problems, "至少要有一道题目")
	}
	return in, questions, problems
}

func parseLocalTime(v string) *time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", v, time.Local); err == nil {
		return &t
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", v, time.Local); err == nil {
		return &t
	}
	return nil
}

func parseQuestions(f map[string][]string) ([]store.QuestionInput, []string) {
	indexes := map[int]bool{}
	for key := range f {
		if !strings.HasPrefix(key, "q") {
			continue
		}
		rest := key[1:]
		cut := strings.IndexAny(rest, "_")
		if cut <= 0 {
			continue
		}
		if n, err := strconv.Atoi(rest[:cut]); err == nil {
			indexes[n] = true
		}
	}
	ordered := make([]int, 0, len(indexes))
	for n := range indexes {
		ordered = append(ordered, n)
	}
	sort.Ints(ordered)

	var out []store.QuestionInput
	var problems []string
	if len(ordered) > 20 {
		return nil, []string{"题目最多 20 道"}
	}

	for pos, idx := range ordered {
		prefix := "q" + strconv.Itoa(idx) + "_"
		// 手工构造的请求可能只有 q0_title 没有 q0_type，直接下标会 panic。
		types := f[prefix+"type"]
		if len(types) == 0 || strings.TrimSpace(types[0]) == "" {
			problems = append(problems, "第 "+strconv.Itoa(pos+1)+" 题缺少题型")
			continue
		}
		q := store.QuestionInput{
			Type:     types[0],
			Title:    strings.TrimSpace(first(f[prefix+"title"])),
			Hint:     strings.TrimSpace(first(f[prefix+"hint"])),
			Required: first(f[prefix+"required"]) != "",
		}
		label := "第 " + strconv.Itoa(pos+1) + " 题"
		switch q.Type {
		case "single", "multiple", "text", "rank":
		default:
			problems = append(problems, label+"的题型不合法")
			continue
		}
		if q.Title == "" {
			problems = append(problems, label+"的题干不能为空")
		} else if len([]rune(q.Title)) > 300 {
			problems = append(problems, label+"的题干最多 300 字")
		}
		if len([]rune(q.Hint)) > 300 {
			problems = append(problems, label+"的提示最多 300 字")
		}

		// 收集选项：q{i}_opt{j}
		optIdx := map[int]bool{}
		for key := range f {
			if !strings.HasPrefix(key, prefix+"opt") {
				continue
			}
			if n, err := strconv.Atoi(strings.TrimPrefix(key, prefix+"opt")); err == nil {
				optIdx[n] = true
			}
		}
		optOrder := make([]int, 0, len(optIdx))
		for n := range optIdx {
			optOrder = append(optOrder, n)
		}
		sort.Ints(optOrder)
		for _, oi := range optOrder {
			v := strings.TrimSpace(first(f[prefix+"opt"+strconv.Itoa(oi)]))
			if v == "" {
				continue
			}
			if len([]rune(v)) > 200 {
				problems = append(problems, label+"的选项最多 200 字")
				continue
			}
			q.Options = append(q.Options, v)
		}
		if len(q.Options) > 30 {
			problems = append(problems, label+"的选项最多 30 个")
		}

		switch q.Type {
		case "single", "rank":
			if len(q.Options) < 2 {
				problems = append(problems, label+"至少需要两个选项")
			}
			q.MinChoices, q.MaxChoices = 0, 0
		case "multiple":
			if len(q.Options) < 2 {
				problems = append(problems, label+"至少需要两个选项")
			}
			q.MinChoices = atoiDefault(first(f[prefix+"min"]), 1)
			q.MaxChoices = atoiDefault(first(f[prefix+"max"]), 0)
			if q.MinChoices < 1 {
				q.MinChoices = 1
			}
			if q.MinChoices > len(q.Options) {
				problems = append(problems, label+"的最少选择数超过了选项数量")
			}
			if q.MaxChoices > 0 && q.MaxChoices > len(q.Options) {
				problems = append(problems, label+"的最多选择数超过了选项数量")
			}
			if q.MaxChoices > 0 && q.MaxChoices < q.MinChoices {
				problems = append(problems, label+"的最多选择数不能小于最少选择数")
			}
		case "text":
			q.Options = nil
			q.MaxLength = atoiDefault(first(f[prefix+"max_length"]), 300)
			if q.MaxLength < 1 || q.MaxLength > 300 {
				problems = append(problems, label+"的字数上限需在 1~300 之间")
			}
		}
		out = append(out, q)
	}
	return out, problems
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// questionsDiffer 判断题目是否有实质变化（已有票的投票不允许改题目）。
func questionsDiffer(cur []store.Question, next []store.QuestionInput) bool {
	if len(cur) != len(next) {
		return true
	}
	for i := range cur {
		a, b := cur[i], next[i]
		if a.Type != b.Type || a.Title != b.Title || a.Hint != b.Hint || a.Required != b.Required ||
			a.MaxLength != b.MaxLength || a.MinChoices != b.MinChoices || a.MaxChoices != b.MaxChoices {
			return true
		}
		if len(a.Options) != len(b.Options) {
			return true
		}
		for j := range a.Options {
			if a.Options[j].Label != b.Options[j] {
				return true
			}
		}
	}
	return false
}
