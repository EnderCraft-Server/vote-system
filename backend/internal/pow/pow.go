// Package pow 实现"工作量证明验证码"（hashcash 思路，ALTCHA/Cap 那一类）。
//
// 为什么不用图片验证码硬抗 ML：任何自建图片验证码都会被 OCR/多模态模型以很高成功率破解，
// 提高位数只会先劝退人。PoW 没有可被"识别"的语义，只把每次提交的代价变成可度量的 CPU 工作量；
// 再叠加"每 IP 申请越多难度越高"，自动化批量投票的成本会指数级上涨，而正常用户只解一次。
package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
	"strconv"
	"sync"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
)

var (
	ErrExpired   = errors.New("pow: 挑战已过期")
	ErrSignature = errors.New("pow: 签名无效")
	ErrReplay    = errors.New("pow: 挑战已被使用")
	ErrSolution  = errors.New("pow: 解不满足难度要求")
	ErrBits      = errors.New("pow: 难度不在允许范围")
)

// Challenge 是发给浏览器的挑战（明文，全部被签名保护）。
type Challenge struct {
	Nonce     string `json:"nonce"`
	Salt      string `json:"salt"`
	Bits      int    `json:"bits"`
	Expires   int64  `json:"expires"`
	Signature string `json:"signature"`
}

// Solution 是浏览器算出来的解。
type Solution struct {
	Nonce     string `json:"nonce"`
	Salt      string `json:"salt"`
	Bits      int    `json:"bits"`
	Expires   int64  `json:"expires"`
	Signature string `json:"signature"`
	Counter   uint64 `json:"counter"`
}

type issueState struct {
	count       int
	windowStart time.Time
}

// Verifier 同时负责签发挑战、校验解、按 IP 升级难度、拦截重放。
type Verifier struct {
	secret        []byte
	ttl           time.Duration
	window        time.Duration
	baseBits      int
	maxBits       int
	escalateEvery int
	now           func() time.Time

	mu     sync.Mutex
	seen   map[string]time.Time
	issues map[string]*issueState
}

func New(cfg config.Captcha, secret []byte) *Verifier {
	ttl := cfg.Pow.TTL.Duration
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	window := cfg.Pow.Window.Duration
	if window <= 0 {
		window = 10 * time.Minute
	}
	base := cfg.Pow.BaseBits
	if base < 10 {
		base = 18
	}
	maxBits := cfg.Pow.MaxBits
	if maxBits < base {
		maxBits = base
	}
	every := cfg.Pow.EscalateEvery
	if every < 1 {
		every = 3
	}
	return &Verifier{
		secret: secret, ttl: ttl, window: window,
		baseBits: base, maxBits: maxBits, escalateEvery: every,
		now:    time.Now,
		seen:   make(map[string]time.Time),
		issues: make(map[string]*issueState),
	}
}

// SetClock 仅供测试。
func (v *Verifier) SetClock(fn func() time.Time) { v.now = fn }

// BitsFor 返回该 IP 当前应使用的难度：申请次数越多，位数越高。
func (v *Verifier) BitsFor(ip string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	st, ok := v.issues[ip]
	if !ok || v.now().Sub(st.windowStart) > v.window {
		return v.baseBits
	}
	b := v.baseBits + st.count/v.escalateEvery
	if b > v.maxBits {
		b = v.maxBits
	}
	return b
}

func (v *Verifier) sign(c Challenge, ip string) string {
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte("pow|" + c.Nonce + "|" + c.Salt + "|" + strconv.Itoa(c.Bits) + "|" +
		strconv.FormatInt(c.Expires, 10) + "|" + ip))
	return hex.EncodeToString(mac.Sum(nil))
}

// Issue 为某个 IP 签一张新挑战，并把它计入难度升级的统计窗口。
func (v *Verifier) Issue(ip string) (Challenge, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return Challenge{}, err
	}
	salt, err := randomHex(16)
	if err != nil {
		return Challenge{}, err
	}
	now := v.now()
	bits := v.BitsFor(ip)

	v.mu.Lock()
	st, ok := v.issues[ip]
	if !ok || now.Sub(st.windowStart) > v.window {
		st = &issueState{windowStart: now}
		v.issues[ip] = st
	}
	st.count++
	if len(v.issues) > 20000 {
		for k, s := range v.issues {
			if now.Sub(s.windowStart) > v.window {
				delete(v.issues, k)
			}
		}
	}
	v.mu.Unlock()

	c := Challenge{
		Nonce: nonce, Salt: salt, Bits: bits,
		Expires: now.Add(v.ttl).Unix(),
	}
	c.Signature = v.sign(c, ip)
	return c, nil
}

// Verify 校验签名、有效期、难度范围、工作量和重放。
func (v *Verifier) Verify(sol Solution, ip string) error {
	c := Challenge{Nonce: sol.Nonce, Salt: sol.Salt, Bits: sol.Bits, Expires: sol.Expires, Signature: sol.Signature}
	if sol.Nonce == "" || sol.Salt == "" {
		return ErrSignature
	}
	if !hmac.Equal([]byte(v.sign(c, ip)), []byte(sol.Signature)) {
		return ErrSignature
	}
	now := v.now()
	if now.Unix() > sol.Expires {
		return ErrExpired
	}
	if sol.Bits < v.baseBits || sol.Bits > v.maxBits {
		return ErrBits
	}

	v.mu.Lock()
	if exp, ok := v.seen[sol.Nonce]; ok && now.Before(exp) {
		v.mu.Unlock()
		return ErrReplay
	}
	v.seen[sol.Nonce] = time.Unix(sol.Expires, 0)
	if len(v.seen) > 200000 {
		for k, exp := range v.seen {
			if now.After(exp) {
				delete(v.seen, k)
			}
		}
	}
	v.mu.Unlock()

	if !Check(sol.Salt, sol.Counter, sol.Bits) {
		return ErrSolution
	}
	return nil
}

// Check 判断 sha256(salt:counter) 是否有至少 bits 个前导零比特。
func Check(salt string, counter uint64, bitsWanted int) bool {
	if bitsWanted <= 0 || bitsWanted > 256 {
		return false
	}
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(":"))
	h.Write([]byte(strconv.FormatUint(counter, 10)))
	return LeadingZeroBits(h.Sum(nil)) >= bitsWanted
}

func LeadingZeroBits(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// Solve 是给测试和命令行用的串行解法。
func Solve(c Challenge) (uint64, bool) {
	for i := uint64(0); i < 1<<32; i++ {
		if Check(c.Salt, i, c.Bits) {
			return i, true
		}
	}
	return 0, false
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
