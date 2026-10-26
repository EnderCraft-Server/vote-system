package pow

import (
	"strings"
	"testing"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
)

func cfgForTest() config.Captcha {
	c := config.Default().Captcha
	c.Pow.Enabled = true
	c.Pow.BaseBits = 10
	c.Pow.MaxBits = 12
	c.Pow.EscalateEvery = 3
	c.Pow.TTL = config.Duration{Duration: 2 * time.Minute}
	c.Pow.Window = config.Duration{Duration: 10 * time.Minute}
	return c
}

func TestIssueVerify(t *testing.T) {
	v := New(cfgForTest(), []byte("0123456789abcdef0123456789abcdef"))
	ch, err := v.Issue("203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	counter, ok := Solve(ch)
	if !ok {
		t.Fatal("求解失败")
	}
	sol := Solution{Nonce: ch.Nonce, Salt: ch.Salt, Bits: ch.Bits, Expires: ch.Expires, Signature: ch.Signature, Counter: counter}
	if err := v.Verify(sol, "203.0.113.5"); err != nil {
		t.Fatalf("正确解应通过：%v", err)
	}
	// 重放
	if err := v.Verify(sol, "203.0.113.5"); err != ErrReplay {
		t.Fatalf("重放应 ErrReplay，得到 %v", err)
	}
}

func TestRejectsTampered(t *testing.T) {
	v := New(cfgForTest(), []byte("0123456789abcdef0123456789abcdef"))
	ch, _ := v.Issue("203.0.113.6")
	counter, _ := Solve(ch)
	base := Solution{Nonce: ch.Nonce, Salt: ch.Salt, Bits: ch.Bits, Expires: ch.Expires, Signature: ch.Signature, Counter: counter}

	bad := base
	bad.Bits = 8 // 降低难度但签名是对原 bits 算的
	if err := v.Verify(bad, "203.0.113.6"); err == nil {
		t.Fatal("改难度应被签名拦住")
	}

	other := base
	if err := v.Verify(other, "203.0.113.7"); err != ErrSignature {
		t.Fatalf("换 IP 应签名失败，得到 %v", err)
	}

	wrong := base
	wrong.Counter = counter + 1
	if err := v.Verify(wrong, "203.0.113.6"); err != ErrSolution {
		t.Fatalf("错误解应 ErrSolution，得到 %v", err)
	}
}

func TestExpiry(t *testing.T) {
	v := New(cfgForTest(), []byte("0123456789abcdef0123456789abcdef"))
	now := time.Now()
	v.SetClock(func() time.Time { return now })
	ch, _ := v.Issue("203.0.113.8")
	counter, _ := Solve(ch)
	sol := Solution{Nonce: ch.Nonce, Salt: ch.Salt, Bits: ch.Bits, Expires: ch.Expires, Signature: ch.Signature, Counter: counter}
	// 超过 TTL（2 分钟）再提交
	v.SetClock(func() time.Time { return now.Add(3 * time.Minute) })
	if err := v.Verify(sol, "203.0.113.8"); err != ErrExpired {
		t.Fatalf("过期应 ErrExpired，得到 %v", err)
	}
}

func TestEscalation(t *testing.T) {
	v := New(cfgForTest(), []byte("0123456789abcdef0123456789abcdef"))
	first, _ := v.Issue("203.0.113.10")
	if first.Bits != 10 {
		t.Fatalf("初始难度应为 10，得到 %d", first.Bits)
	}
	for i := 0; i < 3; i++ {
		_, _ = v.Issue("203.0.113.10")
	}
	after, _ := v.Issue("203.0.113.10")
	if after.Bits != 11 {
		t.Fatalf("3 次申请后应为 11，得到 %d", after.Bits)
	}
	// 别的 IP 不受影响
	other, _ := v.Issue("198.51.100.1")
	if other.Bits != 10 {
		t.Fatalf("其他 IP 不应被升级，得到 %d", other.Bits)
	}
}

func TestCheckBits(t *testing.T) {
	// 构造一个解，验证前导零位数
	ch := Challenge{Salt: strings.Repeat("a", 32), Bits: 8}
	counter, ok := Solve(ch)
	if !ok {
		t.Fatal("求解失败")
	}
	if !Check(ch.Salt, counter, 8) {
		t.Fatal("8 bit 应通过")
	}
	// 更低的解不满足更高要求
	if Check(ch.Salt, counter, 20) {
		t.Fatal("不应满足 20 bit")
	}
}
